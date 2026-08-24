use crate::state::State;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use zbus::interface;
use zbus::zvariant::{Fd, ObjectPath, Value};
use zeroize::Zeroize;

/// Derive a deterministic 32-byte (256-bit) per-application secret from the master key and `app_id`.
/// Follows standard XDG Portal security practices using HKDF-SHA256.
pub fn derive_app_secret(master_key: &[u8], app_id: &str) -> [u8; 32] {
    let salt = b"org.freedesktop.portal.Secret";
    let info = if app_id.is_empty() {
        b"default".as_slice()
    } else {
        app_id.as_bytes()
    };

    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32-byte output is always valid for HKDF-SHA256");
    okm
}

pub struct PortalSecret {
    state: Arc<RwLock<State>>,
}

impl PortalSecret {
    pub fn new(state: Arc<RwLock<State>>) -> Self {
        Self { state }
    }
}

/// Implementation of the xdg-desktop-portal backend secret interface (`org.freedesktop.impl.portal.Secret`).
/// This allows sandboxed applications (e.g. Flatpak) to retrieve application-specific master secrets
/// through the portal mechanism without exposing the global keyring master key.
#[interface(name = "org.freedesktop.impl.portal.Secret")]
impl PortalSecret {
    /// RetrieveSecret method implementation.
    ///
    /// # Arguments
    /// * `handle` - Object path for the request.
    /// * `app_id` - Identifier of the application requesting the secret.
    /// * `fd` - File descriptor where the secret should be written.
    /// * `options` - Additional options for the request.
    async fn retrieve_secret(
        &self,
        handle: ObjectPath<'_>,
        app_id: String,
        fd: Fd<'_>,
        _options: HashMap<String, Value<'_>>,
    ) -> zbus::fdo::Result<HashMap<String, Value<'static>>> {
        debug!(%app_id, %handle, "RetrieveSecret called from sandboxed application (Portal)");

        let state_guard = self.state.read().await;
        if !state_guard.is_unlocked {
            return Err(zbus::fdo::Error::Failed(
                "Vault is locked; unlock the keyring first".into(),
            ));
        }

        let master_key = match &state_guard.vault {
            Some(vault) => vault.get_master_key(),
            None => return Err(zbus::fdo::Error::Failed("No active vault".into())),
        };

        // Derive application-specific 32-byte secret using HKDF-SHA256
        let mut app_secret = derive_app_secret(master_key, &app_id);

        // Transfer the secret through the provided file descriptor
        let mut stream = unsafe {
            let std_stream = std::os::unix::net::UnixStream::from_raw_fd(fd.as_fd().as_raw_fd());
            UnixStream::from_std(std_stream).map_err(|e| {
                error!(error = %e, "Failed to create UnixStream from portal FD");
                app_secret.zeroize();
                zbus::fdo::Error::Failed(e.to_string())
            })?
        };

        let write_result = stream.write_all(&app_secret).await;
        let flush_result = stream.flush().await;

        // Zeroize in-memory secret immediately after transmission
        app_secret.zeroize();

        if let Err(e) = write_result.or(flush_result) {
            error!(error = %e, "Failed to write secret to portal FD");
            return Err(zbus::fdo::Error::Failed("IO Error".into()));
        }

        info!(%app_id, "Successfully sent derived app secret to portal");

        // The portal spec expects an empty results dictionary on success
        Ok(HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_app_secret_deterministic() {
        let master_key = b"test_master_key_32_bytes_length!!";
        let secret1 = derive_app_secret(master_key, "org.mozilla.firefox");
        let secret2 = derive_app_secret(master_key, "org.mozilla.firefox");
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_derive_app_secret_isolation() {
        let master_key = b"test_master_key_32_bytes_length!!";
        let secret_firefox = derive_app_secret(master_key, "org.mozilla.firefox");
        let secret_vscode = derive_app_secret(master_key, "com.visualstudio.code");
        assert_ne!(secret_firefox, secret_vscode);
        assert_ne!(secret_firefox, master_key[..32]);
    }

    #[test]
    fn test_derive_app_secret_empty_app_id() {
        let master_key = b"test_master_key_32_bytes_length!!";
        let secret = derive_app_secret(master_key, "");
        assert_ne!(secret, [0u8; 32]);
    }
}
