use crate::state::State;
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::fd::AsFd;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tracing::{error, info};
use zbus::interface;
use zbus::zvariant::{Fd, ObjectPath, Value};

pub struct PortalSecret {
    state: Arc<RwLock<State>>,
}

impl PortalSecret {
    pub fn new(state: Arc<RwLock<State>>) -> Self {
        Self { state }
    }
}

/// Implementation of the xdg-desktop-portal backend secret interface.
/// This allows sandboxed applications (Flatpak) to store and retrieve secrets
/// through the portal mechanism without direct access to the D-Bus secret service.
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

        // In a real-world scenario, you would derive a per-app secret or 
        // return a master key that the portal uses to encrypt the app's data.
        // For WSSP, we'll provide the internal vault's master key if available.
        let secret = match &state_guard.vault {
            Some(vault) => vault.get_master_key(),
            None => return Err(zbus::fdo::Error::Failed("No active vault".into())),
        };

        // Transfer the secret through the file descriptor.
        // We use UnixStream to wrap the raw FD for asynchronous I/O.
        let mut stream = unsafe {
            let std_stream = std::os::unix::net::UnixStream::from_raw_fd(fd.as_fd().as_raw_fd());
            // Ensure the FD isn't closed when std_stream is dropped prematurely
            UnixStream::from_std(std_stream).map_err(|e| {
                error!(error = %e, "Failed to create UnixStream from portal FD");
                zbus::fdo::Error::Failed(e.to_string())
            })?
        };

        if let Err(e) = stream.write_all(secret).await {
            error!(error = %e, "Failed to write secret to portal FD");
            return Err(zbus::fdo::Error::Failed("IO Error".into()));
        }

        // Flush and shutdown the write side to signal completion
        let _ = stream.flush().await;

        info!(%app_id, "Successfully sent secret to portal");
        
        // The portal spec expects an empty results dictionary on success
        Ok(HashMap::new())
    }
}
