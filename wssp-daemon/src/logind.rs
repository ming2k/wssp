use std::path::PathBuf;
use std::sync::Arc;
use futures_util::StreamExt;
use inotify::{Inotify, WatchMask};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::service::load_vault;
use crate::state::State;
use crate::unlock::{apply_vault_data, try_unlock_with_keyfile};

/// Subscribe to logind Session.Lock signal → lock vault when screen locks.
pub fn spawn_lock_listener(state: Arc<RwLock<State>>) {
    tokio::spawn(async move {
        if let Err(e) = run_lock_listener(state).await {
            warn!("logind lock listener stopped: {}", e);
        }
    });
}

async fn run_lock_listener(state: Arc<RwLock<State>>) -> Result<(), Box<dyn std::error::Error>> {
    let system_bus = zbus::Connection::system().await?;

    // Resolve our logind session path.
    let session_id = std::env::var("XDG_SESSION_ID").unwrap_or_default();
    let session_path: zbus::zvariant::OwnedObjectPath = if session_id.is_empty() {
        let manager = zbus::Proxy::new(
            &system_bus,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        manager
            .call("GetSessionByPID", &(std::process::id()))
            .await?
    } else {
        let manager = zbus::Proxy::new(
            &system_bus,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        manager.call("GetSession", &session_id.as_str()).await?
    };

    let session = zbus::Proxy::new(
        &system_bus,
        "org.freedesktop.login1",
        session_path.as_str(),
        "org.freedesktop.login1.Session",
    )
    .await?;

    info!("Subscribed to logind Lock signal on {}", session_path);
    let mut lock_stream = session.receive_signal("Lock").await?;

    while lock_stream.next().await.is_some() {
        info!("Screen locked — locking vault.");
        let mut st = state.write().await;
        st.is_unlocked = false;
        st.vault = None;
        // Note: in-memory item secrets are not zeroized here (see security.md Known Limitations).
        // The vault key is gone, so no new writes can be committed to disk.
    }

    Ok(())
}

/// Watch for PAM token file creation → re-unlock vault after screensaver dismissal.
pub fn spawn_pam_watcher(
    state: Arc<RwLock<State>>,
    vault_path: PathBuf,
    salt_path: PathBuf,
) {
    tokio::spawn(async move {
        if let Err(e) = run_pam_watcher(state, vault_path, salt_path).await {
            error!("PAM token watcher stopped: {}", e);
        }
    });
}

async fn run_pam_watcher(
    state: Arc<RwLock<State>>,
    vault_path: PathBuf,
    _salt_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));

    let inotify = Inotify::init()?;
    inotify
        .watches()
        .add(&runtime_dir, WatchMask::CLOSE_WRITE)?;

    let buffer = vec![0u8; 4096];
    let mut stream = inotify.into_event_stream(buffer)?;

    info!("Watching {:?} for PAM token file.", runtime_dir);

    while let Some(event) = stream.next().await {
        let event = event?;
        let name = match event.name {
            Some(n) => n,
            None => continue,
        };
        if name != "wssp-pam-token" {
            continue;
        }

        let (should_unlock, key_path, vault_path2, salt_path2) = {
            let st = state.read().await;
            (
                !st.is_unlocked && vault_path.exists(),
                st.key_path.clone(),
                st.vault_path.clone(),
                st.salt_path.clone(),
            )
        };
        if !should_unlock {
            continue;
        }

        let token_path = PathBuf::from(&runtime_dir).join("wssp-pam-token");

        if key_path.exists() {
            // Keyfile mode: PAM token is just an "auth succeeded" signal; discard content.
            let _ = std::fs::remove_file(&token_path);
            match try_unlock_with_keyfile(&key_path, &vault_path2, state.clone()).await {
                Ok(_) => info!("Vault re-unlocked via keyfile (screensaver dismissed)."),
                Err(e) => error!("Keyfile re-unlock failed: {}", e),
            }
        } else {
            // Password mode: use token content as credential.
            match std::fs::read_to_string(&token_path) {
                Ok(password) => {
                    let _ = std::fs::remove_file(&token_path);
                    match load_vault(&password, &vault_path2, &salt_path2, false) {
                        Ok((vault, data)) => {
                            apply_vault_data(vault, &data, state.clone()).await;
                            info!("Vault re-unlocked via PAM token (screensaver dismissed).");
                        }
                        Err(e) => error!(
                            "PAM re-unlock failed (vault/login password mismatch?): {}",
                            e
                        ),
                    }
                }
                Err(e) => error!("Failed to read PAM token: {}", e),
            }
        }
        let _ = salt_path2; // used only in password mode branch above
    }

    Ok(())
}
