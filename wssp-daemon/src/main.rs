use std::error::Error;
use tracing::{error, info};
use zbus::connection;

mod collection;
mod error;
mod ipc;
mod item;
mod logind;
mod portal;
mod prompt;
mod service;
mod session;
mod state;
mod unlock;
mod vault;

use service::load_vault;
use state::State;
use unlock::{apply_vault_data, try_unlock_with_keyfile};
use std::sync::Arc;
use tokio::sync::RwLock;

use directories::ProjectDirs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting wss-daemon...");

    let proj_dirs =
        ProjectDirs::from("org", "wssp", "wssp").ok_or("Could not determine project directories")?;
    std::fs::create_dir_all(proj_dirs.data_dir())?;
    let vault_path = proj_dirs.data_dir().join("vault.enc");
    let salt_path = proj_dirs.data_dir().join("vault.salt");
    let key_path = proj_dirs.data_dir().join("vault.key");
    info!("Vault path: {:?}", vault_path);

    let state = Arc::new(RwLock::new(State::new(
        vault_path.clone(),
        salt_path.clone(),
        key_path.clone(),
    )));

    // Ensure "login" collection always exists
    {
        let mut st = state.write().await;
        st.collections.entry("login".into()).or_insert_with(|| collection::Collection {
            id: "login".into(),
            label: Arc::new(RwLock::new("Login".into())),
            items: Arc::new(RwLock::new(std::collections::HashMap::new())),
            is_deleted: Arc::new(RwLock::new(false)),
            state: state.clone(),
        });
    }

    // Attempt automatic unlock at startup.
    if vault_path.exists() {
        if key_path.exists() {
            // Keyfile mode: no password needed, read key directly.
            info!("Keyfile mode detected; attempting automatic unlock.");
            match try_unlock_with_keyfile(&key_path, &vault_path, state.clone()).await {
                Ok(n) => info!("Vault auto-unlocked via keyfile. {} collection(s) loaded.", n),
                Err(e) => error!("Keyfile unlock failed: {}", e),
            }
        } else {
            // Password mode: look for PAM token written at login.
            let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
                .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
            let pam_token_path = std::path::PathBuf::from(&runtime_dir).join("wssp-pam-token");

            if pam_token_path.exists() {
                match std::fs::read_to_string(&pam_token_path) {
                    Ok(password) => {
                        let _ = std::fs::remove_file(&pam_token_path);
                        info!("PAM token found; attempting automatic unlock.");
                        match load_vault(&password, &vault_path, &salt_path, false) {
                            Ok((vault, data)) => {
                                apply_vault_data(vault, &data, state.clone()).await;
                                info!(
                                    "Vault auto-unlocked via PAM. {} collection(s) loaded.",
                                    data.collections.len()
                                );
                            }
                            Err(e) => error!("PAM auto-unlock failed: {}", e),
                        }
                    }
                    Err(e) => error!("Failed to read PAM token: {}", e),
                }
            } else {
                info!("Existing vault found; starting in locked state.");
            }
        }
    } else {
        // First run: auto-initialize in no-password mode.
        // Users who need password protection can run: wssp-cli set-password <password>
        info!("No vault found; initializing in no-password mode (keyfile).");
        let key = wssp_core::vault::Vault::generate_key();
        let key_hex = wssp_core::vault::Vault::key_to_hex(&key);
        match std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .open(&key_path)
        {
            Ok(mut f) => {
                use std::io::Write;
                use std::os::unix::fs::PermissionsExt;
                let _ = f.write_all(key_hex.as_bytes());
                let _ = std::fs::set_permissions(&key_path,
                    std::fs::Permissions::from_mode(0o600));
                let vault = wssp_core::vault::Vault::new(vault_path.clone(), key);
                match vault.save(&wssp_core::vault::VaultData { collections: vec![] }) {
                    Ok(_) => {
                        match try_unlock_with_keyfile(&key_path, &vault_path, state.clone()).await {
                            Ok(_) => info!("Vault initialized and unlocked in no-password mode."),
                            Err(e) => error!("Auto-init unlock failed: {}", e),
                        }
                    }
                    Err(e) => error!("Failed to initialize vault: {}", e),
                }
            }
            Err(e) => error!("Failed to create vault.key: {}", e),
        }
    }

    let service = service::Service::new(state.clone());
    let portal_service = portal::PortalSecret::new(state.clone());

    let conn = connection::Builder::session()?
        .name("org.freedesktop.secrets")?
        .serve_at("/org/freedesktop/secrets", service)?
        .serve_at("/org/freedesktop/portal/desktop", portal_service)?
        .build()
        .await?;

    // Register all collections (and their items) on D-Bus
    {
        let server = conn.object_server();
        let st = state.read().await;
        for (col_id, col) in st.collections.iter() {
            let col_path = format!("/org/freedesktop/secrets/collection/{}", col_id);
            if let Ok(p) = zbus::zvariant::OwnedObjectPath::try_from(col_path) {
                if let Err(e) = server.at(p, col.clone()).await {
                    error!("Failed to register collection {}: {}", col_id, e);
                } else {
                    info!("Registered collection: {}", col_id);
                }
            }

            for (item_id, item) in col.items.read().await.iter() {
                let item_path = format!(
                    "/org/freedesktop/secrets/collection/{}/{}",
                    col_id, item_id
                );
                if let Ok(p) = zbus::zvariant::OwnedObjectPath::try_from(item_path) {
                    let _ = server.at(p, item.clone()).await;
                }
            }

            if col_id == "login" {
                if let Ok(p) = zbus::zvariant::OwnedObjectPath::try_from(
                    "/org/freedesktop/secrets/aliases/default",
                ) {
                    let _ = server.at(p, col.clone()).await;
                    info!("Registered 'login' as 'default' alias.");
                }
            }
        }
    }

    // Screensaver integration: lock vault on screen lock, re-unlock on screensaver dismissal.
    logind::spawn_lock_listener(state.clone());
    logind::spawn_pam_watcher(state.clone(), vault_path, salt_path);

    info!("wss-daemon running.");

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

