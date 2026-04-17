use std::error::Error;
use tracing::{error, info};
use zbus::connection;

mod collection;
mod error;
mod ipc;
mod item;
mod portal;
mod prompt;
mod service;
mod session;
mod state;
mod vault;

use service::load_vault;
use state::{build_collections, State};
use std::sync::Arc;
use tokio::sync::RwLock;

use directories::ProjectDirs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting wss-daemon...");

    let proj_dirs =
        ProjectDirs::from("org", "wssp", "wss").ok_or("Could not determine project directories")?;
    std::fs::create_dir_all(proj_dirs.data_dir())?;
    let vault_path = proj_dirs.data_dir().join("vault.enc");
    let salt_path = proj_dirs.data_dir().join("vault.salt");

    let state = Arc::new(RwLock::new(State::new(
        vault_path.clone(),
        salt_path.clone(),
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

    // Attempt automatic unlock via PAM token written at login
    if vault_path.exists() {
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
                            let cols = build_collections(&data, state.clone());
                            let mut st = state.write().await;
                            for (col_id, col) in cols {
                                if let Some(existing) = st.collections.get(&col_id) {
                                    *existing.label.write().await = col.label.read().await.clone();
                                    *existing.items.write().await =
                                        col.items.read().await.clone();
                                } else {
                                    st.collections.insert(col_id, col);
                                }
                            }
                            st.vault = Some(vault);
                            st.is_unlocked = true;
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
    } else {
        info!("No existing vault; will prompt for password on first unlock.");
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

    info!("wss-daemon running.");

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
