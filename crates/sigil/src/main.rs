use sigil_crypto::MasterKey;
use sigil_ipc::NativeIpcServer;
use sigil_secret_service::{Collection, Prompt, SecretServiceDbus};
use sigil_service::SigilService;
use sigil_store::{ensure_secure_dir, FileVaultStore, StoredVaultData};
use directories::ProjectDirs;
use std::error::Error;
use std::path::PathBuf;
use tracing::{error, info};
use zbus::connection;

mod logind;

fn get_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SIGIL_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(proj_dirs) = ProjectDirs::from("org", "freedesktop", "sigil") {
        proj_dirs.data_dir().to_path_buf()
    } else {
        PathBuf::from(".local/share/sigil")
    }
}

fn get_runtime_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("SIGIL_SOCKET_PATH") {
        return PathBuf::from(path);
    }
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(runtime_dir).join("sigil/native.sock")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting sigil daemon...");

    let data_dir = get_data_dir();
    ensure_secure_dir(&data_dir)?;
    let store = FileVaultStore::new(data_dir.clone());
    let service = SigilService::new(store.clone());

    // Auto-unlock or auto-init
    if store.exists() {
        if store.is_keyfile_mode() {
            match store.read_keyfile() {
                Ok(key) => match service.unlock_with_master_key(key).await {
                    Ok(_) => info!("Vault unlocked using keyfile."),
                    Err(e) => error!("Failed to unlock vault with keyfile: {}", e),
                },
                Err(e) => error!("Failed to read keyfile: {}", e),
            }
        } else {
            info!("Password-mode vault detected. Awaiting unlock.");
        }
    } else {
        // Initialize new keyfile vault
        info!("No vault found at {}. Creating new vault in keyfile mode.", data_dir.display());
        let key = MasterKey::generate();
        if let Err(e) = store.write_keyfile(&key) {
            error!("Failed to write keyfile: {}", e);
        } else if let Err(e) = store.save(&key, &StoredVaultData::default()) {
            error!("Failed to initialize vault: {}", e);
        } else if let Err(e) = service.unlock_with_master_key(key).await {
            error!("Failed to unlock newly initialized vault: {}", e);
        } else {
            info!("New vault initialized and unlocked.");
        }
    }

    // Spawn Native IPC server
    let socket_path = get_runtime_socket_path();
    let ipc_service = service.clone();
    tokio::spawn(async move {
        let server = NativeIpcServer::new(socket_path, ipc_service);
        if let Err(e) = server.run().await {
            error!("Native IPC server terminated with error: {}", e);
        }
    });

    // Spawn logind lock listener
    logind::spawn_lock_listener(service.clone(), data_dir.clone());

    // Setup Secret Service D-Bus interface
    let secret_service = SecretServiceDbus::new(service.clone());
    let prompt = Prompt {
        path: zbus::zvariant::ObjectPath::from_static_str("/org/freedesktop/secrets/prompt/default").unwrap(),
    };

    let default_login_col = Collection {
        id: "login".into(),
        service: service.clone(),
        sessions: secret_service.sessions.clone(),
    };

    let _conn = connection::Builder::session()?
        .name("org.freedesktop.secrets")?
        .serve_at("/org/freedesktop/secrets", secret_service)?
        .serve_at("/org/freedesktop/secrets/prompt/default", prompt)?
        .serve_at("/org/freedesktop/secrets/collection/login", default_login_col)?
        .build()
        .await?;

    info!("sigil successfully registered on D-Bus as org.freedesktop.secrets.");

    // Keep daemon running
    std::future::pending::<()>().await;

    Ok(())
}
