use sigil_service::SigilService;
use futures_util::StreamExt;
use std::path::PathBuf;
use tracing::{error, info, warn};

/// Subscribe to logind Session.Lock signal -> lock vault when screen locks.
pub fn spawn_lock_listener(service: SigilService, _data_dir: PathBuf) {
    tokio::spawn(async move {
        if let Err(e) = run_lock_listener(service).await {
            warn!("logind lock listener stopped: {}", e);
        }
    });
}

async fn run_lock_listener(service: SigilService) -> Result<(), Box<dyn std::error::Error>> {
    let system_bus = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Could not connect to system bus for logind: {}", e);
            return Ok(());
        }
    };

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
        info!("Screen locked — locking credential vault.");
        if let Err(e) = service.lock().await {
            error!("Error locking vault on screen lock: {}", e);
        }
    }

    Ok(())
}
