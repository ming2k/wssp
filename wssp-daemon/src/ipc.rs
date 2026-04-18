use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tracing::{error, info};
use wssp_common::ipc::PromptResponse;

fn has_display() -> bool {
    std::env::var("WAYLAND_DISPLAY").is_ok() || std::env::var("DISPLAY").is_ok()
}

pub async fn request_password() -> Result<String, Box<dyn std::error::Error>> {
    // On boot the Wayland compositor may not have exported WAYLAND_DISPLAY yet.
    // Wait up to 30 s for a display to appear before falling back to headless.
    if !has_display() {
        for _ in 0..15 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if has_display() {
                break;
            }
        }
    }

    if !has_display() {
        if let Ok(pwd) = std::env::var("WSSP_PASSWORD") {
            info!("Headless environment detected. Unlocking via WSSP_PASSWORD.");
            return Ok(pwd);
        } else {
            return Err(
                "Headless environment detected, but WSSP_PASSWORD is not set.".into(),
            );
        }
    }

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_path = PathBuf::from(runtime_dir).join("wssp.sock");

    let listener = UnixListener::bind(&socket_path).or_else(|_| {
        std::fs::remove_file(&socket_path)?;
        UnixListener::bind(&socket_path)
    })?;
    info!("Listening for prompter on {:?}", socket_path);

    let prompter_path = if let Ok(path) = std::env::var("WSSP_PROMPTER_PATH") {
        path
    } else if let Ok(mut exe_path) = std::env::current_exe() {
        exe_path.set_file_name("wssp-prompter");
        if exe_path.exists() {
            exe_path.to_string_lossy().to_string()
        } else {
            "wssp-prompter".to_string()
        }
    } else {
        "wssp-prompter".to_string()
    };

    match Command::new(prompter_path).spawn() {
        Ok(child) => info!("Spawned wssp-prompter with PID: {}", child.id()),
        Err(e) => {
            error!("Failed to spawn wssp-prompter: {}. Set WSSP_PROMPTER_PATH if needed.", e);
            return Err(e.into());
        }
    }

    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(60), listener.accept())
        .await
        .map_err(|_| "Prompt timed out: no response from prompter")??;
    info!("Accepted connection from prompter");

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut buf))
        .await
        .map_err(|_| "Prompt timed out: incomplete data from prompter")??;

    let _ = std::fs::remove_file(&socket_path);

    let response: PromptResponse = serde_json::from_slice(&buf)?;
    response.password.ok_or_else(|| "No password provided (user cancelled)".into())
}
