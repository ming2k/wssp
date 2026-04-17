use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tracing::{error, info};
use wss_common::ipc::PromptResponse;

pub async fn request_password(is_initial: bool) -> Result<String, Box<dyn std::error::Error>> {
    if std::env::var("WAYLAND_DISPLAY").is_err() && std::env::var("DISPLAY").is_err() {
        if let Ok(pwd) = std::env::var("WSSP_PASSWORD") {
            info!(
                "Headless environment detected. Unlocking via WSSP_PASSWORD environment variable."
            );
            return Ok(pwd);
        } else {
            return Err(
                "Headless environment detected, but WSSP_PASSWORD is not set. Cannot prompt user."
                    .into(),
            );
        }
    }

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_path = PathBuf::from(runtime_dir).join("wssp.sock");

    // Bind socket, removing stale file if necessary (avoids TOCTOU)
    let listener = UnixListener::bind(&socket_path).or_else(|_| {
        std::fs::remove_file(&socket_path)?;
        UnixListener::bind(&socket_path)
    })?;
    info!("Listening for prompter on {:?}", socket_path);

    // Spawn the prompter process
    let prompter_path = if let Ok(path) = std::env::var("WSSP_PROMPTER_PATH") {
        path
    } else if let Ok(mut exe_path) = std::env::current_exe() {
        exe_path.set_file_name("wss-prompter");
        if exe_path.exists() {
            exe_path.to_string_lossy().to_string()
        } else {
            "wss-prompter".to_string()
        }
    } else {
        "wss-prompter".to_string()
    };

    let mut prompter_cmd = Command::new(prompter_path);
    
    // Pass the mode to prompter
    if is_initial {
        prompter_cmd.env("WSSP_PROMPT_MODE", "create");
    }

    match prompter_cmd.spawn() {
        Ok(child) => {
            info!("Spawned wss-prompter with PID: {}", child.id());
        }
        Err(e) => {
            error!("Failed to spawn wss-prompter ({}). Ensure it is in your PATH or set WSSP_PROMPTER_PATH.", e);
            return Err(e.into());
        }
    }

    // Wait for the connection (60s timeout — user may be slow to respond)
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(60), listener.accept())
        .await
        .map_err(|_| "Prompt timed out: no response from prompter")??;
    info!("Accepted connection from prompter");

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut buf))
        .await
        .map_err(|_| "Prompt timed out: incomplete data from prompter")??;

    // Cleanup the socket file
    let _ = std::fs::remove_file(&socket_path);

    let response: PromptResponse = serde_json::from_slice(&buf)?;

    if let Some(password) = response.password {
        Ok(password)
    } else {
        Err("No password provided".into())
    }
}
