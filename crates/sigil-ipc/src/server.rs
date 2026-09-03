use crate::frame::{read_request, write_response};
use crate::peer::check_peer_credentials;
use crate::protocol::{IpcRequest, IpcResponse};
use sigil_core::{SigilError, Namespace, Purpose, Result, Subject};
use sigil_service::SigilService;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

pub struct NativeIpcServer {
    socket_path: PathBuf,
    service: SigilService,
}

impl NativeIpcServer {
    pub fn new(socket_path: PathBuf, service: SigilService) -> Self {
        Self {
            socket_path,
            service,
        }
    }

    pub async fn run(self) -> Result<()> {
        if let Some(parent) = self.socket_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }

        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        fs::set_permissions(&self.socket_path, fs::Permissions::from_mode(0o600))?;
        info!(
            "Native IPC server listening on {}",
            self.socket_path.display()
        );

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let service = self.service.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, service).await {
                            debug!("IPC connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting IPC connection: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(mut stream: UnixStream, service: SigilService) -> Result<()> {
    if let Err(e) = check_peer_credentials(&stream) {
        let resp = IpcResponse::AccessDenied(e.to_string());
        let _ = write_response(&mut stream, &resp).await;
        return Err(e);
    }

    loop {
        let req = match read_request(&mut stream).await {
            Ok(r) => r,
            Err(SigilError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e),
        };

        let resp = match req {
            IpcRequest::Ping => IpcResponse::Success,
            IpcRequest::GetLockStatus => {
                let status = service.lock_state().await;
                IpcResponse::LockStatus(status)
            }
            IpcRequest::Lock => match service.lock().await {
                Ok(_) => IpcResponse::Success,
                Err(e) => IpcResponse::Error(e.to_string()),
            },
            IpcRequest::GetApplicationSecret {
                namespace,
                subject,
                purpose,
            } => {
                match service
                    .derive_app_secret(
                        &Namespace::new(namespace),
                        &Subject::new(subject),
                        &Purpose::new(purpose),
                    )
                    .await
                {
                    Ok(secret) => IpcResponse::Secret(secret.as_slice().to_vec()),
                    Err(SigilError::Locked) => IpcResponse::Locked,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
        };

        write_response(&mut stream, &resp).await?;
    }

    Ok(())
}
