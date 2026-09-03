use crate::error::{ClientError, Result};
use sigil_core::{LockState, SecretBytes};
use sigil_ipc::{read_response, write_request, IpcRequest, IpcResponse};
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;

pub const DEFAULT_SOCKET_SUBPATH: &str = "sigil/native.sock";

#[derive(Clone, Debug)]
pub struct SigilClient {
    socket_path: PathBuf,
}

impl SigilClient {
    /// Creates a client targeting the specified socket path.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Creates a client connecting to the default `$XDG_RUNTIME_DIR/sigil/native.sock`.
    pub fn connect_default() -> Result<Self> {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .ok_or(ClientError::NoRuntimeDir)?;
        let path = PathBuf::from(runtime_dir).join(DEFAULT_SOCKET_SUBPATH);
        Ok(Self::new(path))
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    async fn open_stream(&self) -> Result<UnixStream> {
        UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| ClientError::ConnectionFailed(self.socket_path.clone(), e))
    }

    /// Pings the sigil daemon.
    pub async fn ping(&self) -> Result<()> {
        let mut stream = self.open_stream().await?;
        write_request(&mut stream, &IpcRequest::Ping).await?;
        match read_response(&mut stream).await? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!("Unexpected response: {:?}", other))),
        }
    }

    /// Queries the current lock status of the credential service.
    pub async fn get_lock_status(&self) -> Result<LockState> {
        let mut stream = self.open_stream().await?;
        write_request(&mut stream, &IpcRequest::GetLockStatus).await?;
        match read_response(&mut stream).await? {
            IpcResponse::LockStatus(status) => Ok(status),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!("Unexpected response: {:?}", other))),
        }
    }

    /// Checks if the credential service is locked.
    pub async fn is_locked(&self) -> Result<bool> {
        let status = self.get_lock_status().await?;
        Ok(status != LockState::Unlocked)
    }

    /// Retrieves / derives an application secret for a specific namespace, subject, and purpose.
    pub async fn get_application_secret(
        &self,
        namespace: &str,
        subject: &str,
        purpose: &str,
    ) -> Result<SecretBytes> {
        let mut stream = self.open_stream().await?;
        let req = IpcRequest::GetApplicationSecret {
            namespace: namespace.to_string(),
            subject: subject.to_string(),
            purpose: purpose.to_string(),
        };

        write_request(&mut stream, &req).await?;
        match read_response(&mut stream).await? {
            IpcResponse::Secret(bytes) => Ok(SecretBytes::new(bytes)),
            IpcResponse::Locked => Err(ClientError::Locked),
            IpcResponse::Cancelled => Err(ClientError::Cancelled),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            other => Err(ClientError::DaemonError(format!("Unexpected response: {:?}", other))),
        }
    }

    /// Locks the credential service.
    pub async fn lock(&self) -> Result<()> {
        let mut stream = self.open_stream().await?;
        write_request(&mut stream, &IpcRequest::Lock).await?;
        match read_response(&mut stream).await? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!("Unexpected response: {:?}", other))),
        }
    }
}
