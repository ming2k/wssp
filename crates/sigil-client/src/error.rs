use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("XDG_RUNTIME_DIR environment variable is not set")]
    NoRuntimeDir,

    #[error("Failed to connect to sigil socket at {0}: {1}")]
    ConnectionFailed(std::path::PathBuf, std::io::Error),

    #[error("Credential vault is locked")]
    Locked,

    #[error("Operation was cancelled by user")]
    Cancelled,

    #[error("Access denied by daemon: {0}")]
    AccessDenied(String),

    #[error("Daemon error: {0}")]
    DaemonError(String),

    #[error("Protocol / framing error: {0}")]
    Protocol(#[from] sigil_core::SigilError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ClientError>;
