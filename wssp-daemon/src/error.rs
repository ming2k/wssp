use thiserror::Error;
use wssp_core::error::CoreError;

#[derive(Error, Debug)]
pub enum WssDaemonError {
    #[error("Core logic error: {0}")]
    Core(#[from] CoreError),

    #[error("D-Bus protocol error: {0}")]
    Zbus(#[from] zbus::Error),

    #[error("Invalid D-Bus argument: {0}")]
    InvalidArgs(String),

    #[error("Internal service error: {0}")]
    Internal(String),
}

// 自动将 daemon 错误转换为 D-Bus 的标准错误响应
impl From<WssDaemonError> for zbus::fdo::Error {
    fn from(err: WssDaemonError) -> Self {
        match err {
            WssDaemonError::InvalidArgs(msg) => zbus::fdo::Error::InvalidArgs(msg),
            _ => zbus::fdo::Error::Failed(err.to_string()),
        }
    }
}
