use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Encryption/Decryption error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Vault error: {0}")]
    Vault(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
