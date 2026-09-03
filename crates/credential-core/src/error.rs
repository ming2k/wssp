use thiserror::Error;

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Vault is locked")]
    Locked,

    #[error("Item or collection not found: {0}")]
    NotFound(String),

    #[error("Item or collection already exists: {0}")]
    AlreadyExists(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid request or arguments: {0}")]
    InvalidRequest(String),

    #[error("Authentication required: {0}")]
    AuthenticationRequired(String),

    #[error("Authentication was cancelled")]
    Cancelled,

    #[error("Storage failure: {0}")]
    StorageFailure(String),

    #[error("Cryptographic operation failure: {0}")]
    CryptoFailure(String),

    #[error("Corrupt data or format violation: {0}")]
    CorruptData(String),

    #[error("IO failure: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal failure: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CredentialError>;
