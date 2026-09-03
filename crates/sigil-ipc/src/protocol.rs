use sigil_core::LockState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptResponse {
    pub password: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Retrieve/derive an application secret for a given namespace, subject, and purpose
    GetApplicationSecret {
        namespace: String,
        subject: String,
        purpose: String,
    },
    /// Query the current lock status of the credential service
    GetLockStatus,
    /// Lock the vault, clearing in-memory keys
    Lock,
    /// Ping the daemon to test connectivity
    Ping,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    /// Success with raw 32-byte secret payload
    Secret(Vec<u8>),
    /// Current lock state
    LockStatus(LockState),
    /// Operation succeeded without payload
    Success,
    /// Operation failed because the service is locked
    Locked,
    /// Operation cancelled by user or timeout
    Cancelled,
    /// Access denied (caller UID mismatch or permission issue)
    AccessDenied(String),
    /// Internal error or invalid argument
    Error(String),
}
