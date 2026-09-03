use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CURRENT_VAULT_VERSION: u32 = 1;

/// In-memory representation of an individual stored item in the vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StoredItem {
    pub id: String,
    pub label: String,
    #[zeroize(skip)]
    pub attributes: HashMap<String, String>,
    pub secret: Vec<u8>,
    #[zeroize(skip)]
    pub content_type: String,
    #[zeroize(skip)]
    pub created_at: u64,
    #[zeroize(skip)]
    pub modified_at: u64,
}

/// In-memory representation of a collection in the vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCollection {
    pub id: String,
    pub label: String,
    pub items: Vec<StoredItem>,
}

/// The root data structure serialized into encrypted vault payloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredVaultData {
    #[serde(default = "default_vault_version")]
    pub version: u32,
    pub collections: Vec<StoredCollection>,
}

fn default_vault_version() -> u32 {
    CURRENT_VAULT_VERSION
}

impl Default for StoredVaultData {
    fn default() -> Self {
        Self {
            version: CURRENT_VAULT_VERSION,
            collections: Vec::new(),
        }
    }
}
