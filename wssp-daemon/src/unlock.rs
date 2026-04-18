use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use wssp_core::vault::{Vault, VaultData};

use crate::state::{build_collections, State};

pub async fn try_unlock_with_keyfile(
    key_path: &Path,
    vault_path: &Path,
    state: Arc<RwLock<State>>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let hex = std::fs::read_to_string(key_path)?;
    let key = Vault::key_from_hex(hex.trim())?;
    let vault = Vault::new(vault_path.to_path_buf(), key);
    let data = vault.load()?;
    let n = data.collections.len();
    apply_vault_data(vault, &data, state).await;
    Ok(n)
}

pub async fn apply_vault_data(
    vault: Vault,
    data: &VaultData,
    state: Arc<RwLock<State>>,
) {
    let cols = build_collections(data, state.clone());
    let mut st = state.write().await;
    for (col_id, col) in cols {
        if let Some(existing) = st.collections.get(&col_id) {
            *existing.label.write().await = col.label.read().await.clone();
            *existing.items.write().await = col.items.read().await.clone();
        } else {
            st.collections.insert(col_id, col);
        }
    }
    st.vault = Some(vault);
    st.is_unlocked = true;
}
