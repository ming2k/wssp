use crate::collection::Collection;
use crate::item::Item;
use crate::session::Session;
use crate::vault::{CollectionData, ItemData, Vault, VaultData};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use zbus::zvariant::OwnedObjectPath;

pub struct State {
    pub collections: HashMap<String, Collection>,
    pub sessions: HashMap<OwnedObjectPath, Arc<Session>>,
    pub is_unlocked: bool,
    pub is_unlocking: bool,
    pub vault: Option<Vault>,
    pub vault_path: PathBuf,
    pub salt_path: PathBuf,
}

impl State {
    pub fn new(vault_path: PathBuf, salt_path: PathBuf) -> Self {
        Self {
            collections: HashMap::new(),
            sessions: HashMap::new(),
            is_unlocked: false,
            is_unlocking: false,
            vault: None,
            vault_path,
            salt_path,
        }
    }

    pub async fn sync_to_vault(&self) {
        let Some(vault) = &self.vault else { return };
        let mut collections = Vec::new();
        for (col_id, col) in &self.collections {
            if *col.is_deleted.read().await {
                continue;
            }
            let mut items = Vec::new();
            for (item_id, item) in col.items.read().await.iter() {
                if !*item.is_deleted.read().await {
                    items.push(ItemData {
                        id: item_id.clone(),
                        label: item.label.read().await.clone(),
                        attributes: item.attributes.read().await.clone(),
                        secret: item.secret.read().await.clone(),
                    });
                }
            }
            collections.push(CollectionData {
                id: col_id.clone(),
                label: col.label.read().await.clone(),
                items,
            });
        }
        if let Err(e) = vault.save(&VaultData { collections }) {
            tracing::error!("Failed to sync vault to disk: {}", e);
        } else {
            tracing::info!("Vault synced to disk.");
        }
    }
}

/// Build in-memory Collection and Item objects from deserialized vault data.
pub fn build_collections(
    data: &VaultData,
    state: Arc<RwLock<State>>,
) -> HashMap<String, Collection> {
    data.collections
        .iter()
        .map(|col_data| {
            let items: HashMap<String, Item> = col_data
                .items
                .iter()
                .map(|item_data| {
                    let item = Item {
                        id: item_data.id.clone(),
                        label: Arc::new(RwLock::new(item_data.label.clone())),
                        attributes: Arc::new(RwLock::new(item_data.attributes.clone())),
                        secret: Arc::new(RwLock::new(item_data.secret.clone())),
                        is_deleted: Arc::new(RwLock::new(false)),
                        state: state.clone(),
                    };
                    (item_data.id.clone(), item)
                })
                .collect();

            let col = Collection {
                id: col_data.id.clone(),
                label: Arc::new(RwLock::new(col_data.label.clone())),
                items: Arc::new(RwLock::new(items)),
                is_deleted: Arc::new(RwLock::new(false)),
                state: state.clone(),
            };
            (col_data.id.clone(), col)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_initialization() {
        let vault_path = PathBuf::from("/tmp/vault.enc");
        let salt_path = PathBuf::from("/tmp/vault.salt");
        let state = State::new(vault_path.clone(), salt_path.clone());

        assert_eq!(state.vault_path, vault_path);
        assert_eq!(state.salt_path, salt_path);
        assert!(!state.is_unlocked);
        assert!(!state.is_unlocking);
        assert!(state.vault.is_none());
        assert!(state.collections.is_empty());
        assert!(state.sessions.is_empty());
    }
}
