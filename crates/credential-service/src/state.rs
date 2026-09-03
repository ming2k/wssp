use credential_core::{CredentialError, LockState, Namespace, Purpose, Result, SecretBytes, Subject};
use credential_crypto::{derive_app_secret, derive_portal_secret, MasterKey};
use credential_store::{FileVaultStore, StoredCollection, StoredItem, StoredVaultData};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::info;
use zeroize::Zeroize;

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug)]
pub struct ItemRecord {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Vec<u8>,
    pub content_type: String,
    pub created_at: u64,
    pub modified_at: u64,
}

#[derive(Clone, Debug)]
pub struct CollectionRecord {
    pub id: String,
    pub label: String,
    pub items: HashMap<String, ItemRecord>,
}

pub struct ServiceInner {
    pub store: FileVaultStore,
    pub master_key: Option<MasterKey>,
    pub collections: HashMap<String, CollectionRecord>,
}

#[derive(Clone)]
pub struct CredentialService {
    inner: Arc<RwLock<ServiceInner>>,
}

impl CredentialService {
    pub fn new(store: FileVaultStore) -> Self {
        let mut collections = HashMap::new();
        // Ensure default "login" collection exists in state
        collections.insert(
            "login".to_string(),
            CollectionRecord {
                id: "login".to_string(),
                label: "Login".to_string(),
                items: HashMap::new(),
            },
        );

        Self {
            inner: Arc::new(RwLock::new(ServiceInner {
                store,
                master_key: None,
                collections,
            })),
        }
    }

    pub async fn lock_state(&self) -> LockState {
        let inner = self.inner.read().await;
        if !inner.store.exists() && !inner.store.is_keyfile_mode() {
            if inner.master_key.is_some() {
                LockState::Unlocked
            } else {
                LockState::Uninitialized
            }
        } else if inner.master_key.is_some() {
            LockState::Unlocked
        } else {
            LockState::Locked
        }
    }

    pub async fn is_locked(&self) -> bool {
        let inner = self.inner.read().await;
        inner.master_key.is_none()
    }

    pub async fn lock(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(mut key) = inner.master_key.take() {
            key.zeroize();
            info!("Master key cleared. Credential service locked.");
        }
        // Zeroize in-memory secret items
        for col in inner.collections.values_mut() {
            for item in col.items.values_mut() {
                item.secret.zeroize();
            }
            col.items.clear();
        }
        Ok(())
    }

    pub async fn unlock_with_master_key(&self, key: MasterKey) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.store.exists() {
            let data = inner.store.load(&key)?;
            inner.collections.clear();
            for col in data.collections {
                let mut items = HashMap::new();
                for item in col.items {
                    items.insert(
                        item.id.clone(),
                        ItemRecord {
                            id: item.id.clone(),
                            label: item.label.clone(),
                            attributes: item.attributes.clone(),
                            secret: item.secret.clone(),
                            content_type: item.content_type.clone(),
                            created_at: item.created_at,
                            modified_at: item.modified_at,
                        },
                    );
                }
                inner.collections.insert(
                    col.id.clone(),
                    CollectionRecord {
                        id: col.id,
                        label: col.label,
                        items,
                    },
                );
            }
            // Ensure default login collection always present
            inner.collections.entry("login".to_string()).or_insert_with(|| {
                CollectionRecord {
                    id: "login".to_string(),
                    label: "Login".to_string(),
                    items: HashMap::new(),
                }
            });
        }
        inner.master_key = Some(key);
        info!("Credential service successfully unlocked.");
        Ok(())
    }

    pub async fn derive_app_secret(
        &self,
        namespace: &Namespace,
        subject: &Subject,
        purpose: &Purpose,
    ) -> Result<SecretBytes> {
        let inner = self.inner.read().await;
        let master_key = inner
            .master_key
            .as_ref()
            .ok_or(CredentialError::Locked)?;

        // Special backward-compatibility handling for Portal Secret v1
        if namespace.as_str() == "aegis.portal.Secret/v1" || namespace.as_str() == "xdg-portal" {
            Ok(derive_portal_secret(master_key, subject.as_str()))
        } else {
            Ok(derive_app_secret(
                master_key,
                namespace.as_str(),
                subject.as_str(),
                purpose.as_str(),
            ))
        }
    }

    pub async fn get_collection_ids(&self) -> Vec<String> {
        let inner = self.inner.read().await;
        inner.collections.keys().cloned().collect()
    }

    pub async fn get_collection(&self, id: &str) -> Result<CollectionRecord> {
        let inner = self.inner.read().await;
        inner
            .collections
            .get(id)
            .cloned()
            .ok_or_else(|| CredentialError::NotFound(format!("Collection {id} not found")))
    }

    pub async fn create_collection(&self, id: &str, label: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.collections.contains_key(id) {
            return Err(CredentialError::AlreadyExists(format!(
                "Collection {id} already exists"
            )));
        }
        inner.collections.insert(
            id.to_string(),
            CollectionRecord {
                id: id.to_string(),
                label: label.to_string(),
                items: HashMap::new(),
            },
        );
        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn delete_collection(&self, id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.collections.remove(id).is_none() {
            return Err(CredentialError::NotFound(format!(
                "Collection {id} not found"
            )));
        }
        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn get_item(&self, collection_id: &str, item_id: &str) -> Result<ItemRecord> {
        let inner = self.inner.read().await;
        if inner.master_key.is_none() {
            return Err(CredentialError::Locked);
        }
        let col = inner
            .collections
            .get(collection_id)
            .ok_or_else(|| CredentialError::NotFound(format!("Collection {collection_id} not found")))?;
        col.items
            .get(item_id)
            .cloned()
            .ok_or_else(|| CredentialError::NotFound(format!("Item {item_id} not found")))
    }

    pub async fn set_item(
        &self,
        collection_id: &str,
        item_id: &str,
        label: &str,
        attributes: HashMap<String, String>,
        secret: &[u8],
        content_type: &str,
        replace: bool,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.master_key.is_none() {
            return Err(CredentialError::Locked);
        }
        let col = inner
            .collections
            .get_mut(collection_id)
            .ok_or_else(|| CredentialError::NotFound(format!("Collection {collection_id} not found")))?;

        let now = current_timestamp();
        if let Some(existing) = col.items.get_mut(item_id) {
            if !replace {
                return Err(CredentialError::AlreadyExists(format!(
                    "Item {item_id} already exists"
                )));
            }
            existing.label = label.to_string();
            existing.attributes = attributes;
            existing.secret = secret.to_vec();
            existing.content_type = content_type.to_string();
            existing.modified_at = now;
        } else {
            col.items.insert(
                item_id.to_string(),
                ItemRecord {
                    id: item_id.to_string(),
                    label: label.to_string(),
                    attributes,
                    secret: secret.to_vec(),
                    content_type: content_type.to_string(),
                    created_at: now,
                    modified_at: now,
                },
            );
        }

        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn delete_item(&self, collection_id: &str, item_id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.master_key.is_none() {
            return Err(CredentialError::Locked);
        }
        let col = inner
            .collections
            .get_mut(collection_id)
            .ok_or_else(|| CredentialError::NotFound(format!("Collection {collection_id} not found")))?;

        if col.items.remove(item_id).is_none() {
            return Err(CredentialError::NotFound(format!("Item {item_id} not found")));
        }

        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn search_items(
        &self,
        collection_id: Option<&str>,
        attributes: &HashMap<String, String>,
    ) -> Result<Vec<(String, String)>> {
        let inner = self.inner.read().await;
        if inner.master_key.is_none() {
            return Err(CredentialError::Locked);
        }

        let mut matches = Vec::new();
        let target_collections: Vec<&CollectionRecord> = match collection_id {
            Some(id) => inner.collections.get(id).into_iter().collect(),
            None => inner.collections.values().collect(),
        };

        for col in target_collections {
            for item in col.items.values() {
                let all_match = attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k).map(|iv| iv == v).unwrap_or(false));
                if all_match {
                    matches.push((col.id.clone(), item.id.clone()));
                }
            }
        }

        Ok(matches)
    }

    fn save_locked(&self, inner: &mut ServiceInner) -> Result<()> {
        let master_key = match inner.master_key.as_ref() {
            Some(k) => k,
            None => return Ok(()), // Not yet unlocked, don't write empty
        };

        let mut collections_data = Vec::new();
        for col in inner.collections.values() {
            let mut items_data = Vec::new();
            for item in col.items.values() {
                items_data.push(StoredItem {
                    id: item.id.clone(),
                    label: item.label.clone(),
                    attributes: item.attributes.clone(),
                    secret: item.secret.clone(),
                    content_type: item.content_type.clone(),
                    created_at: item.created_at,
                    modified_at: item.modified_at,
                });
            }
            collections_data.push(StoredCollection {
                id: col.id.clone(),
                label: col.label.clone(),
                items: items_data,
            });
        }

        let vault_data = StoredVaultData {
            version: 1,
            collections: collections_data,
        };

        inner.store.save(master_key, &vault_data)
    }
}
