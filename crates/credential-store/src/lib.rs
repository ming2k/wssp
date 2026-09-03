pub mod file_store;
pub mod model;

pub use file_store::{
    atomic_replace, ensure_secure_dir, FileVaultStore, VAULT_ENC_FILENAME, VAULT_KDF_FILENAME,
    VAULT_KEY_FILENAME, VAULT_SALT_FILENAME,
};
pub use model::{StoredCollection, StoredItem, StoredVaultData, CURRENT_VAULT_VERSION};

#[cfg(test)]
mod tests {
    use super::*;
    use credential_crypto::MasterKey;
    use std::collections::HashMap;

    #[test]
    fn test_file_store_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("credentiald_test_store_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = FileVaultStore::new(temp_dir.clone());
        assert!(!store.exists());

        let key = MasterKey::generate();
        let mut data = StoredVaultData::default();
        data.collections.push(StoredCollection {
            id: "login".into(),
            label: "Login".into(),
            items: vec![StoredItem {
                id: "item1".into(),
                label: "My Password".into(),
                attributes: HashMap::from([("xdg:schema".into(), "login".into())]),
                secret: b"super-secret-pw".to_vec(),
                content_type: "text/plain".into(),
                created_at: 100,
                modified_at: 100,
            }],
        });

        store.save(&key, &data).unwrap();
        assert!(store.exists());

        let loaded = store.load(&key).unwrap();
        assert_eq!(loaded.collections.len(), 1);
        assert_eq!(loaded.collections[0].items.len(), 1);
        assert_eq!(loaded.collections[0].items[0].label, "My Password");
        assert_eq!(loaded.collections[0].items[0].secret, b"super-secret-pw");

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
