pub mod state;

pub use state::{CollectionRecord, SigilService, ItemRecord};

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{Namespace, Purpose, Subject};
    use sigil_crypto::MasterKey;
    use sigil_store::FileVaultStore;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_service_lifecycle_and_crud() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_svc_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = FileVaultStore::new(temp_dir.clone());
        let service = SigilService::new(store);

        assert!(service.is_locked().await);

        // Derive secret while locked fails
        let res = service
            .derive_app_secret(
                &Namespace::new("xdg-portal"),
                &Subject::new("org.mozilla.Firefox"),
                &Purpose::new("master-secret"),
            )
            .await;
        assert!(res.is_err());

        // Unlock
        let key = MasterKey::generate();
        service.unlock_with_master_key(key).await.unwrap();
        assert!(!service.is_locked().await);

        // Derive secret succeeds
        let sec = service
            .derive_app_secret(
                &Namespace::new("xdg-portal"),
                &Subject::new("org.mozilla.Firefox"),
                &Purpose::new("master-secret"),
            )
            .await
            .unwrap();
        assert_eq!(sec.len(), 32);

        // Item CRUD
        service
            .set_item(
                "login",
                "item-1",
                "Test Label",
                HashMap::from([("service".into(), "github.com".into())]),
                b"my-password",
                "text/plain",
                false,
            )
            .await
            .unwrap();

        let item = service.get_item("login", "item-1").await.unwrap();
        assert_eq!(item.label, "Test Label");
        assert_eq!(item.secret, b"my-password");

        // Search
        let matches = service
            .search_items(None, &HashMap::from([("service".into(), "github.com".into())]))
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], ("login".into(), "item-1".into()));

        // Lock
        service.lock().await.unwrap();
        assert!(service.is_locked().await);
        assert!(service.get_item("login", "item-1").await.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
