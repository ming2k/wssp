pub mod client;
pub mod error;

pub use client::{SigilClient, DEFAULT_SOCKET_SUBPATH};
pub use error::{ClientError, Result};

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_crypto::MasterKey;
    use sigil_ipc::NativeIpcServer;
    use sigil_service::SigilService;
    use sigil_store::FileVaultStore;

    #[tokio::test]
    async fn test_client_integration() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_client_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let sock_path = temp_dir.join("native.sock");
        let store = FileVaultStore::new(temp_dir.clone());
        let service = SigilService::new(store);

        let server = NativeIpcServer::new(sock_path.clone(), service.clone());
        tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Wait for socket to be ready
        for _ in 0..50 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        let client = SigilClient::new(sock_path);

        // Ping works
        client.ping().await.unwrap();

        // While locked, get_application_secret returns ClientError::Locked
        assert!(client.is_locked().await.unwrap());
        let err = client
            .get_application_secret("xdg-portal", "org.test.App", "master-secret")
            .await;
        assert!(matches!(err, Err(ClientError::Locked)));

        // Unlock
        let key = MasterKey::generate();
        service.unlock_with_master_key(key).await.unwrap();
        assert!(!client.is_locked().await.unwrap());

        // Now secret retrieval succeeds
        let sec = client
            .get_application_secret("xdg-portal", "org.test.App", "master-secret")
            .await
            .unwrap();
        assert_eq!(sec.len(), 32);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
