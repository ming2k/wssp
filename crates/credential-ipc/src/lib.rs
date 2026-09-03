pub mod frame;
pub mod peer;
pub mod protocol;
pub mod server;

pub use frame::{read_request, read_response, write_request, write_response};
pub use peer::check_peer_credentials;
pub use protocol::{IpcRequest, IpcResponse, PromptResponse};
pub use server::NativeIpcServer;

#[cfg(test)]
mod tests {
    use super::*;
    use credential_crypto::MasterKey;
    use credential_service::CredentialService;
    use credential_store::FileVaultStore;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_ipc_server_client_flow() {
        let temp_dir = std::env::temp_dir().join(format!("credentiald_ipc_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let sock_path = temp_dir.join("native.sock");
        let store = FileVaultStore::new(temp_dir.clone());
        let service = CredentialService::new(store);

        let key = MasterKey::generate();
        service.unlock_with_master_key(key).await.unwrap();

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

        let mut stream = UnixStream::connect(&sock_path).await.unwrap();

        // Ping
        write_request(&mut stream, &IpcRequest::Ping).await.unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::Success));

        // GetApplicationSecret
        write_request(
            &mut stream,
            &IpcRequest::GetApplicationSecret {
                namespace: "xdg-portal".into(),
                subject: "org.mozilla.Firefox".into(),
                purpose: "master-secret".into(),
            },
        )
        .await
        .unwrap();

        let resp = read_response(&mut stream).await.unwrap();
        match resp {
            IpcResponse::Secret(bytes) => assert_eq!(bytes.len(), 32),
            other => panic!("Expected Secret, got {:?}", other),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
