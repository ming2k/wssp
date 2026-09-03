use sigil_client::{ClientError, SigilClient};
use sigil_crypto::MasterKey;
use sigil_ipc::NativeIpcServer;
use sigil_service::SigilService;
use sigil_store::FileVaultStore;
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn test_portal_secret_derivation_and_isolation() {
    let temp_dir = std::env::temp_dir().join(format!("sigil_portal_int_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let sock_path = temp_dir.join("native.sock");
    let store = FileVaultStore::new(temp_dir.clone());
    let service = SigilService::new(store);

    let key = MasterKey::generate();
    service.unlock_with_master_key(key).await.unwrap();

    let server = NativeIpcServer::new(sock_path.clone(), service.clone());
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    for _ in 0..50 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    let client = SigilClient::new(sock_path);

    // 1. Check unlock status
    let locked = client.is_locked().await.unwrap();
    assert!(!locked);

    // 2. Retrieve secret for Firefox
    let firefox_secret = client
        .get_application_secret("aegis.portal.Secret/v1", "org.mozilla.Firefox", "master-secret")
        .await
        .unwrap();
    assert_eq!(firefox_secret.len(), 32);

    // 3. Retrieve secret again for Firefox -> must be 100% deterministic
    let firefox_secret_repeat = client
        .get_application_secret("aegis.portal.Secret/v1", "org.mozilla.Firefox", "master-secret")
        .await
        .unwrap();
    assert_eq!(firefox_secret.as_slice(), firefox_secret_repeat.as_slice());

    // 4. Retrieve secret for Chromium -> must be completely isolated
    let chromium_secret = client
        .get_application_secret("aegis.portal.Secret/v1", "org.chromium.Chromium", "master-secret")
        .await
        .unwrap();
    assert_eq!(chromium_secret.len(), 32);
    assert_ne!(firefox_secret.as_slice(), chromium_secret.as_slice());

    // 5. Lock vault
    client.lock().await.unwrap();
    assert!(client.is_locked().await.unwrap());

    // 6. After lock, retrieving secret fails closed with Locked
    let err = client
        .get_application_secret("aegis.portal.Secret/v1", "org.mozilla.Firefox", "master-secret")
        .await;
    assert!(matches!(err, Err(ClientError::Locked)));

    let _ = std::fs::remove_dir_all(&temp_dir);
}
