pub mod cipher;
pub mod dh;
pub mod hkdf;
pub mod kdf;
pub mod key;

pub use cipher::{decrypt_xchacha20poly1305, encrypt_xchacha20poly1305};
pub use dh::{
    decrypt_secret_service_aes128, encrypt_secret_service_aes128, DhSession, DH_GENERATOR,
    DH_PRIME_HEX,
};
pub use hkdf::{derive_app_secret, derive_portal_secret};
pub use kdf::{
    decode_kdf, derive_key_argon2id, encode_kdf, generate_salt, KdfConfig, KdfParams,
    DEFAULT_SALT_LEN, KDF_FILE_VERSION, KDF_NAME,
};
pub use key::{MasterKey, MASTER_KEY_LEN};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20_roundtrip() {
        let key = MasterKey::generate();
        let plaintext = b"Hello, sigil cryptographic world!";
        let aad = b"context-metadata";

        let ciphertext = encrypt_xchacha20poly1305(&key, plaintext, aad).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt_xchacha20poly1305(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);

        // Tampered ciphertext fails
        let mut tampered = ciphertext.clone();
        let len = tampered.len();
        tampered[len - 1] ^= 0x01;
        assert!(decrypt_xchacha20poly1305(&key, &tampered, aad).is_err());

        // Wrong AAD fails
        assert!(decrypt_xchacha20poly1305(&key, &ciphertext, b"wrong-aad").is_err());
    }

    #[test]
    fn test_argon2id_derivation() {
        let password = b"correct horse battery staple";
        let salt = generate_salt(DEFAULT_SALT_LEN);
        let params = KdfParams {
            m_cost: 1024, // low memory for fast test
            t_cost: 1,
            p_cost: 1,
            version: 0x13,
        };

        let key1 = derive_key_argon2id(password, &salt, &params).unwrap();
        let key2 = derive_key_argon2id(password, &salt, &params).unwrap();
        assert_eq!(key1, key2);

        let wrong_key = derive_key_argon2id(b"wrong password", &salt, &params).unwrap();
        assert_ne!(key1, wrong_key);
    }

    #[test]
    fn test_hkdf_domain_isolation() {
        let key = MasterKey::generate();
        let s1 = derive_app_secret(&key, "xdg-portal", "org.mozilla.Firefox", "master-secret");
        let s2 = derive_app_secret(&key, "xdg-portal", "org.chromium.Chromium", "master-secret");
        let s3 = derive_app_secret(&key, "other-ns", "org.mozilla.Firefox", "master-secret");
        let s4 = derive_app_secret(&key, "xdg-portal", "org.mozilla.Firefox", "token");

        assert_eq!(s1.len(), 32);
        assert_ne!(s1.as_slice(), s2.as_slice());
        assert_ne!(s1.as_slice(), s3.as_slice());
        assert_ne!(s1.as_slice(), s4.as_slice());
    }

    #[test]
    fn test_dh_session_roundtrip() {
        let server_dh = DhSession::generate().unwrap();
        let client_dh = DhSession::generate().unwrap();

        let server_key = server_dh.derive_shared_key(&client_dh.public_key).unwrap();
        let client_key = client_dh.derive_shared_key(&server_dh.public_key).unwrap();
        assert_eq!(server_key, client_key);

        let secret = b"super-secret-password-123";
        let (iv, ciphertext) = encrypt_secret_service_aes128(&client_key, secret).unwrap();
        let decrypted = decrypt_secret_service_aes128(&server_key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), secret);
    }
}
