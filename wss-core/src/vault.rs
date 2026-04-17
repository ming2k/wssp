use crate::error::{CoreError, Result};
use argon2::{
    password_hash::SaltString,
    Argon2,
};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct VaultData {
    pub collections: Vec<CollectionData>,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct CollectionData {
    pub label: String,
    pub id: String,
    pub items: Vec<ItemData>,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ItemData {
    pub id: String,
    pub label: String,
    #[zeroize(skip)]
    pub attributes: std::collections::HashMap<String, String>,
    pub secret: Vec<u8>,
}

pub struct Vault {
    path: PathBuf,
    master_key: [u8; 32],
}

impl Vault {
    pub fn get_master_key(&self) -> &[u8; 32] {
        &self.master_key
    }

    pub fn new(path: PathBuf, master_key: [u8; 32]) -> Self {
        Self { path, master_key }
    }

    pub fn derive_key(password: &str, salt_str: &str) -> Result<[u8; 32]> {
        let salt = SaltString::from_b64(salt_str)
            .map_err(|e| CoreError::Crypto(format!("Invalid salt: {}", e)))?;
        let argon2 = Argon2::default();
        
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
            .map_err(|e| CoreError::Crypto(format!("Hash failed: {}", e)))?;

        Ok(key)
    }

    pub fn generate_salt() -> String {
        SaltString::generate(&mut OsRng).as_str().to_string()
    }

    pub fn save(&self, data: &VaultData) -> Result<()> {
        let serialized = serde_json::to_vec(data)?;
        let cipher = XChaCha20Poly1305::new(&self.master_key.into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, serialized.as_ref())
            .map_err(|e| CoreError::Crypto(format!("Encryption failure: {}", e)))?;

        let mut final_data = nonce.to_vec();
        final_data.extend_from_slice(&ciphertext);

        fs::write(&self.path, final_data).map_err(CoreError::Io)
    }

    pub fn load(&self) -> Result<VaultData> {
        if !self.path.exists() {
            return Ok(VaultData {
                collections: vec![],
            });
        }

        let file_data = fs::read(&self.path).map_err(CoreError::Io)?;
        if file_data.len() < 24 {
            return Err(CoreError::Vault("Vault file corrupted".to_string()));
        }

        let (nonce_bytes, ciphertext) = file_data.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        let cipher = XChaCha20Poly1305::new(&self.master_key.into());
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CoreError::Crypto(format!("Decryption failure: {}", e)))?;

        let data: VaultData =
            serde_json::from_slice(&plaintext).map_err(CoreError::Serialization)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_crypto_lifecycle() {
        let temp_dir = std::env::temp_dir();
        let vault_path = temp_dir.join("test_vault.enc");

        let password = "super-secret-password";
        let salt = Vault::generate_salt();
        let key = Vault::derive_key(password, &salt).expect("Key derivation failed");

        let vault = Vault::new(vault_path.clone(), key);

        // 构建测试数据
        let data = VaultData {
            collections: vec![],
        };

        // 测试保存
        vault.save(&data).expect("Save failed");

        // 测试加载
        let loaded_data = vault.load().expect("Load failed");
        assert_eq!(loaded_data.collections.len(), 0);

        let _ = std::fs::remove_file(vault_path);
    }
}
