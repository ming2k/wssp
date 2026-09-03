use sigil_core::Result;
use sigil_crypto::{
    decrypt_secret_service_aes128, encrypt_secret_service_aes128,
};
use tracing::info;
use zbus::interface;
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroize;

#[derive(Clone)]
pub enum SessionAlgorithm {
    Plain,
    Dh([u8; 16]),
}

impl Drop for SessionAlgorithm {
    fn drop(&mut self) {
        if let SessionAlgorithm::Dh(mut key) = self {
            key.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct Session {
    pub id: OwnedObjectPath,
    pub algorithm: SessionAlgorithm,
}

impl Session {
    pub fn new_plain(id: OwnedObjectPath) -> Self {
        Self {
            id,
            algorithm: SessionAlgorithm::Plain,
        }
    }

    pub fn new_dh(id: OwnedObjectPath, aes_key: [u8; 16]) -> Self {
        Self {
            id,
            algorithm: SessionAlgorithm::Dh(aes_key),
        }
    }

    pub fn encrypt(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match &self.algorithm {
            SessionAlgorithm::Plain => Ok((Vec::new(), secret.to_vec())),
            SessionAlgorithm::Dh(key) => encrypt_secret_service_aes128(key, secret),
        }
    }

    pub fn decrypt(&self, iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match &self.algorithm {
            SessionAlgorithm::Plain => Ok(ciphertext.to_vec()),
            SessionAlgorithm::Dh(key) => {
                let decrypted = decrypt_secret_service_aes128(key, iv, ciphertext)?;
                Ok(decrypted.as_slice().to_vec())
            }
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(&self) -> zbus::fdo::Result<()> {
        info!("Secret Service Session closed: {:?}", self.id);
        Ok(())
    }
}
