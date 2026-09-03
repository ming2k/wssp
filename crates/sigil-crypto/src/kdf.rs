use crate::key::MasterKey;
use argon2::{Algorithm, Argon2, Params, Version};
use sigil_core::{SigilError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const DEFAULT_SALT_LEN: usize = 32;
pub const KDF_FILE_VERSION: u32 = 1;
pub const KDF_NAME: &str = "argon2id";

/// Argon2id parameters persisted in `vault.kdf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub version: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65536, // 64 MB
            t_cost: 3,     // 3 iterations
            p_cost: 4,     // 4 threads
            version: 0x13, // Argon2 v1.3
        }
    }
}

impl KdfParams {
    pub fn to_argon2_params(&self) -> Result<Params> {
        Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| SigilError::CryptoFailure(format!("Invalid Argon2 params: {e}")))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfConfig {
    pub version: u32,
    pub kdf: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: String,
}

pub fn encode_kdf(params: &KdfParams, salt: &str) -> Result<Vec<u8>> {
    let config = KdfConfig {
        version: KDF_FILE_VERSION,
        kdf: KDF_NAME.to_string(),
        m_cost: params.m_cost,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        salt: salt.to_string(),
    };
    serde_json::to_vec(&config)
        .map_err(|e| SigilError::CryptoFailure(format!("KDF serialization failed: {e}")))
}

pub fn decode_kdf(bytes: &[u8]) -> Result<(KdfParams, String)> {
    let config: KdfConfig = serde_json::from_slice(bytes)
        .map_err(|e| SigilError::CryptoFailure(format!("KDF deserialization failed: {e}")))?;
    if config.version != KDF_FILE_VERSION {
        return Err(SigilError::CryptoFailure(format!(
            "Unsupported KDF version: {}",
            config.version
        )));
    }
    if config.kdf != KDF_NAME {
        return Err(SigilError::CryptoFailure(format!(
            "Unsupported KDF algorithm: {}",
            config.kdf
        )));
    }
    let params = KdfParams {
        m_cost: config.m_cost,
        t_cost: config.t_cost,
        p_cost: config.p_cost,
        version: 0x13,
    };
    Ok((params, config.salt))
}

pub fn generate_salt(len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives a 256-bit `MasterKey` from a password and salt using Argon2id.
pub fn derive_key_argon2id(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<MasterKey> {
    let argon_params = params.to_argon2_params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key_bytes)
        .map_err(|e| SigilError::CryptoFailure(format!("Argon2 derivation failed: {e}")))?;

    Ok(MasterKey::new(key_bytes))
}
