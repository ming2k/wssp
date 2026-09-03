use credential_core::{CredentialError, Result, SecretBytes};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MASTER_KEY_LEN: usize = 32;

/// A 256-bit cryptographic master key protected by zeroization on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    pub fn new(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; MASTER_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != MASTER_KEY_LEN {
            return Err(CredentialError::CryptoFailure(format!(
                "Invalid master key length: expected {}, got {}",
                MASTER_KEY_LEN,
                slice.len()
            )));
        }
        let mut bytes = [0u8; MASTER_KEY_LEN];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let trimmed = hex_str.trim();
        if trimmed.len() != MASTER_KEY_LEN * 2 {
            return Err(CredentialError::CryptoFailure(format!(
                "Invalid hex key length: expected {}, got {}",
                MASTER_KEY_LEN * 2,
                trimmed.len()
            )));
        }
        let mut bytes = [0u8; MASTER_KEY_LEN];
        for i in 0..MASTER_KEY_LEN {
            bytes[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|e| CredentialError::CryptoFailure(format!("Invalid hex string: {e}")))?;
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(MASTER_KEY_LEN * 2);
        for byte in &self.0 {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", byte);
        }
        s
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }

    pub fn to_secret_bytes(&self) -> SecretBytes {
        SecretBytes::from_slice(&self.0)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MasterKey([redacted])")
    }
}
