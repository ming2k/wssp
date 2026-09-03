use crate::key::MasterKey;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use sigil_core::{SigilError, Result, SecretBytes};
use rand::rngs::OsRng;

pub const NONCE_LEN: usize = 24;

/// Encrypts `plaintext` using XChaCha20-Poly1305 under `key`.
/// Returns `[24-byte nonce || ciphertext + 16-byte Poly1305 tag]`.
pub fn encrypt_xchacha20poly1305(
    key: &MasterKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| SigilError::CryptoFailure(format!("Failed to initialize cipher: {e}")))?;

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| SigilError::CryptoFailure(format!("Encryption failed: {e}")))?;

    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts `blob` formatted as `[24-byte nonce || ciphertext + 16-byte Poly1305 tag]` under `key`.
pub fn decrypt_xchacha20poly1305(
    key: &MasterKey,
    blob: &[u8],
    aad: &[u8],
) -> Result<SecretBytes> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(SigilError::CorruptData(format!(
            "Encrypted blob is too short: {} bytes (minimum {})",
            blob.len(),
            NONCE_LEN + 16
        )));
    }

    let (nonce_slice, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_slice);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| SigilError::CryptoFailure(format!("Failed to initialize cipher: {e}")))?;

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let decrypted = cipher
        .decrypt(nonce, payload)
        .map_err(|_| SigilError::CryptoFailure("Decryption failed / MAC verification failed".into()))?;

    Ok(SecretBytes::new(decrypted))
}
