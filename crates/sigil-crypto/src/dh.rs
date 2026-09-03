use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sigil_core::{SigilError, Result, SecretBytes};
use hkdf::Hkdf;
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroize;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

// RFC 2409 Oakley Group 2: 1024-bit MODP Group (Standard Secret Service DH group)
pub const DH_PRIME_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
FFFFFFFFFFFFFFFF";

pub const DH_GENERATOR: u32 = 2;

/// DH-IETF-1024-SHA256 session key negotiator.
pub struct DhSession {
    private_key: BigUint,
    pub public_key: Vec<u8>,
}

impl DhSession {
    pub fn generate() -> Result<Self> {
        let prime = BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16)
            .ok_or_else(|| SigilError::CryptoFailure("Invalid DH prime hex".into()))?;
        let generator = BigUint::from(DH_GENERATOR);

        let mut rng = OsRng;
        let private_key = rng.gen_biguint_range(&BigUint::from(2u32), &(&prime - 1u32));
        let public_key_bn = generator.modpow(&private_key, &prime);

        Ok(Self {
            private_key,
            public_key: public_key_bn.to_bytes_be(),
        })
    }

    /// Derives the 128-bit AES session key from the peer's public key bytes using HKDF-SHA256.
    pub fn derive_shared_key(&self, peer_public_bytes: &[u8]) -> Result<[u8; 16]> {
        let prime = BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16)
            .ok_or_else(|| SigilError::CryptoFailure("Invalid DH prime hex".into()))?;
        let peer_public = BigUint::from_bytes_be(peer_public_bytes);

        if peer_public <= BigUint::from(1u32) || peer_public >= prime.clone() - 1u32 {
            return Err(SigilError::CryptoFailure("Invalid peer DH public key".into()));
        }

        let shared_secret_bn = peer_public.modpow(&self.private_key, &prime);
        let shared_secret_bytes = shared_secret_bn.to_bytes_be();

        // Secret Service spec: HKDF-SHA256 with no salt and empty info, expand to 16 bytes for AES-128
        let hk = Hkdf::<Sha256>::new(None, &shared_secret_bytes);
        let mut aes_key = [0u8; 16];
        hk.expand(&[], &mut aes_key)
            .map_err(|e| SigilError::CryptoFailure(format!("HKDF expand failed: {e}")))?;

        Ok(aes_key)
    }
}

/// Encrypts `secret` for Secret Service transmission using AES-128-CBC with PKCS#7 padding.
/// Returns `(iv, ciphertext)`.
pub fn encrypt_secret_service_aes128(
    aes_key: &[u8; 16],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut iv = [0u8; 16];
    rand::RngCore::fill_bytes(&mut OsRng, &mut iv);

    let cipher = Aes128CbcEnc::new_from_slices(aes_key, &iv)
        .map_err(|e| SigilError::CryptoFailure(format!("AES-128-CBC init failed: {e}")))?;

    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| SigilError::CryptoFailure(format!("AES-128-CBC encryption failed: {e}")))?
        .to_vec();

    Ok((iv.to_vec(), ciphertext))
}

/// Decrypts Secret Service encrypted secret `(iv, ciphertext)` using AES-128-CBC.
pub fn decrypt_secret_service_aes128(
    aes_key: &[u8; 16],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes> {
    if iv.len() != 16 {
        return Err(SigilError::CryptoFailure("IV must be 16 bytes".into()));
    }

    let cipher = Aes128CbcDec::new_from_slices(aes_key, iv)
        .map_err(|e| SigilError::CryptoFailure(format!("AES-128-CBC init failed: {e}")))?;

    let mut buf = ciphertext.to_vec();
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| SigilError::CryptoFailure(format!("AES-128-CBC decryption failed: {e}")))?;

    let secret = SecretBytes::new(decrypted.to_vec());
    buf.zeroize();
    Ok(secret)
}
