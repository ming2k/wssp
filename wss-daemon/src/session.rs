use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use hkdf::Hkdf;
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use tracing::{error, info};
use zbus::interface;
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroize;

pub enum SessionAlgorithm {
    Plain,
    Dh(Vec<u8>),
}

impl Drop for SessionAlgorithm {
    fn drop(&mut self) {
        if let SessionAlgorithm::Dh(key) = self {
            key.zeroize();
        }
    }
}

pub struct Session {
    pub id: OwnedObjectPath,
    pub algorithm: SessionAlgorithm,
}

impl Session {
    pub fn encrypt(
        &self,
        secret: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        match &self.algorithm {
            SessionAlgorithm::Plain => Ok((vec![], secret.to_vec())),
            SessionAlgorithm::Dh(key) => {
                let mut iv = [0u8; 16];
                OsRng.fill_bytes(&mut iv);
                let encryptor = Encryptor::<Aes128>::new(key.as_slice().into(), &iv.into());
                let mut buf = vec![0u8; secret.len() + 16];
                buf[..secret.len()].copy_from_slice(secret);
                let ct_len = encryptor
                    .encrypt_padded_mut::<Pkcs7>(&mut buf, secret.len())
                    .map_err(|e| format!("AES encryption failed: {e}"))?
                    .len();
                buf.truncate(ct_len);
                Ok((iv.to_vec(), buf))
            }
        }
    }

    pub fn decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        match &self.algorithm {
            SessionAlgorithm::Plain => Ok(ciphertext.to_vec()),
            SessionAlgorithm::Dh(key) => {
                if iv.len() != 16 {
                    return Err(format!("Invalid IV length: {}", iv.len()).into());
                }
                let mut iv_arr = [0u8; 16];
                iv_arr.copy_from_slice(iv);

                let decryptor = Decryptor::<Aes128>::new(key.as_slice().into(), &iv_arr.into());
                let mut buf = ciphertext.to_vec();

                match decryptor.decrypt_padded_mut::<Pkcs7>(&mut buf) {
                    Ok(pt) => {
                        let result = pt.to_vec();
                        buf.zeroize();
                        Ok(result)
                    }
                    Err(e) => {
                        buf.zeroize();
                        error!("AES decryption/unpad failed: {e}");
                        Err(format!("Decryption failed: {e}").into())
                    }
                }
            }
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(&self) -> zbus::fdo::Result<()> {
        info!("Session closed: {:?}", self.id);
        Ok(())
    }
}

// RFC 2409 IETF 1024-bit MODP Group 2
const DH_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
const DH_G: u32 = 2;

/// Perform server-side DH key exchange and return (server_public_key_128_bytes, aes128_session_key).
///
/// Returns `Err` if the client's public key fails RFC 2409 range validation (must be in (1, p-1)).
pub fn calculate_dh_shared_secret(
    client_pub: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let p = BigUint::parse_bytes(DH_P.as_bytes(), 16)
        .ok_or("Failed to parse DH prime")?;
    let g = BigUint::from(DH_G);

    let mut rng = rand::thread_rng();
    let priv_key = rng.gen_biguint_range(&BigUint::from(2u32), &(&p - BigUint::from(2u32)));

    let pub_key = g.modpow(&priv_key, &p);

    // RFC 2409: client public key must be in (1, p-1)
    let client_pub_bn = BigUint::from_bytes_be(client_pub);
    let one = BigUint::from(1u32);
    if client_pub_bn <= one || client_pub_bn >= &p - &one {
        return Err("Client DH public key out of valid range".into());
    }

    let shared_secret = client_pub_bn.modpow(&priv_key, &p);

    // Pad shared secret to 128 bytes (spec: hash the full prime-sized value)
    let mut shared_bytes = shared_secret.to_bytes_be();
    if shared_bytes.len() < 128 {
        let mut padded = vec![0u8; 128 - shared_bytes.len()];
        padded.extend_from_slice(&shared_bytes);
        shared_bytes = padded;
    }

    // HKDF-SHA256, null salt (32 zero bytes per RFC 5869 §2.2), empty info — matches libsecret
    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    shared_bytes.zeroize();
    let mut sym_key = vec![0u8; 16];
    hk.expand(&[], &mut sym_key)
        .expect("HKDF 16-byte output is always valid");
    info!("DH session key derived.");

    // Pad server public key to 128 bytes
    let mut pub_bytes = pub_key.to_bytes_be();
    if pub_bytes.len() < 128 {
        let mut padded = vec![0u8; 128 - pub_bytes.len()];
        padded.extend_from_slice(&pub_bytes);
        pub_bytes = padded;
    }

    Ok((pub_bytes, sym_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn python_hkdf(shared_secret_128: &[u8]) -> [u8; 16] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        // Matches secretstorage/libsecret exactly:
        // PRK = HMAC-SHA256(key=b'\x00'*32, data=shared_secret)
        let mut mac = HmacSha256::new_from_slice(&[0u8; 32]).unwrap();
        mac.update(shared_secret_128);
        let prk = mac.finalize().into_bytes();

        // T(1) = HMAC-SHA256(key=PRK, data=b'\x01')
        let mut mac2 = HmacSha256::new_from_slice(&prk).unwrap();
        mac2.update(&[0x01]);
        let t1 = mac2.finalize().into_bytes();

        let mut key = [0u8; 16];
        key.copy_from_slice(&t1[..16]);
        key
    }

    #[test]
    fn hkdf_matches_libsecret_reference() {
        let shared = [0u8; 128]; // trivial test vector

        // Our HKDF (via hkdf crate)
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut ours = [0u8; 16];
        hk.expand(&[], &mut ours).unwrap();

        // Python/libsecret manual HKDF
        let reference = python_hkdf(&shared);

        assert_eq!(ours, reference, "HKDF output must match libsecret reference");
    }

    #[test]
    fn full_dh_roundtrip() {
        // Simulate the client side (libsecret)
        let p = BigUint::parse_bytes(DH_P.as_bytes(), 16).unwrap();
        let g = BigUint::from(2u32);

        let client_priv = BigUint::from(12345678901234u64);
        let client_pub = g.modpow(&client_priv, &p);
        let mut client_pub_bytes = client_pub.to_bytes_be();
        if client_pub_bytes.len() < 128 {
            let mut padded = vec![0u8; 128 - client_pub_bytes.len()];
            padded.extend_from_slice(&client_pub_bytes);
            client_pub_bytes = padded;
        }

        // Server processes client's public key
        let (server_pub_bytes, server_key) =
            calculate_dh_shared_secret(&client_pub_bytes).unwrap();

        // Client computes key from server's public key
        let server_pub_bn = BigUint::from_bytes_be(&server_pub_bytes);
        let shared = server_pub_bn.modpow(&client_priv, &p);
        let mut shared_bytes = shared.to_bytes_be();
        if shared_bytes.len() < 128 {
            let mut padded = vec![0u8; 128 - shared_bytes.len()];
            padded.extend_from_slice(&shared_bytes);
            shared_bytes = padded;
        }
        let client_key = python_hkdf(&shared_bytes);

        assert_eq!(server_key.as_slice(), &client_key, "DH keys must match on both sides");
    }
}
