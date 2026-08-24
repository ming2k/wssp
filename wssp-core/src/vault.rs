use crate::error::{CoreError, Result};
use argon2::{
    password_hash::SaltString,
    Algorithm, Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
pub const KDF_FILE_VERSION: u32 = 1;
pub const KDF_NAME: &str = "argon2id";

/// The persisted `vault.kdf` configuration: exact Argon2id parameters and salt
/// recorded on disk so derivation remains reproducible across library updates.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KdfConfig {
    pub version: u32,
    pub kdf: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: String,
}

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
    master_key: Box<[u8; 32]>,
    mlocked: bool,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.master_key.zeroize();
        if self.mlocked {
            unsafe {
                libc::munlock(
                    self.master_key.as_ptr().cast::<libc::c_void>(),
                    self.master_key.len(),
                );
            }
        }
    }
}

pub fn encode_kdf(params: &Params, salt: &str) -> Result<Vec<u8>> {
    let kdf = KdfConfig {
        version: KDF_FILE_VERSION,
        kdf: KDF_NAME.to_owned(),
        m_cost: params.m_cost(),
        t_cost: params.t_cost(),
        p_cost: params.p_cost(),
        salt: salt.to_owned(),
    };
    serde_json::to_vec(&kdf).map_err(CoreError::Serialization)
}

pub fn decode_kdf(bytes: &[u8]) -> Result<(Params, String)> {
    let kdf: KdfConfig = serde_json::from_slice(bytes).map_err(CoreError::Serialization)?;
    if kdf.version != KDF_FILE_VERSION {
        return Err(CoreError::Vault(format!(
            "Unsupported vault.kdf version: {}",
            kdf.version
        )));
    }
    if kdf.kdf != KDF_NAME {
        return Err(CoreError::Vault(format!(
            "Unsupported vault.kdf algorithm: {}",
            kdf.kdf
        )));
    }
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, None)
        .map_err(|e| CoreError::Crypto(format!("Invalid vault.kdf parameters: {e}")))?;
    SaltString::from_b64(&kdf.salt)
        .map_err(|e| CoreError::Crypto(format!("Invalid vault.kdf salt: {e}")))?;
    Ok((params, kdf.salt))
}

impl Vault {
    pub fn new(path: PathBuf, master_key: [u8; 32]) -> Self {
        let mut vault = Self {
            path,
            master_key: Box::new(master_key),
            mlocked: false,
        };
        let result = unsafe {
            libc::mlock(
                vault.master_key.as_ptr().cast::<libc::c_void>(),
                vault.master_key.len(),
            )
        };
        if result == 0 {
            vault.mlocked = true;
        } else {
            tracing::warn!(
                "Could not mlock vault master key: {}",
                std::io::Error::last_os_error()
            );
        }
        mark_dontdump(
            "vault master key",
            vault.master_key.as_ptr(),
            vault.master_key.len(),
        );
        vault
    }

    pub fn get_master_key(&self) -> &[u8; 32] {
        &self.master_key
    }

    pub fn derive_key(password: &str, salt_str: &str) -> Result<[u8; 32]> {
        Self::derive_key_with_params(password, salt_str, &Params::default())
    }

    pub fn derive_key_with_params(
        password: &str,
        salt_str: &str,
        params: &Params,
    ) -> Result<[u8; 32]> {
        let salt = SaltString::from_b64(salt_str)
            .map_err(|e| CoreError::Crypto(format!("Invalid salt: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());

        let mut key = [0u8; 32];
        if let Err(e) =
            argon2.hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
        {
            key.zeroize();
            return Err(CoreError::Crypto(format!("Hash failed: {}", e)));
        }

        Ok(key)
    }

    pub fn generate_salt() -> String {
        SaltString::generate(&mut OsRng).as_str().to_string()
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn key_to_hex(key: &[u8; 32]) -> String {
        key.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn key_from_hex(hex: &str) -> Result<[u8; 32]> {
        let hex = hex.trim();
        if hex.len() != 64 {
            return Err(CoreError::Crypto("vault.key must be 64 hex chars (32 bytes)".into()));
        }
        let mut arr = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = match std::str::from_utf8(chunk) {
                Ok(v) => v,
                Err(_) => {
                    arr.zeroize();
                    return Err(CoreError::Crypto("Invalid hex in vault.key".into()));
                }
            };
            arr[i] = match u8::from_str_radix(s, 16) {
                Ok(v) => v,
                Err(_) => {
                    arr.zeroize();
                    return Err(CoreError::Crypto(format!("Invalid hex byte: {}", s)));
                }
            };
        }
        Ok(arr)
    }

    pub fn save(&self, data: &VaultData) -> Result<()> {
        let sealed = self.seal(data)?;
        atomic_replace(&self.path, &sealed).map_err(CoreError::Io)
    }

    pub fn save_new(&self, data: &VaultData) -> Result<()> {
        let sealed = self.seal(data)?;
        atomic_create(&self.path, &sealed).map_err(CoreError::Io)
    }

    fn seal(&self, data: &VaultData) -> Result<Vec<u8>> {
        let serialized = Zeroizing::new(serde_json::to_vec(data)?);
        let cipher = XChaCha20Poly1305::new((&*self.master_key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, serialized.as_ref())
            .map_err(|e| CoreError::Crypto(format!("Encryption failure: {}", e)))?;

        let mut final_data = nonce.to_vec();
        final_data.extend_from_slice(&ciphertext);
        Ok(final_data)
    }

    pub fn load(&self) -> Result<VaultData> {
        let Some(file_data) = read_vault_file(&self.path, true)? else {
            return Ok(VaultData {
                collections: vec![],
            });
        };

        if file_data.len() < 24 {
            return Err(CoreError::Vault("Vault file corrupted".to_string()));
        }

        let (nonce_bytes, ciphertext) = file_data.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        let cipher = XChaCha20Poly1305::new((&*self.master_key).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| CoreError::Crypto(format!("Decryption failure: {}", e)))?,
        );

        let data: VaultData = serde_json::from_slice(plaintext.as_ref())?;
        Ok(data)
    }

    pub fn validate_ciphertext(path: &Path) -> Result<()> {
        let Some(file_data) = read_vault_file(path, false)? else {
            return Err(CoreError::Vault("Vault file is missing".to_owned()));
        };
        if file_data.len() < 24 {
            return Err(CoreError::Vault("Vault file corrupted".to_string()));
        }
        Ok(())
    }
}

fn mark_dontdump(what: &str, ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let page = page_size();
    let start = ptr as usize & !(page - 1);
    let end = (ptr as usize + len + page - 1) & !(page - 1);
    if unsafe { libc::madvise(start as *mut libc::c_void, end - start, libc::MADV_DONTDUMP) } != 0 {
        tracing::warn!(
            "Could not mark {what} MADV_DONTDUMP: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as usize
    } else {
        4096
    }
}

pub fn read_vault_file(path: &Path, missing_is_empty: bool) -> Result<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if missing_is_empty && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(CoreError::Io(error)),
    };
    let metadata = file.metadata()?;
    let uid = unsafe { libc::getuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > MAX_VAULT_BYTES
    {
        return Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "vault file must be a user-owned regular file, mode 0600, at most 64 MiB",
        )));
    }
    let mut file_data = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut file_data)?;
    Ok(Some(file_data))
}

pub fn atomic_replace(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vault path must have a parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "vault path must name a file")
    })?;

    let temporary_path = temporary_path(parent, file_name);

    let result = (|| {
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary_path)?;
        temporary.write_all(contents)?;
        temporary.sync_all()?;
        fs::rename(&temporary_path, path)?;

        // Persist the directory entry replacement
        File::open(parent)?.sync_all()
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

pub fn atomic_create(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vault path must have a parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "vault path must name a file")
    })?;
    let temporary_path = temporary_path(parent, file_name);
    let result = (|| {
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary_path)?;
        temporary.write_all(contents)?;
        temporary.sync_all()?;
        fs::hard_link(&temporary_path, path)?;
        fs::remove_file(&temporary_path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn temporary_path(parent: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".{suffix}.tmp"));
    parent.join(temporary_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_crypto_lifecycle() {
        let temp_dir = std::env::temp_dir();
        let unique_id = Vault::generate_salt().replace('/', "_").replace('+', "-");
        let vault_path = temp_dir.join(format!("test_vault_{}.enc", unique_id));

        let password = "super-secret-password";
        let salt = Vault::generate_salt();
        let key = Vault::derive_key(password, &salt).expect("Key derivation failed");

        let vault = Vault::new(vault_path.clone(), key);

        let data = VaultData {
            collections: vec![],
        };

        // Test save
        vault.save(&data).expect("Save failed");

        // Test load
        let loaded_data = vault.load().expect("Load failed");
        assert_eq!(loaded_data.collections.len(), 0);

        let _ = std::fs::remove_file(vault_path);
    }

    #[test]
    fn test_kdf_serialization_roundtrip() {
        let params = Params::default();
        let salt = Vault::generate_salt();
        let encoded = encode_kdf(&params, &salt).expect("Encoding KDF failed");

        let (decoded_params, decoded_salt) = decode_kdf(&encoded).expect("Decoding KDF failed");
        assert_eq!(params.m_cost(), decoded_params.m_cost());
        assert_eq!(params.t_cost(), decoded_params.t_cost());
        assert_eq!(params.p_cost(), decoded_params.p_cost());
        assert_eq!(salt, decoded_salt);
    }

    #[test]
    fn test_tampered_ciphertext_detection() {
        let temp_dir = std::env::temp_dir();
        let unique_id = Vault::generate_salt().replace('/', "_").replace('+', "-");
        let vault_path = temp_dir.join(format!("test_tamper_{}.enc", unique_id));

        let key = Vault::generate_key();
        let vault = Vault::new(vault_path.clone(), key);

        let data = VaultData { collections: vec![] };
        vault.save(&data).expect("Save failed");

        // Tamper with a byte in the ciphertext
        let mut raw = std::fs::read(&vault_path).unwrap();
        let last_idx = raw.len() - 1;
        raw[last_idx] ^= 0xFF;
        std::fs::write(&vault_path, raw).unwrap();

        // Load must fail due to Poly1305 MAC tag failure
        assert!(vault.load().is_err());

        let _ = std::fs::remove_file(vault_path);
    }

    #[test]
    fn test_atomic_replace_creates_mode_0600() {
        let temp_dir = std::env::temp_dir();
        let unique_id = Vault::generate_salt().replace('/', "_").replace('+', "-");
        let file_path = temp_dir.join(format!("test_atomic_{}.dat", unique_id));

        atomic_replace(&file_path, b"test content").expect("atomic_replace failed");

        let meta = std::fs::metadata(&file_path).expect("Failed to get metadata");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);

        let _ = std::fs::remove_file(file_path);
    }
}

