use crate::model::StoredVaultData;
use credential_core::{CredentialError, Result};
use credential_crypto::{decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, MasterKey};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tracing::warn;
use zeroize::Zeroize;

pub const VAULT_ENC_FILENAME: &str = "vault.enc";
pub const VAULT_KEY_FILENAME: &str = "vault.key";
pub const VAULT_KDF_FILENAME: &str = "vault.kdf";
pub const VAULT_SALT_FILENAME: &str = "vault.salt";

/// Verifies directory permissions and ensures path is not an unauthorized symlink.
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    } else {
        let meta = fs::symlink_metadata(dir)?;
        if meta.file_type().is_symlink() {
            return Err(CredentialError::AccessDenied(format!(
                "Vault directory cannot be a symlink: {}",
                dir.display()
            )));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            warn!(
                "Vault directory {} permissions {:#o} too open, tightening to 0700",
                dir.display(),
                mode
            );
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Atomically replaces a file by writing to a secure tempfile and renaming it.
pub fn atomic_replace(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        CredentialError::StorageFailure("Cannot get parent directory of path".into())
    })?;
    ensure_secure_dir(parent)?;

    let mut temp_path = path.to_path_buf();
    temp_path.set_extension(format!("tmp.{}", std::process::id()));

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    fs::rename(&temp_path, path)?;
    Ok(())
}

/// A filesystem-backed encrypted vault storage.
#[derive(Clone, Debug)]
pub struct FileVaultStore {
    pub dir: PathBuf,
}

impl FileVaultStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn enc_path(&self) -> PathBuf {
        self.dir.join(VAULT_ENC_FILENAME)
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join(VAULT_KEY_FILENAME)
    }

    pub fn kdf_path(&self) -> PathBuf {
        self.dir.join(VAULT_KDF_FILENAME)
    }

    pub fn salt_path(&self) -> PathBuf {
        self.dir.join(VAULT_SALT_FILENAME)
    }

    pub fn exists(&self) -> bool {
        self.enc_path().exists()
    }

    pub fn is_keyfile_mode(&self) -> bool {
        self.key_path().exists()
    }

    pub fn read_keyfile(&self) -> Result<MasterKey> {
        let path = self.key_path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(CredentialError::AccessDenied(
                "vault.key cannot be a symlink".into(),
            ));
        }
        let hex = fs::read_to_string(&path)?;
        MasterKey::from_hex(hex.trim())
    }

    pub fn write_keyfile(&self, key: &MasterKey) -> Result<()> {
        let hex = key.to_hex();
        atomic_replace(&self.key_path(), hex.as_bytes())
    }

    /// Loads and decrypts the vault data using `key`.
    pub fn load(&self, key: &MasterKey) -> Result<StoredVaultData> {
        let path = self.enc_path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(CredentialError::AccessDenied(
                "vault.enc cannot be a symlink".into(),
            ));
        }

        let mut file = File::open(&path)?;
        let mut encrypted_bytes = Vec::new();
        file.read_to_end(&mut encrypted_bytes)?;

        let mut decrypted_secret = decrypt_xchacha20poly1305(key, &encrypted_bytes, b"")?;
        let data: StoredVaultData = serde_json::from_slice(decrypted_secret.as_slice())
            .map_err(|e| CredentialError::CorruptData(format!("JSON deserialization failed: {e}")))?;

        decrypted_secret.zeroize();
        Ok(data)
    }

    /// Encrypts and atomically saves the vault data using `key`.
    pub fn save(&self, key: &MasterKey, data: &StoredVaultData) -> Result<()> {
        ensure_secure_dir(&self.dir)?;

        let mut json_bytes = serde_json::to_vec(data)
            .map_err(|e| CredentialError::StorageFailure(format!("JSON serialization failed: {e}")))?;

        let encrypted = encrypt_xchacha20poly1305(key, &json_bytes, b"")?;
        json_bytes.zeroize();

        atomic_replace(&self.enc_path(), &encrypted)
    }
}
