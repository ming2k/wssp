use sigil_crypto::{
    decode_kdf, derive_key_argon2id, encode_kdf, generate_salt, KdfParams, MasterKey,
    DEFAULT_SALT_LEN,
};
use sigil_store::{atomic_replace, FileVaultStore, StoredVaultData};
use directories::ProjectDirs;
use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

struct VaultPaths {
    vault: PathBuf,
    salt: PathBuf,
    kdf: PathBuf,
    key: PathBuf,
}

fn get_data_dir() -> PathBuf {
    if let Ok(dir) = env::var("SIGIL_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(proj_dirs) = ProjectDirs::from("org", "freedesktop", "sigil") {
        proj_dirs.data_dir().to_path_buf()
    } else {
        PathBuf::from(".local/share/sigil")
    }
}

fn vault_paths() -> VaultPaths {
    let dir = get_data_dir();
    VaultPaths {
        vault: dir.join("vault.enc"),
        salt: dir.join("vault.salt"),
        kdf: dir.join("vault.kdf"),
        key: dir.join("vault.key"),
    }
}

fn load_password_vault(
    password: &str,
    vault_path: &Path,
    salt_path: &Path,
    kdf_path: &Path,
) -> Result<(MasterKey, StoredVaultData), Box<dyn std::error::Error>> {
    let parent = vault_path.parent().ok_or("Invalid vault path parent")?;
    let store = FileVaultStore::new(parent.to_path_buf());

    let (params, salt_hex) = if kdf_path.exists() {
        let kdf_bytes = std::fs::read(kdf_path)?;
        decode_kdf(&kdf_bytes)?
    } else if salt_path.exists() {
        let salt_str = std::fs::read_to_string(salt_path)?;
        (KdfParams::default(), salt_str.trim().to_string())
    } else {
        return Err("No salt or KDF config found for vault".into());
    };

    let mut salt = Vec::new();
    for i in (0..salt_hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&salt_hex[i..i + 2], 16)?;
        salt.push(byte);
    }

    let key = derive_key_argon2id(password.as_bytes(), &salt, &params)?;
    let data = store.load(&key)?;
    Ok((key, data))
}

fn read_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("Failed to read password: {}", e);
        std::process::exit(1);
    })
}

fn read_new_password(prompt: &str, confirm_prompt: &str) -> String {
    loop {
        let p1 = read_password(prompt);
        if p1.is_empty() {
            eprintln!("Password cannot be empty.");
            continue;
        }
        let p2 = read_password(confirm_prompt);
        if p1 != p2 {
            eprintln!("Passwords do not match. Try again.");
            continue;
        }
        return p1;
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn init(no_password: bool) {
    let paths = vault_paths();
    let parent = match paths.vault.parent() {
        Some(p) => p,
        None => {
            eprintln!("Invalid vault directory");
            std::process::exit(1);
        }
    };
    let store = FileVaultStore::new(parent.to_path_buf());

    if store.exists() || paths.key.exists() {
        eprintln!("Vault already exists at {}", paths.vault.display());
        eprintln!("Use 'sigil-cli reset' first if you want to start over.");
        std::process::exit(1);
    }

    if no_password {
        let key = MasterKey::generate();
        let key_hex = key.to_hex();
        atomic_replace(&paths.key, key_hex.as_bytes()).expect("Cannot write vault.key");
        store
            .save(&key, &StoredVaultData::default())
            .expect("Cannot write vault.enc");
        println!("Vault initialized in no-password mode (vault.key created).");
    } else {
        let mut pw = read_new_password("New vault password: ", "Confirm password: ");
        let salt_bytes = generate_salt(DEFAULT_SALT_LEN);
        let salt_hex = hex_encode(&salt_bytes);
        let params = KdfParams::default();

        let key = derive_key_argon2id(pw.as_bytes(), &salt_bytes, &params)
            .expect("Argon2 derivation failed");
        pw.zeroize();

        let kdf_bytes = encode_kdf(&params, &salt_hex).expect("Encoding KDF failed");
        atomic_replace(&paths.kdf, &kdf_bytes).expect("Cannot write vault.kdf");
        atomic_replace(&paths.salt, salt_hex.as_bytes()).expect("Cannot write vault.salt");

        store
            .save(&key, &StoredVaultData::default())
            .expect("Cannot write vault.enc");
        println!("Vault initialized at {}", paths.vault.display());
    }
}

fn change_password() {
    let paths = vault_paths();
    let parent = match paths.vault.parent() {
        Some(p) => p,
        None => {
            eprintln!("Invalid vault directory");
            std::process::exit(1);
        }
    };
    let store = FileVaultStore::new(parent.to_path_buf());

    if !store.exists() {
        eprintln!("No vault found. Run 'sigil-cli init' first.");
        std::process::exit(1);
    }

    if paths.key.exists() {
        eprintln!("Vault is in no-password mode (keyfile).");
        eprintln!("To set a password, remove {} and re-init.", paths.key.display());
        std::process::exit(1);
    }

    let mut current_password = read_password("Current password: ");
    let (_old_key, data) =
        match load_password_vault(&current_password, &paths.vault, &paths.salt, &paths.kdf) {
            Ok(res) => res,
            Err(e) => {
                current_password.zeroize();
                eprintln!("Failed to decrypt vault — wrong password? ({})", e);
                std::process::exit(1);
            }
        };
    current_password.zeroize();

    let mut new_password = read_new_password("New password: ", "Confirm new password: ");
    let new_salt_bytes = generate_salt(DEFAULT_SALT_LEN);
    let new_salt_hex = hex_encode(&new_salt_bytes);
    let params = KdfParams::default();

    let new_key = derive_key_argon2id(new_password.as_bytes(), &new_salt_bytes, &params)
        .expect("Argon2 derivation failed");
    new_password.zeroize();

    let kdf_bytes = encode_kdf(&params, &new_salt_hex).expect("Encoding KDF failed");
    atomic_replace(&paths.kdf, &kdf_bytes).expect("Cannot write vault.kdf");
    atomic_replace(&paths.salt, new_salt_hex.as_bytes()).expect("Cannot write vault.salt");

    store
        .save(&new_key, &data)
        .expect("Failed to re-encrypt and save vault");

    println!("Vault password changed successfully.");
}

fn reset() {
    let paths = vault_paths();
    println!("WARNING: This will delete the existing vault and all stored credentials!");
    print!("Type 'yes' to confirm: ");
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();
    if confirm.trim() != "yes" {
        println!("Aborted.");
        return;
    }

    let mut deleted = false;
    for path in [&paths.vault, &paths.salt, &paths.kdf, &paths.key] {
        if path.exists() {
            std::fs::remove_file(path).unwrap_or_else(|e| eprintln!("Cannot remove {}: {}", path.display(), e));
            println!("Removed {}", path.display());
            deleted = true;
        }
    }
    if deleted {
        println!("Vault reset. Run 'sigil-cli init' to create a new one.");
    } else {
        println!("No vault files found — nothing to reset.");
    }
}

fn usage() {
    eprintln!("Usage:");
    eprintln!("  sigil-cli init                 # first-time setup with password (prompted)");
    eprintln!("  sigil-cli init --no-password   # first-time setup without password (requires FDE)");
    eprintln!("  sigil-cli change-password      # change password on existing vault");
    eprintln!("  sigil-cli reset                # delete vault and start over");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "init" => {
            let no_password = args.get(2).map(|s| s.as_str()) == Some("--no-password");
            init(no_password);
        }
        "change-password" => change_password(),
        "reset" => reset(),
        _ => {
            usage();
            std::process::exit(1);
        }
    }
}
