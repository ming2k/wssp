use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use argon2::Params;
use directories::ProjectDirs;
use wssp_common::ipc::PromptResponse;
use wssp_core::vault::{
    atomic_replace, decode_kdf, encode_kdf, Vault, VaultData,
};
use zeroize::Zeroize;

struct VaultPaths {
    vault: PathBuf,
    salt: PathBuf,
    kdf: PathBuf,
    key: PathBuf,
}

fn vault_paths() -> VaultPaths {
    let proj_dirs = ProjectDirs::from("org", "wssp", "wssp")
        .expect("Could not determine project directories");
    let d = proj_dirs.data_dir();
    VaultPaths {
        vault: d.join("vault.enc"),
        salt:  d.join("vault.salt"),
        kdf:   d.join("vault.kdf"),
        key:   d.join("vault.key"),
    }
}

fn read_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("Failed to read password: {}", e);
        std::process::exit(1);
    })
}

fn read_new_password(prompt: &str, confirm_prompt: &str) -> String {
    loop {
        let mut pw = read_password(prompt);
        let mut confirm = read_password(confirm_prompt);
        if pw == confirm {
            confirm.zeroize();
            return pw;
        }
        pw.zeroize();
        confirm.zeroize();
        eprintln!("Passwords do not match, try again.");
    }
}

fn load_password_vault(
    password: &str,
    vault_path: &PathBuf,
    salt_path: &PathBuf,
    kdf_path: &PathBuf,
) -> Result<(Vault, VaultData), Box<dyn std::error::Error>> {
    let key = if kdf_path.exists() {
        let kdf_bytes = std::fs::read(kdf_path)?;
        let (params, salt) = decode_kdf(&kdf_bytes)?;
        Vault::derive_key_with_params(password, &salt, &params)?
    } else if salt_path.exists() {
        let salt = std::fs::read_to_string(salt_path)?;
        Vault::derive_key(password, salt.trim())?
    } else {
        return Err("No vault.kdf or vault.salt found".into());
    };

    let vault = Vault::new(vault_path.clone(), key);
    let data = vault.load()?;
    Ok((vault, data))
}

fn cmd_unlock() {
    let runtime_dir = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_path = PathBuf::from(runtime_dir).join("wssp.sock");

    if !socket_path.exists() {
        eprintln!("Daemon is not currently requesting a password (socket not found).");
        std::process::exit(1);
    }

    let mut password = read_password("Vault password: ");

    match UnixStream::connect(&socket_path) {
        Ok(mut stream) => {
            let response = PromptResponse { password: Some(password.clone()) };
            if let Ok(serialized) = serde_json::to_vec(&response) {
                let _ = stream.write_all(&serialized);
                println!("Password sent to daemon successfully.");
            } else {
                eprintln!("Failed to serialize password.");
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon socket: {}", e);
        }
    }
    password.zeroize();
}

fn cmd_init(no_password: bool) {
    let VaultPaths { vault: vault_path, salt: salt_path, kdf: kdf_path, key: key_path } = vault_paths();

    if vault_path.exists() {
        eprintln!("Vault already exists. Use change-password or clear-password instead.");
        std::process::exit(1);
    }

    std::fs::create_dir_all(vault_path.parent().unwrap()).expect("Cannot create data directory");

    if no_password {
        let key = Vault::generate_key();
        let key_hex = Vault::key_to_hex(&key);
        atomic_replace(&key_path, key_hex.as_bytes()).expect("Cannot write vault.key");
        let vault = Vault::new(vault_path, key);
        vault.save_new(&VaultData { collections: vec![] })
            .expect("Cannot write vault.enc");
        println!("Vault initialized in no-password mode (vault.key created).");
    } else {
        let mut pw = read_new_password("New vault password: ", "Confirm password: ");
        let salt = Vault::generate_salt();
        let params = Params::default();
        let key = Vault::derive_key_with_params(&pw, &salt, &params).expect("Key derivation failed");
        pw.zeroize();

        let kdf_bytes = encode_kdf(&params, &salt).expect("Cannot encode KDF configuration");
        atomic_replace(&kdf_path, &kdf_bytes).expect("Cannot write vault.kdf");
        atomic_replace(&salt_path, salt.as_bytes()).expect("Cannot write vault.salt");

        let vault = Vault::new(vault_path, key);
        vault.save_new(&VaultData { collections: vec![] })
            .expect("Cannot write vault.enc");
        println!("Vault initialized with password (vault.kdf created).");
    }
    println!("Start wssp-daemon to begin using the vault:");
    println!("  systemctl --user start wssp-daemon.service");
}

fn cmd_change_password() {
    let VaultPaths { vault: vault_path, salt: salt_path, kdf: kdf_path, key: key_path } = vault_paths();

    if !vault_path.exists() {
        eprintln!("No vault found at {:?}. Initialize it by running wssp-daemon first.", vault_path);
        std::process::exit(1);
    }

    if key_path.exists() {
        eprintln!("Vault is currently in keyfile (no-password) mode. Use set-password instead.");
        std::process::exit(1);
    }

    let mut old_password = read_password("Current password: ");
    let (_old_vault, data) = match load_password_vault(&old_password, &vault_path, &salt_path, &kdf_path) {
        Ok(res) => res,
        Err(e) => {
            old_password.zeroize();
            eprintln!("Failed to decrypt vault — wrong current password? ({})", e);
            std::process::exit(1);
        }
    };
    old_password.zeroize();

    let mut new_password = read_new_password("New password: ", "Confirm new password: ");
    let new_salt = Vault::generate_salt();
    let new_params = Params::default();
    let new_key = match Vault::derive_key_with_params(&new_password, &new_salt, &new_params) {
        Ok(k) => k,
        Err(e) => {
            new_password.zeroize();
            eprintln!("Key derivation failed: {}", e);
            std::process::exit(1);
        }
    };
    new_password.zeroize();

    // Two-phase crash-safe staging
    let parent = vault_path.parent().unwrap();
    let kdf_next = parent.join("vault.kdf.next");
    let salt_next = parent.join("vault.salt.next");

    let kdf_bytes = encode_kdf(&new_params, &new_salt).expect("Cannot encode KDF configuration");
    if let Err(e) = atomic_replace(&kdf_next, &kdf_bytes) {
        eprintln!("Cannot stage vault.kdf.next: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = atomic_replace(&salt_next, new_salt.as_bytes()) {
        eprintln!("Cannot stage vault.salt.next: {}", e);
        let _ = std::fs::remove_file(&kdf_next);
        std::process::exit(1);
    }

    let new_vault = Vault::new(vault_path.clone(), new_key);
    if let Err(e) = new_vault.save(&data) {
        eprintln!("Cannot write vault file: {}", e);
        let _ = std::fs::remove_file(&kdf_next);
        let _ = std::fs::remove_file(&salt_next);
        std::process::exit(1);
    }

    // Commit re-key by renaming staged metadata over active
    let _ = std::fs::rename(&kdf_next, &kdf_path);
    let _ = std::fs::rename(&salt_next, &salt_path);
    let _ = File::open(parent).map(|f| f.sync_all());

    println!("Vault password changed successfully (two-phase committed).");
    println!("Restart wssp-daemon for the change to take effect:");
    println!("  systemctl --user restart wssp-daemon.service");
}

fn cmd_clear_password() {
    let VaultPaths { vault: vault_path, salt: salt_path, kdf: kdf_path, key: key_path } = vault_paths();

    if !vault_path.exists() {
        eprintln!("No vault found. Initialize it by running wssp-daemon first.");
        std::process::exit(1);
    }
    if key_path.exists() {
        eprintln!("Vault is already in keyfile (no-password) mode.");
        std::process::exit(1);
    }

    let mut current_password = read_password("Current password: ");
    let (_old_vault, data) = match load_password_vault(&current_password, &vault_path, &salt_path, &kdf_path) {
        Ok(res) => res,
        Err(e) => {
            current_password.zeroize();
            eprintln!("Failed to decrypt vault — wrong password? ({})", e);
            std::process::exit(1);
        }
    };
    current_password.zeroize();

    let new_key = Vault::generate_key();
    let key_hex = Vault::key_to_hex(&new_key);
    if let Err(e) = atomic_replace(&key_path, key_hex.as_bytes()) {
        eprintln!("Cannot create vault.key: {}", e);
        std::process::exit(1);
    }

    let new_vault = Vault::new(vault_path, new_key);
    if let Err(e) = new_vault.save(&data) {
        eprintln!("Cannot re-encrypt vault: {}", e);
        let _ = std::fs::remove_file(&key_path);
        std::process::exit(1);
    }
    let _ = std::fs::remove_file(&salt_path);
    let _ = std::fs::remove_file(&kdf_path);

    println!("Password cleared. Vault is now in keyfile mode — login unlocks automatically.");
    println!("Restart wssp-daemon: systemctl --user restart wssp-daemon.service");
}

fn cmd_set_password() {
    let VaultPaths { vault: vault_path, salt: salt_path, kdf: kdf_path, key: key_path } = vault_paths();

    if !vault_path.exists() {
        eprintln!("No vault found. Initialize it by running wssp-daemon first.");
        std::process::exit(1);
    }
    if !key_path.exists() {
        eprintln!("Vault is already in password mode. Use change-password instead.");
        std::process::exit(1);
    }

    let hex = match std::fs::read_to_string(&key_path) {
        Ok(h) => h,
        Err(e) => { eprintln!("Cannot read vault.key: {}", e); std::process::exit(1); }
    };
    let old_key = match Vault::key_from_hex(hex.trim()) {
        Ok(k) => k,
        Err(e) => { eprintln!("Invalid vault.key: {}", e); std::process::exit(1); }
    };
    let old_vault = Vault::new(vault_path.clone(), old_key);
    let data = match old_vault.load() {
        Ok(d) => d,
        Err(e) => { eprintln!("Cannot decrypt vault: {}", e); std::process::exit(1); }
    };

    let mut new_password = read_new_password("New password: ", "Confirm new password: ");
    let new_salt = Vault::generate_salt();
    let new_params = Params::default();
    let new_key = match Vault::derive_key_with_params(&new_password, &new_salt, &new_params) {
        Ok(k) => k,
        Err(e) => {
            new_password.zeroize();
            eprintln!("Key derivation failed: {}", e);
            std::process::exit(1);
        }
    };
    new_password.zeroize();

    let kdf_bytes = encode_kdf(&new_params, &new_salt).expect("Cannot encode KDF configuration");
    if let Err(e) = atomic_replace(&kdf_path, &kdf_bytes) {
        eprintln!("Cannot write kdf file: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = atomic_replace(&salt_path, new_salt.as_bytes()) {
        eprintln!("Cannot write salt file: {}", e);
        let _ = std::fs::remove_file(&kdf_path);
        std::process::exit(1);
    }
    let new_vault = Vault::new(vault_path, new_key);
    if let Err(e) = new_vault.save(&data) {
        eprintln!("Cannot re-encrypt vault: {}", e);
        let _ = std::fs::remove_file(&salt_path);
        let _ = std::fs::remove_file(&kdf_path);
        std::process::exit(1);
    }
    let _ = std::fs::remove_file(&key_path);

    println!("Password set. Vault is now in password mode.");
    println!("Restart wssp-daemon: systemctl --user restart wssp-daemon.service");
}

fn cmd_reset(force: bool) {
    if !force {
        print!("WARNING: this permanently deletes all stored secrets. Type 'yes' to confirm: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        if input.trim() != "yes" {
            println!("Reset cancelled.");
            return;
        }
    }

    let VaultPaths { vault: vault_path, salt: salt_path, kdf: kdf_path, key: key_path } = vault_paths();
    let parent = vault_path.parent().unwrap();
    let mut deleted = false;
    if vault_path.exists() {
        std::fs::remove_file(&vault_path).expect("Failed to delete vault.enc");
        deleted = true;
    }
    if salt_path.exists() {
        std::fs::remove_file(&salt_path).expect("Failed to delete vault.salt");
        deleted = true;
    }
    if kdf_path.exists() {
        std::fs::remove_file(&kdf_path).expect("Failed to delete vault.kdf");
        deleted = true;
    }
    if key_path.exists() {
        std::fs::remove_file(&key_path).expect("Failed to delete vault.key");
        deleted = true;
    }
    let _ = std::fs::remove_file(parent.join("vault.kdf.next"));
    let _ = std::fs::remove_file(parent.join("vault.salt.next"));

    if deleted {
        println!("Vault reset. Restart wssp-daemon to initialize a new vault:");
        println!("  systemctl --user restart wssp-daemon.service");
    } else {
        println!("No vault files found — nothing to reset.");
    }
}

fn usage() {
    eprintln!("Usage:");
    eprintln!("  wssp-cli init                 # first-time setup with password (prompted)");
    eprintln!("  wssp-cli init --no-password   # first-time setup without password (requires FDE)");
    eprintln!("  wssp-cli unlock");
    eprintln!("  wssp-cli change-password");
    eprintln!("  wssp-cli clear-password       # switch to no-password mode");
    eprintln!("  wssp-cli set-password         # switch from no-password to password mode");
    eprintln!("  wssp-cli reset [--force]");
    eprintln!("  wssp-cli --version | -V       # print version and exit");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "--version" | "-V" => {
            println!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
        }
        "init" => {
            let no_password = args.get(2).map(|s| s == "--no-password").unwrap_or(false);
            cmd_init(no_password);
        }
        "unlock" => {
            cmd_unlock();
        }
        "change-password" => {
            cmd_change_password();
        }
        "clear-password" => {
            cmd_clear_password();
        }
        "set-password" => {
            cmd_set_password();
        }
        "reset" => {
            let force = args.get(2).map(|s| s == "--force").unwrap_or(false);
            cmd_reset(force);
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            usage();
            std::process::exit(1);
        }
    }
}
