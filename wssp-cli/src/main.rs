use std::env;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use directories::ProjectDirs;
use wssp_common::ipc::PromptResponse;
use wssp_core::vault::Vault;

struct VaultPaths {
    vault: PathBuf,
    salt: PathBuf,
    key: PathBuf,
}

fn vault_paths() -> VaultPaths {
    let proj_dirs = ProjectDirs::from("org", "wssp", "wssp")
        .expect("Could not determine project directories");
    let d = proj_dirs.data_dir();
    VaultPaths {
        vault: d.join("vault.enc"),
        salt:  d.join("vault.salt"),
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
        let pw = read_password(prompt);
        let confirm = read_password(confirm_prompt);
        if pw == confirm {
            return pw;
        }
        eprintln!("Passwords do not match, try again.");
    }
}

fn cmd_unlock() {
    let runtime_dir = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_path = PathBuf::from(runtime_dir).join("wssp.sock");

    if !socket_path.exists() {
        eprintln!("Daemon is not currently requesting a password (socket not found).");
        std::process::exit(1);
    }

    let password = read_password("Vault password: ");

    match UnixStream::connect(&socket_path) {
        Ok(mut stream) => {
            let response = PromptResponse { password: Some(password) };
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
}

fn cmd_init(no_password: bool) {
    let VaultPaths { vault: vault_path, salt: salt_path, key: key_path } = vault_paths();

    if vault_path.exists() {
        eprintln!("Vault already exists. Use change-password or clear-password instead.");
        std::process::exit(1);
    }

    std::fs::create_dir_all(vault_path.parent().unwrap()).expect("Cannot create data directory");

    if no_password {
        let key = Vault::generate_key();
        let key_hex = Vault::key_to_hex(&key);
        std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(&key_path)
            .and_then(|mut f| { f.write_all(key_hex.as_bytes())?; Ok(()) })
            .expect("Cannot write vault.key");
        let vault = Vault::new(vault_path, key);
        vault.save(&wssp_core::vault::VaultData { collections: vec![] })
            .expect("Cannot write vault.enc");
        println!("Vault initialized in no-password mode (vault.key created).");
    } else {
        let pw = read_new_password("New vault password: ", "Confirm password: ");
        let salt = Vault::generate_salt();
        let key = Vault::derive_key(&pw, &salt).expect("Key derivation failed");
        std::fs::write(&salt_path, &salt).expect("Cannot write vault.salt");
        let vault = Vault::new(vault_path, key);
        vault.save(&wssp_core::vault::VaultData { collections: vec![] })
            .expect("Cannot write vault.enc");
        println!("Vault initialized with password.");
    }
    println!("Start wss-daemon to begin using the vault:");
    println!("  systemctl --user start wss-daemon.service");
}

fn cmd_change_password() {
    let VaultPaths { vault: vault_path, salt: salt_path, key: key_path } = vault_paths();

    if !vault_path.exists() {
        eprintln!("No vault found at {:?}. Initialize it by running wss-daemon first.", vault_path);
        std::process::exit(1);
    }

    if key_path.exists() {
        eprintln!("Vault is currently in keyfile (no-password) mode. Use set-password instead.");
        std::process::exit(1);
    }

    let old_password = read_password("Current password: ");

    let old_salt = match std::fs::read_to_string(&salt_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("Cannot read salt file: {}", e); std::process::exit(1); }
    };
    let old_key = match Vault::derive_key(&old_password, old_salt.trim()) {
        Ok(k) => k,
        Err(e) => { eprintln!("Key derivation failed: {}", e); std::process::exit(1); }
    };
    let old_vault = Vault::new(vault_path.clone(), old_key);
    let data = match old_vault.load() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to decrypt vault — wrong current password? ({})", e);
            std::process::exit(1);
        }
    };

    let new_password = read_new_password("New password: ", "Confirm new password: ");

    let new_salt = Vault::generate_salt();
    let new_key = match Vault::derive_key(&new_password, &new_salt) {
        Ok(k) => k,
        Err(e) => { eprintln!("Key derivation failed: {}", e); std::process::exit(1); }
    };
    if let Err(e) = std::fs::write(&salt_path, &new_salt) {
        eprintln!("Cannot write salt file: {}", e);
        std::process::exit(1);
    }
    let new_vault = Vault::new(vault_path, new_key);
    if let Err(e) = new_vault.save(&data) {
        eprintln!("Cannot write vault file: {}", e);
        std::process::exit(1);
    }

    println!("Vault password changed successfully.");
    println!("Restart wss-daemon for the change to take effect:");
    println!("  systemctl --user restart wss-daemon.service");
}

fn cmd_clear_password() {
    let VaultPaths { vault: vault_path, salt: salt_path, key: key_path } = vault_paths();

    if !vault_path.exists() {
        eprintln!("No vault found. Initialize it by running wss-daemon first.");
        std::process::exit(1);
    }
    if key_path.exists() {
        eprintln!("Vault is already in keyfile (no-password) mode.");
        std::process::exit(1);
    }

    let current_password = read_password("Current password: ");

    let old_salt = match std::fs::read_to_string(&salt_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("Cannot read salt file: {}", e); std::process::exit(1); }
    };
    let old_key = match Vault::derive_key(&current_password, old_salt.trim()) {
        Ok(k) => k,
        Err(e) => { eprintln!("Key derivation failed: {}", e); std::process::exit(1); }
    };
    let old_vault = Vault::new(vault_path.clone(), old_key);
    let data = match old_vault.load() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to decrypt vault — wrong password? ({})", e);
            std::process::exit(1);
        }
    };

    let new_key = Vault::generate_key();
    let key_hex = Vault::key_to_hex(&new_key);
    match std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true).mode(0o600)
        .open(&key_path)
    {
        Ok(mut f) => { f.write_all(key_hex.as_bytes()).expect("Cannot write keyfile"); }
        Err(e) => { eprintln!("Cannot create vault.key: {}", e); std::process::exit(1); }
    }
    let new_vault = Vault::new(vault_path, new_key);
    if let Err(e) = new_vault.save(&data) {
        eprintln!("Cannot re-encrypt vault: {}", e);
        let _ = std::fs::remove_file(&key_path);
        std::process::exit(1);
    }
    let _ = std::fs::remove_file(&salt_path);

    println!("Password cleared. Vault is now in keyfile mode — login unlocks automatically.");
    println!("Restart wss-daemon: systemctl --user restart wss-daemon.service");
}

fn cmd_set_password() {
    let VaultPaths { vault: vault_path, salt: salt_path, key: key_path } = vault_paths();

    if !vault_path.exists() {
        eprintln!("No vault found. Initialize it by running wss-daemon first.");
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

    let new_password = read_new_password("New password: ", "Confirm new password: ");

    let new_salt = Vault::generate_salt();
    let new_key = match Vault::derive_key(&new_password, &new_salt) {
        Ok(k) => k,
        Err(e) => { eprintln!("Key derivation failed: {}", e); std::process::exit(1); }
    };
    if let Err(e) = std::fs::write(&salt_path, &new_salt) {
        eprintln!("Cannot write salt file: {}", e); std::process::exit(1);
    }
    let new_vault = Vault::new(vault_path, new_key);
    if let Err(e) = new_vault.save(&data) {
        eprintln!("Cannot re-encrypt vault: {}", e);
        let _ = std::fs::remove_file(&salt_path);
        std::process::exit(1);
    }
    let _ = std::fs::remove_file(&key_path);

    println!("Password set. Vault is now in password mode.");
    println!("Restart wss-daemon: systemctl --user restart wss-daemon.service");
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

    let VaultPaths { vault: vault_path, salt: salt_path, key: key_path } = vault_paths();
    let mut deleted = false;
    if vault_path.exists() {
        std::fs::remove_file(&vault_path).expect("Failed to delete vault.enc");
        deleted = true;
    }
    if salt_path.exists() {
        std::fs::remove_file(&salt_path).expect("Failed to delete vault.salt");
        deleted = true;
    }
    if key_path.exists() {
        std::fs::remove_file(&key_path).expect("Failed to delete vault.key");
        deleted = true;
    }

    if deleted {
        println!("Vault reset. Restart wss-daemon to initialize a new vault:");
        println!("  systemctl --user restart wss-daemon.service");
    } else {
        println!("No vault files found — nothing to reset.");
    }
}

fn usage() {
    eprintln!("Usage:");
    eprintln!("  wss-cli init                 # first-time setup with password (prompted)");
    eprintln!("  wss-cli init --no-password   # first-time setup without password (requires FDE)");
    eprintln!("  wss-cli unlock");
    eprintln!("  wss-cli change-password");
    eprintln!("  wss-cli clear-password       # switch to no-password mode");
    eprintln!("  wss-cli set-password         # switch from no-password to password mode");
    eprintln!("  wss-cli reset [--force]");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
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
