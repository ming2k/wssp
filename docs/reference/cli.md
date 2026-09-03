# CLI Reference (`credentiald-cli`)

`credentiald-cli` is the administrative command-line utility for managing the `credentiald` vault directly on disk.

## Usage

```bash
credentiald-cli <COMMAND> [OPTIONS]
```

## Commands

### `init`

Initializes a new vault if none exists.

```bash
# Password-protected vault (prompts securely for password)
credentiald-cli init

# Keyfile-backed vault (generates random 256-bit key in vault.key)
credentiald-cli init --no-password
```

### `change-password`

Prompts for the current password, verifies decryption, prompts for a new password, and atomically re-encrypts the vault with fresh salt and Argon2id parameters.

```bash
credentiald-cli change-password
```

### `reset`

Deletes all existing vault files (`vault.enc`, `vault.salt`, `vault.kdf`, `vault.key`) after explicit user confirmation.

```bash
credentiald-cli reset
```

## Environment Variables

- `CREDENTIALD_DATA_DIR`: Override the default vault data directory (default: `~/.local/share/credentiald`).
- `CREDENTIALD_SOCKET_PATH`: Override the default Native IPC socket path (default: `$XDG_RUNTIME_DIR/credentiald/native.sock`).
