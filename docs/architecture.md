# Architecture

WSSP (Wayland Secret Service Provider) is a Rust implementation of the
[freedesktop.org Secret Service API](https://specifications.freedesktop.org/secret-service/latest/).
It is designed as a security-first, split-process daemon that runs without any GUI dependencies
in its core and is compatible with any application that uses libsecret or the raw D-Bus interface.

## Workspace Layout

```
wssp/
├── wssp-core/        Pure cryptographic core (no D-Bus, no async)
├── wssp-daemon/      D-Bus service and state management
├── wssp-common/      IPC type definitions shared between daemon and prompter
├── wssp-prompter/    Transient GTK4 password prompt UI
├── wssp-cli/         Vault management CLI
└── wssp-pam/         PAM module for login-time and screensaver unlock
```

## Component Descriptions

### `wssp-core` — Cryptographic Engine

A pure Rust library with no async or D-Bus dependencies.

| Module | Responsibility |
|--------|---------------|
| `vault` | Serialize/encrypt vault data with XChaCha20-Poly1305; derive master key with Argon2id; generate and encode random keyfiles |
| `error` | `CoreError` type used across the workspace |

The `Vault` struct owns the master key `[u8; 32]` and the on-disk path. All sensitive structs
(`VaultData`, `CollectionData`, `ItemData`) derive `Zeroize` + `#[zeroize(drop)]` so memory
is cleared on drop.

### `wssp-daemon` — D-Bus Service

The persistent background process. No GTK or graphical dependencies.

```
wssp-daemon/src/
├── main.rs        Startup, auto-init, PAM token read, D-Bus setup
├── service.rs     org.freedesktop.Secret.Service interface
├── collection.rs  org.freedesktop.Secret.Collection interface
├── item.rs        org.freedesktop.Secret.Item interface
├── session.rs     DH key exchange + AES-128-CBC-PKCS7 en/decryption
├── prompt.rs      org.freedesktop.Secret.Prompt interface + Completed signal
├── portal.rs      org.freedesktop.portal.Secret stub
├── ipc.rs         Unix socket listener; spawns wssp-prompter on demand
├── logind.rs      logind Session.Lock subscription + inotify PAM token watcher
├── unlock.rs      Shared helpers: apply_vault_data, try_unlock_with_keyfile
├── state.rs       Shared mutable state (Arc<RwLock<State>>)
├── vault.rs       Re-export of wssp-core::vault
└── error.rs       WsspDaemonError mapped to zbus::fdo::Error
```

**State model**: a single `Arc<RwLock<State>>` is cloned into every D-Bus interface object.
`State` holds the collection/item graph, active sessions, vault handle, unlock status, and
the paths to `vault.enc`, `vault.salt`, and `vault.key`.

**Persistence**: every write operation (`create_item`, `set_secret`, `delete`) calls
`state.sync_to_vault()`, which serializes the entire in-memory graph and re-encrypts it to disk.

**Vault modes**:
- *Password mode*: `vault.salt` exists; key derived via Argon2id(password, salt).
- *No-password mode*: `vault.key` exists; key read directly from the file (OS-random 256-bit).

### `wssp-common` — Shared IPC Types

Contains `PromptResponse { password: Option<String> }`, serialized as JSON over the Unix socket.

### `wssp-prompter` — Password UI

A GTK4 / Libadwaita application **spawned on demand** by `wssp-daemon` when the vault is
password-protected and locked. Its sole responsibility is to ask for the master password and
send it back to the daemon.

After the user submits a password (or cancels), the prompter:
1. Connects to the Unix socket at `$XDG_RUNTIME_DIR/wssp.sock`
2. Sends a JSON-encoded `PromptResponse`
3. Exits

The prompter process does **not** stay running. Its lifetime is a single interaction.
In no-password mode the prompter is never spawned.

### `wssp-cli` — Vault Management CLI

Command-line tool for vault lifecycle management and headless unlock.

| Command | Description |
|---------|-------------|
| `wssp-cli init <password>` | First-time initialization in password mode |
| `wssp-cli init --no-password` | First-time initialization in no-password (keyfile) mode |
| `wssp-cli unlock <password>` | Send password to a waiting daemon socket (headless unlock) |
| `wssp-cli change-password <old> <new>` | Re-encrypt vault with a new password |
| `wssp-cli clear-password <current>` | Migrate to no-password mode |
| `wssp-cli set-password <new>` | Migrate from no-password to password mode |
| `wssp-cli reset [--force]` | Delete all vault files |

Stop the daemon before any command that modifies vault files.

### `wssp-pam` — Login and Screensaver Integration

A PAM shared library (`libwssp_pam.so`) that intercepts the user's authentication token.

On `authenticate`:
1. Reads the auth token from PAM
2. Writes it to `/run/user/<UID>/wssp-pam-token` (mode `0600`, owned by the user)
3. Returns `SUCCESS` immediately (does not block login)

The token file serves two purposes depending on context:

| Context | How the daemon uses the token |
|---------|-------------------------------|
| Login (daemon startup) | Password mode: derive vault key from token content. No-password mode: use token as auth signal, read key from `vault.key`. |
| Screensaver dismissed (inotify) | Same as above; token detected by `logind.rs` watcher, deleted immediately after read. |

Install `pam_wssp.so` in both `/etc/pam.d/system-login` and `/etc/pam.d/swaylock` for full
login + screensaver integration. See [unlock-strategies.md](unlock-strategies.md).

## Data Flow

### Startup and Auto-Init

```
wssp-daemon starts
│
├── vault.enc exists?
│     ├── YES + vault.key exists  → no-password mode: read key → unlock immediately
│     └── YES + vault.salt exists → password mode:
│               PAM token present? → read token → delete → derive key → unlock
│               PAM token absent?  → start locked (await Unlock D-Bus call)
│
└── vault.enc absent → first run:
      auto-init in no-password mode:
        generate 256-bit key → write vault.key (0600)
        create empty vault.enc → unlock immediately
      (use wssp-cli set-password to switch to password mode)
```

### Session Key Exchange (DH)

Every client interaction that transfers a secret uses an encrypted session. The algorithm is
`dh-ietf1024-sha256-aes128-cbc-pkcs7` as defined in the Secret Service spec.

```
Client (libsecret)                      Daemon (wssp-daemon)
─────────────────                       ──────────────────
Generate client_priv (random)
client_pub = 2^client_priv mod P
                         ──OpenSession(client_pub)──►
                                        Generate server_priv (random 2 ≤ x < P-2)
                                        server_pub = 2^server_priv mod P
                                        shared = client_pub^server_priv mod P
                                        Pad shared to 128 bytes
                                        AES_key = HKDF-SHA256(IKM=shared, salt=∅, info=∅)[0:16]
                         ◄──(server_pub, session_path)──
shared = server_pub^client_priv mod P
Pad shared to 128 bytes
AES_key = HKDF-SHA256(IKM=shared, salt=∅, info=∅)[0:16]

Both sides now hold the same AES-128 key.

Client encrypts secret:  IV = random 16 bytes
                         ciphertext = AES-128-CBC-PKCS7(AES_key, IV, secret)
                         ──CreateItem(session, IV, ciphertext)──►
                                        Daemon decrypts with AES_key → plaintext
                                        Stores plaintext in memory, syncs vault
```

**Key derivation note**: `HKDF-SHA256` with `salt=None` (32 zero bytes per RFC 5869 §2.2) and
empty `info` matches the reference implementation in libsecret/secretstorage exactly.
Plain `SHA256(shared)` produces a different key and is **not** compatible.

### Vault Unlock Flow (password mode, on-demand)

```
1. Client calls Service.Unlock([collection_paths])
2. Daemon atomically checks is_unlocked and is_unlocking (under write lock)
   ├── Already unlocked → return objects immediately
   ├── Unlock in progress → return /prompt/pending
   └── Proceed: set is_unlocking=true, create Prompt object, spawn async task
3. Async task:
   a. Calls ipc::request_password()
      ├── Headless (no display): read WSSP_PASSWORD env var
      └── GUI: create $XDG_RUNTIME_DIR/wssp.sock
               spawn wssp-prompter
               accept connection (60s timeout)
               read PromptResponse (10s timeout)
   b. load_vault(password, vault_path, salt_path, is_existing=true)
      read salt → Argon2id → XChaCha20-Poly1305 decrypt
   c. build_collections(data, state_arc) → register on D-Bus
   d. state.is_unlocked = true; is_unlocking = false
   e. Emit Prompt.Completed(dismissed=false, unlocked_objects)
```

### Screensaver Lock / Unlock Flow

```
Screen locks (loginctl lock-session / swayidle)
  └── logind Session.Lock signal
        └── daemon: is_unlocked = false, vault = None (key evicted)

Screensaver dismissed (swaylock PAM auth succeeds)
  └── pam_wssp.so writes /run/user/<UID>/wssp-pam-token
        └── inotify CLOSE_WRITE event in logind.rs
              ├── no-password mode: delete token → read vault.key → unlock
              └── password mode:   read token content → delete → derive key → unlock
```

### Write Path (CreateItem / SetSecret)

```
D-Bus call → decrypt secret with session AES key
           → update in-memory Item
           → state.sync_to_vault()
               serialize all non-deleted collections+items to JSON
               XChaCha20-Poly1305 encrypt with random 24-byte nonce
               atomic write to vault.enc (nonce ‖ ciphertext)
```

## D-Bus Object Hierarchy

```
/org/freedesktop/secrets
├── (Service interface)
├── /session/s<hex16>          ← ephemeral, one per OpenSession call
├── /prompt/p<hex16>           ← ephemeral, one per pending unlock
├── /collection/login          ← always present ("Login" keyring)
│   └── /collection/login/<hex16>   ← items
└── /aliases/default           ← mirrors /collection/login
```

Object path IDs (`<hex16>`) are 8 cryptographically-random bytes rendered as 16 hex characters,
generated with `rand::rngs::OsRng`.
