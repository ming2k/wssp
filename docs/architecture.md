# Architecture

WSSP (Wayland Secret Service Provider) is a Rust implementation of the
[freedesktop.org Secret Service API](https://specifications.freedesktop.org/secret-service/latest/).
It is designed as a security-first, split-process daemon that runs without any GUI dependencies
in its core and is compatible with any application that uses libsecret or the raw D-Bus interface.

## Workspace Layout

```
wssp/
├── wss-core/        Pure cryptographic core (no D-Bus, no async)
├── wss-daemon/      D-Bus service and state management
├── wss-common/      IPC type definitions shared between daemon and prompter
├── wss-prompter/    Transient GTK4 password prompt UI
├── wss-cli/         Headless CLI for scripted unlocking
└── wss-pam/         PAM module for automatic login-time unlock
```

## Component Descriptions

### `wss-core` — Cryptographic Engine

A pure Rust library with no async or D-Bus dependencies.

| Module | Responsibility |
|--------|---------------|
| `vault` | Serialize/encrypt vault data with XChaCha20-Poly1305; derive master key with Argon2id |
| `error` | `CoreError` type used across the workspace |

The `Vault` struct owns the master key `[u8; 32]` and the on-disk path. All sensitive structs
(`VaultData`, `CollectionData`, `ItemData`) derive `Zeroize` + `#[zeroize(drop)]` so memory
is cleared on drop.

### `wss-daemon` — D-Bus Service

The persistent background process. No GTK or graphical dependencies.

```
wss-daemon/src/
├── main.rs        Startup, PAM auto-unlock, D-Bus connection setup
├── service.rs     org.freedesktop.Secret.Service interface
├── collection.rs  org.freedesktop.Secret.Collection interface
├── item.rs        org.freedesktop.Secret.Item interface
├── session.rs     DH key exchange + AES-128-CBC-PKCS7 en/decryption
├── prompt.rs      org.freedesktop.Secret.Prompt interface + Completed signal
├── portal.rs      org.freedesktop.portal.Secret stub
├── ipc.rs         Unix socket listener; spawns wss-prompter
├── state.rs       Shared mutable state (Arc<RwLock<State>>)
├── vault.rs       Re-export of wss-core::vault
└── error.rs       WssDaemonError mapped to zbus::fdo::Error
```

**State model**: a single `Arc<RwLock<State>>` is cloned into every D-Bus interface object.
`State` holds the collection/item graph, active sessions, vault handle, and unlock status.

**Persistence**: every write operation (`create_item`, `set_secret`, `delete`) calls
`state.sync_to_vault()`, which serializes the entire in-memory graph and re-encrypts it to disk.

### `wss-common` — Shared IPC Types

Contains `PromptResponse { password: Option<String> }`, serialized as JSON over the Unix socket.

### `wss-prompter` — Password UI

A GTK4 / Libadwaita application that is **spawned on demand** by `wss-daemon`. It has two modes:

| Mode (`WSSP_PROMPT_MODE`) | Purpose |
|--------------------------|---------|
| _(unset)_ | Ask for the existing master password to unlock the vault |
| `create` | Ask for a new master password when initializing the vault for the first time |

After the user submits a password (or cancels), the prompter:
1. Connects to the Unix socket at `$XDG_RUNTIME_DIR/wssp.sock`
2. Sends a JSON-encoded `PromptResponse`
3. Exits

The prompter process does **not** stay running. Its lifetime is limited to a single interaction.

### `wss-cli` — Headless Unlock

A minimal CLI (`wss-cli unlock <password>`) that writes a `PromptResponse` directly to the
daemon's Unix socket. Used for scripted environments where no GUI is available.

### `wss-pam` — Login Integration

A PAM shared library (`libwss_pam.so`) that intercepts the user's login credentials.

On authenticate:
1. Reads the auth token from PAM
2. Writes it to `/run/user/<UID>/wssp-pam-token` (mode `0600`, owned by the user)
3. Returns `SUCCESS` immediately (does not block login)

On next daemon startup, `main.rs` reads and deletes this file, derives the vault key, and
auto-unlocks — giving a seamless keyring-at-login experience without a password prompt.

## Data Flow

### Session Key Exchange (DH)

Every client interaction that transfers a secret uses an encrypted session. The algorithm is
`dh-ietf1024-sha256-aes128-cbc-pkcs7` as defined in the Secret Service spec.

```
Client (libsecret)                      Daemon (wss-daemon)
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

### Vault Unlock Flow

```
1. Client calls Service.Unlock([collection_paths])
2. Daemon atomically checks is_unlocked and is_unlocking (under write lock)
   ├── Already unlocked → return objects immediately
   ├── Unlock in progress → return /prompt/pending
   └── Proceed: set is_unlocking=true, create Prompt object, spawn async task
3. Async task:
   a. Calls ipc::request_password(is_initial)
      ├── Headless: read WSSP_PASSWORD env var
      └── GUI:      create $XDG_RUNTIME_DIR/wssp.sock
                    spawn wss-prompter
                    accept connection (60s timeout)
                    read PromptResponse (10s timeout)
   b. load_vault(password, vault_path, salt_path, is_initial)
      ├── New vault: generate salt → Argon2id → create empty Vault
      └── Existing: read salt → Argon2id → XChaCha20-Poly1305 decrypt
   c. build_collections(data, state_arc) → register on D-Bus
   d. state.is_unlocked = true; is_unlocking = false
   e. Emit Prompt.Completed(dismissed=false, unlocked_objects)
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
