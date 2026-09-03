# Architecture

`credentiald` is a security-first desktop session credential service and infrastructure daemon.
It provides a standards-compliant freedesktop.org Secret Service API implementation while exposing a native IPC interface for trusted desktop components such as the XDG Desktop Portal backend.

## Design Principle

> **One credential infrastructure, multiple protocol adapters.**

Secret Service and Portal Secret share storage, cryptography, lifecycle, and policy, but they do not share protocol semantics.

```text
                     Native Applications                          Sandboxed Applications
                              │                                             │
                              ▼                                             ▼
                   org.freedesktop.secrets                        org.freedesktop.portal.Secret
                              │                                             │
                              ▼                                             ▼
                ┌───────────────────────────┐                      xdg-desktop-portal
                │        credentiald        │                               │
                │                           │                               ▼
                │  Secret Service adapter   │                      org.freedesktop.impl.portal.Secret
                │             │             │                               │
                │             ▼             │                               ▼
                │    credential-service     │                   xdg-desktop-portal-aegis
                │       │           │       │                   (aegis-portal-secret adapter)
                │       ▼           ▼       │                               │
                │     crypto      store     │                               ▼ (credential-client)
                │                           │                    Unix Domain Socket (SO_PEERCRED)
                │     native IPC server     │◄──────────────────────────────┘
                └───────────────────────────┘
```

## Workspace Layout

```text
credentiald/
├── Cargo.toml
├── Cargo.lock
│
├── crates/
│   ├── credential-core/           # Domain types, newtypes, SecretBytes, error models (#![forbid(unsafe_code)])
│   ├── credential-crypto/         # XChaCha20-Poly1305, Argon2id, HKDF-SHA256, DH-IETF-1024
│   ├── credential-store/          # Encrypted vault file persistence and atomic transactions
│   ├── credential-service/        # Core service state machine, collections, search, policy
│   ├── credential-ipc/            # Length-prefixed Unix socket protocol and SO_PEERCRED auth
│   ├── credential-client/         # Async Rust SDK for desktop components (e.g. portal backend)
│   ├── credential-secret-service/ # D-Bus org.freedesktop.secrets protocol adapter
│   ├── credentiald/               # Daemon assembly entrypoint
│   ├── credentiald-prompter/      # Transient GTK4 / Libadwaita prompt agent
│   ├── credentiald-cli/           # CLI administration tool
│   └── credentiald-pam/           # Hardened PAM module
│
├── docs/
└── systemd/
```

## Crate Descriptions

### `credential-core`
Pure domain types with zero async, runtime, or D-Bus dependencies.
- `Namespace`, `Subject`, `Purpose`, `CredentialId`
- `SecretBytes` (protected memory with `Zeroize` and `ZeroizeOnDrop`)
- Typed `CredentialError`

### `credential-crypto`
Cryptographic primitives and key derivation:
- XChaCha20-Poly1305 authenticated encryption with AAD binding.
- Argon2id key derivation with serialized `KdfParams`.
- HKDF-SHA256 domain-isolated secret derivation for sandboxed applications.
- DH-IETF-1024 session key negotiation for Secret Service clients.

### `credential-store`
Durable persistence:
- `FileVaultStore` managing `vault.enc`, `vault.key`, `vault.kdf`, and `vault.salt`.
- Atomic writes via temporary files with strict file permissions (`0600`).
- Integrity validation and symlink rejection.

### `credential-service`
The core business logic and state machine:
- Manages lock state (`Locked` / `Unlocked` / `Uninitialized`).
- Application secret derivation (`derive_app_secret`).
- Item and Collection CRUD and metadata search.

### `credential-ipc` & `credential-client`
Native IPC layer over `$XDG_RUNTIME_DIR/credentiald/native.sock`:
- Length-prefixed framed binary JSON transport.
- Linux `SO_PEERCRED` validation ensuring caller UID matches the daemon process.
- Async `CredentialClient` SDK consumed by `xdg-desktop-portal-aegis`.

### `credential-secret-service`
D-Bus frontend adapter:
- Translates `org.freedesktop.Secret.*` method calls into `credential-service` operations.
- Manages session DH handshakes and transport encryption.
- No direct database access or file persistence inside the D-Bus handler.
