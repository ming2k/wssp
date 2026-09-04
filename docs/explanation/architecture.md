# Architecture

`sigil` is a security-first desktop session credential service and infrastructure daemon.
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
                │        sigil        │                               │
                │                           │                               ▼
                │  Secret Service adapter   │                      org.freedesktop.impl.portal.Secret
                │             │             │                               │
                │             ▼             │                               ▼
                │    sigil-service     │                   xdg-desktop-portal-aegis
                │       │           │       │                   (aegis-portal-secret adapter)
                │       ▼           ▼       │                               │
                │     crypto      store     │                               ▼ (sigil-client)
                │                           │                    Unix Domain Socket (SO_PEERCRED)
                │     native IPC server     │◄──────────────────────────────┘
                └───────────────────────────┘
```

## Workspace Layout

```text
sigil/
├── Cargo.toml
├── Cargo.lock
│
├── crates/
│   ├── sigil-core/           # Domain types, newtypes, SecretBytes, error models (#![forbid(unsafe_code)])
│   ├── sigil-crypto/         # XChaCha20-Poly1305, Argon2id, HKDF-SHA256, DH-IETF-1024
│   ├── sigil-store/          # Encrypted vault file persistence and atomic transactions
│   ├── sigil-service/        # Core service state machine, collections, search, policy
│   ├── sigil-ipc/            # Length-prefixed Unix socket protocol and SO_PEERCRED auth
│   ├── sigil-client/         # Async Rust SDK for desktop components (e.g. portal backend)
│   ├── sigil-secret-service/ # D-Bus org.freedesktop.secrets protocol adapter
│   ├── sigil/               # Daemon assembly entrypoint
│   ├── sigil-prompter/      # Transient Optics (iris/lens) prompt agent
│   ├── sigil-cli/           # CLI administration tool
│   └── sigil-pam/           # Hardened PAM module
│
├── docs/
└── systemd/
```

## Crate Descriptions

### `sigil-core`
Pure domain types with zero async, runtime, or D-Bus dependencies.
- `Namespace`, `Subject`, `Purpose`, `CredentialId`
- `SecretBytes` (protected memory with `Zeroize` and `ZeroizeOnDrop`)
- Typed `SigilError`

### `sigil-crypto`
Cryptographic primitives and key derivation:
- XChaCha20-Poly1305 authenticated encryption with AAD binding.
- Argon2id key derivation with serialized `KdfParams`.
- HKDF-SHA256 domain-isolated secret derivation for sandboxed applications.
- DH-IETF-1024 session key negotiation for Secret Service clients.

### `sigil-store`
Durable persistence:
- `FileVaultStore` managing `vault.enc`, `vault.key`, `vault.kdf`, and `vault.salt`.
- Atomic writes via temporary files with strict file permissions (`0600`).
- Integrity validation and symlink rejection.

### `sigil-service`
The core business logic and state machine:
- Manages lock state (`Locked` / `Unlocked` / `Uninitialized`).
- Application secret derivation (`derive_app_secret`).
- Item and Collection CRUD and metadata search.

### `sigil-ipc` & `sigil-client`
Native IPC layer over `$XDG_RUNTIME_DIR/sigil/native.sock`:
- Length-prefixed framed binary JSON transport.
- Linux `SO_PEERCRED` validation ensuring caller UID matches the daemon process.
- Async `SigilClient` SDK consumed by `xdg-desktop-portal-aegis`.

### `sigil-secret-service`
D-Bus frontend adapter:
- Translates `org.freedesktop.Secret.*` method calls into `sigil-service` operations.
- Manages session DH handshakes and transport encryption.
- No direct database access or file persistence inside the D-Bus handler.
