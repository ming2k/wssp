# Threat Model

## 1. Scope & Objective

`credentiald` is a desktop session credential service responsible for secure credential storage, cryptographic protection, lifecycle management, locking, and credential-related policy.

This threat model defines the security boundaries, assets, threat actors, protections, and explicit non-claims of the system.

## 2. Assets to Protect

1. **Master Key Material**: The 256-bit symmetric root key in memory and its persistent wrapped forms.
2. **Stored Secret Payloads**: Passwords, tokens, and symmetric secrets stored in the persistent vault.
3. **Application Derived Secrets**: Per-application keys derived for sandboxed Flatpak / Snap applications.
4. **Metadata Confidentiality**: Sensitive labels, attributes, and collection names.

## 3. Trust Boundaries

```text
┌─────────────────────────────────────────────────────────────┐
│ Unconfined Desktop Session (UID: 1000)                      │
│                                                             │
│  ┌────────────────────────┐       ┌──────────────────────┐  │
│  │ Flatpak Sandbox (App A)│       │ Flatpak Sandbox (App │  │
│  └───────────┬────────────┘       └───────────┬──────────┘  │
│              │ (bwrap / portal)               │             │
│              ▼                                ▼             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ xdg-desktop-portal (verifies app identity)            │  │
│  └───────────────────────────┬───────────────────────────┘  │
│                              │                              │
│                              ▼                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ xdg-desktop-portal-aegis (Trusted Portal Broker)      │  │
│  └───────────────────────────┬───────────────────────────┘  │
│                              │                              │
│                              ▼ (SO_PEERCRED verified)       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ credentiald (Isolated TCB & Vault Guardian)           │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 4. Protected Threats (Security Claims)

- **At-Rest Filesystem Theft**: Encrypted with XChaCha20-Poly1305 and Argon2id. Without the master key or user passphrase, ciphertext disclosure yields zero plaintext or metadata.
- **Cross-Sandbox Secret Leakage**: App A cannot access App B's secret. Portal identities are verified by `xdg-desktop-portal` before reaching `credentiald`, and keys are mathematically orthogonal via HKDF-SHA256 domain separation.
- **Memory Dumping / Core Dumps**: All secret-holding structures implement `Zeroize` / `ZeroizeOnDrop` and are cleared immediately upon leaving scope or when locked.
- **Log Leakage**: `SecretBytes` and `MasterKey` redact their contents in all standard formatting traits (`Debug`, `Display`).
- **Atomicity & Power Loss**: Vault writes use `atomic_replace` (`O_NOFOLLOW`, temporary file, `fsync`, atomic rename). Partial writes or broken JSON files cannot corrupt the storage state.

## 5. Non-Claims (Out of Scope)

- **Root / Kernel Compromise**: An adversary with root/kernel privileges can read arbitrary memory pages and bypass all user-space daemon protections.
- **Debugger / Ptrace on Daemon**: Processes with identical UID and `PTRACE_MODE_ATTACH` capability can inspect daemon memory unless restricted by Yama/SELinux/AppArmor.
- **Hardware-level Side Channels**: Advanced physical EM/power analysis on consumer CPU silicon without hardware secure enclaves is outside the baseline model.
