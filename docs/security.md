# Security Model

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Offline brute-force of `vault.enc` | Argon2id KDF; AEAD authentication tag rejects modified ciphertext |
| Secret exfiltration via D-Bus while unlocked | Session secrets are AES-128-CBC encrypted in transit; plaintext never leaves the daemon |
| Session key recovery from process memory | AES session keys are stored in `Vec<u8>` with a custom `Drop` that calls `zeroize()` |
| Concurrent unlock spawning multiple prompts | `is_unlocking` flag checked and set atomically under a single write lock |
| Malformed DH public key (small-subgroup attack) | Client public key validated: `1 < key < p−1` per RFC 2409 before any computation |
| PAM token lingering on disk | Token is read and deleted before any other work in `main()` |
| Prompter process hijacking | Socket path is inside `$XDG_RUNTIME_DIR` (mode 0700, owned by user) |

**Outside scope**: WSSP trusts the D-Bus session bus. Any process that can connect to the user's
session bus and call `Unlock` can trigger a password prompt. This is an inherent property of the
Secret Service API design — the same limitation applies to gnome-keyring and KWallet.

## Cryptography

### Vault at Rest

| Layer | Algorithm | Parameters | Crate |
|-------|-----------|------------|-------|
| Key derivation | Argon2id | Default (19 MiB memory, 2 iterations, 1 thread) | `argon2` |
| Vault encryption | XChaCha20-Poly1305 | 192-bit random nonce per save | `chacha20poly1305` |
| Salt storage | Base64-encoded `SaltString` | OS-random via `OsRng` | `argon2` / `rand` |

**Vault file format**: `[24-byte nonce][ciphertext+16-byte Poly1305 tag]`

The Poly1305 authentication tag ensures any single-bit corruption or tampering of `vault.enc`
produces a decryption failure, not silent data corruption.

### Secret Service Session (In-Transit)

The `dh-ietf1024-sha256-aes128-cbc-pkcs7` session algorithm mandated by the Secret Service spec:

| Step | Detail |
|------|--------|
| DH group | RFC 2409 IETF 1024-bit MODP Group 2 (1024-bit prime `P`, generator `g=2`) |
| Server private key | Random integer in `[2, P−2]` via `rand::thread_rng().gen_biguint_range(...)` |
| Shared secret | `client_pub ^ server_priv mod P`, padded with leading zeros to 128 bytes |
| Key derivation | `HKDF-SHA256(IKM=shared_128, salt=None, info=∅)`, first 16 bytes |
| Encryption | AES-128-CBC with PKCS#7 padding; 16-byte IV generated with `OsRng` |

**HKDF, not SHA256**: The spec text says "hashing with SHA-256" but the reference implementation
(libsecret, secretstorage) applies RFC 5869 HKDF. `HKDF(IKM, salt=None)` uses a 32-byte
all-zero salt. Using plain `SHA256(shared)` produces a different key and breaks interoperability.

### Memory Safety

All sensitive in-memory structures zeroize their contents on drop:

| Type | Sensitive fields | Mechanism |
|------|-----------------|-----------|
| `VaultData` / `CollectionData` / `ItemData` | `secret: Vec<u8>` | `#[derive(Zeroize)] #[zeroize(drop)]` |
| `SessionAlgorithm::Dh(Vec<u8>)` | AES-128 session key | Manual `Drop` impl calling `zeroize()` |
| Decrypt buffer in `session.rs` | Plaintext + padded ciphertext | `buf.zeroize()` before `Ok`/`Err` return |

Decrypted vault data is held in `Arc<RwLock<Vec<u8>>>` within each `Item`. The data lives only
for the daemon's lifetime; there is no swap/page-out mitigation (`mlock`) at present (see Known
Limitations).

## Known Limitations

### `mlock` not applied to secret memory
Decrypted secrets in `Item.secret` can in principle be swapped to disk by the OS if memory
pressure is high. Mitigating this requires `libc::mlock` on the `Vec<u8>` allocations, which
needs careful integration with the allocator. This is a known future improvement.

### 1024-bit DH is legacy
The Secret Service spec mandates the 1024-bit MODP group. While considered weak by current
NIST guidance, no client library supports a stronger group for this protocol. The session
key only protects the D-Bus wire transport (loopback), not the vault at rest. The vault uses
XChaCha20-Poly1305 with a 256-bit key, which is not affected.

### PAM token is plaintext on disk
`wssp-pam` writes the login password to `/run/user/<UID>/wssp-pam-token` (mode 0600). The file
exists only between PAM `authenticate()` and `wssp-daemon` startup. If the daemon crashes before
reading it, the file persists with a plaintext credential until the next login. A future
improvement would use a kernel keyring or `memfd_create()` to avoid filesystem exposure.

### `lock()` is a no-op
`Service.Lock()` currently returns success without actually evicting decrypted data from memory.
A full implementation would clear the in-memory item secrets and require re-unlocking.

### Portal (`org.freedesktop.portal.Secret`) is a stub
The xdg-desktop-portal integration returns `0u32` rather than writing the master key to the
provided file descriptor. Full portal support requires `nix::unistd::write` with the fd.

## D-Bus Threat Surface

Any local user process on the same session bus can:
- Call `OpenSession` to establish an encrypted channel
- Call `Unlock` to trigger a password prompt (user must approve)
- Enumerate collection/item paths once unlocked

There is no per-application secret namespacing in the Secret Service API. If an application
needs isolation, it should request a dedicated collection via `CreateCollection`.
