# Coding Conventions

## Rust Style

**Formatting**: always run `cargo fmt` before committing. CI will reject unformatted code.

**Linting**: `cargo clippy -- -D warnings` must pass. Suppress individual warnings only with
a comment explaining why:
```rust
#[allow(dead_code)] // preserved for future portal implementation
```

## Error Handling

| Context | Type | Reason |
|---------|------|--------|
| Internal logic | `Result<T, Box<dyn Error + Send + Sync>>` | Flexible `?` propagation across threads |
| D-Bus interface methods | `zbus::fdo::Result<T>` | Maps to D-Bus error replies |
| `wssp-core` | `core::error::Result<T>` | No async, no D-Bus, typed errors |

Convert between layers at the boundary:
```rust
some_internal_call()
    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
```

Avoid `.unwrap()` in non-test code. Use `.expect("reason that explains the invariant")` when
a condition genuinely cannot fail, with a message that explains why.

## Concurrency

- Use `tokio::sync::RwLock` for the shared `State` — reads are far more frequent than writes.
- Never hold a `RwLock` guard across an `.await` point unless you have deliberately designed for
  it. The typical pattern is:
  ```rust
  let value = { self.state.read().await.field.clone() };
  // do async work with value
  ```
- `sync_to_vault()` is called with the state read lock **not held** — it acquires its own
  short-lived read lock internally.

## Sensitive Data

1. Any struct that holds secrets, keys, or passwords **must** derive `Zeroize` and annotate
   with `#[zeroize(drop)]`:
   ```rust
   #[derive(Zeroize)]
   #[zeroize(drop)]
   struct Sensitive { key: Vec<u8> }
   ```

2. Session AES keys (`SessionAlgorithm::Dh`) use a manual `Drop` impl to call `zeroize()`
   because enums cannot use `#[zeroize(drop)]` directly on a variant.

3. Decrypt buffers must be zeroed immediately after use, even on the error path:
   ```rust
   let mut buf = ciphertext.to_vec();
   match decryptor.decrypt_padded_mut::<Pkcs7>(&mut buf) {
       Ok(pt) => { let r = pt.to_vec(); buf.zeroize(); Ok(r) }
       Err(e) => { buf.zeroize(); Err(e.into()) }
   }
   ```

4. **Never log** passwords, decrypted secrets, AES keys, or DH private keys. Log only
   object paths, IDs, byte counts, and error messages:
   ```rust
   info!("Vault unlocked. {} collection(s) loaded.", n);  // OK
   info!("Master key: {:?}", key);                         // NEVER
   ```

## Object Path IDs

D-Bus object path IDs (sessions, prompts, items, collections) are generated with 8 bytes from
`OsRng`, rendered as 16 lowercase hex characters:

```rust
fn generate_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
```

Do not use `rand::random::<u32>()` for IDs — 32-bit random values have only ~4 billion
possible values, making enumeration feasible on a local bus.

## Cryptographic Primitives

| Use case | Primitive | Notes |
|----------|-----------|-------|
| Vault key derivation | Argon2id (default params) | Do not weaken params for "faster tests" |
| Vault encryption | XChaCha20-Poly1305 | AEAD; nonce is 24-byte random per save |
| Session key derivation | HKDF-SHA256, salt=None, info=∅ | Matches libsecret/secretstorage |
| Session encryption | AES-128-CBC-PKCS7 | Mandated by Secret Service spec |
| IV generation | `OsRng.fill_bytes` | Never use `rand::random` for IVs |

**Do not substitute** `SHA256(shared_secret)` for the HKDF step — it produces a different key
and breaks compatibility with all Secret Service clients.

## Vault Persistence

Every mutation of the secret store (create, update, delete) must call `state.sync_to_vault()`.
The helper in `State` iterates all non-deleted collections and items atomically:

```rust
// After mutating an item:
self.state.read().await.sync_to_vault().await;
```

If you add a new write path, ensure `sync_to_vault()` is called before returning `Ok`.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: implement Service.SearchItems
fix: use HKDF-SHA256 for session key derivation
refactor: extract sync_to_vault into State
docs: update DH key exchange description
test: add full_dh_roundtrip integration test
```

Breaking changes must include `!` after the type: `feat!: change vault file format`.
