# Storage Format Reference

## Location & Files

All persistent state lives in `$CREDENTIALD_DATA_DIR` (defaults to `$XDG_DATA_HOME/credentiald/` or `~/.local/share/credentiald/`).

```text
~/.local/share/credentiald/
├── vault.enc   # Encrypted vault data (XChaCha20-Poly1305)
├── vault.key   # 256-bit root key in hex (Keyfile mode only)
├── vault.kdf   # JSON Argon2id parameters (Password mode only)
└── vault.salt  # Random 32-byte salt in hex (Password mode only)
```

## `vault.enc` Structure

The encrypted vault file layout:

```text
+-------------------+-----------------------------------------+
| Nonce (24 bytes)  | Ciphertext + Poly1305 Tag (16 bytes)    |
| (XChaCha20 nonce) | (Encrypted JSON-serialized VaultData)   |
+-------------------+-----------------------------------------+
```

### Decrypted `VaultData` Schema

```json
{
  "version": 1,
  "collections": [
    {
      "id": "login",
      "label": "Login",
      "items": [
        {
          "id": "i_12345678",
          "label": "My Password",
          "attributes": {
            "xdg:schema": "org.freedesktop.Secret.Generic"
          },
          "secret": [115, 101, 99, 114, 101, 116],
          "content_type": "text/plain",
          "created_at": 1700000000,
          "modified_at": 1700000000
        }
      ]
    }
  ]
}
```

## `vault.kdf` Schema

```json
{
  "version": 1,
  "kdf": "argon2id",
  "m_cost": 65536,
  "t_cost": 3,
  "p_cost": 4,
  "salt": "a1b2c3d4..."
}
```

## File Invariants

- Directory permissions MUST be `0700`.
- File permissions MUST be `0600`.
- Symlinks are rejected via `O_NOFOLLOW` and metadata verification.
- Updates use temp-then-rename atomic transactions with `fsync`.
