# Development Guide

## Prerequisites

### System libraries (Debian/Ubuntu)
```bash
sudo apt install libgtk-4-dev libadwaita-1-dev libdbus-1-dev pkg-config
```

### Rust toolchain
```bash
rustup update stable
```

### Useful tools
```bash
sudo apt install busctl secret-tool d-feet
```

## Building

```bash
# Full workspace
cargo build

# Daemon only (faster iteration)
cargo build -p wss-daemon
```

## Running the Daemon

The daemon registers the well-known D-Bus name `org.freedesktop.secrets`. To avoid conflicting
with a running gnome-keyring or kwallet during development, stop your existing secret service
first, or run inside a separate D-Bus session (see _Isolated D-Bus session_ below).

```bash
# Standard run with debug logging
RUST_LOG=debug cargo run -p wss-daemon

# Run with the prompter binary path explicitly set
WSSP_PROMPTER_PATH=./target/debug/wss-prompter RUST_LOG=debug cargo run -p wss-daemon
```

### Key environment variables

| Variable | Effect |
|----------|--------|
| `RUST_LOG` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace` |
| `WSSP_PROMPTER_PATH` | Absolute or relative path to `wss-prompter` binary |
| `WSSP_PASSWORD` | Skip GUI; used when `WAYLAND_DISPLAY` and `DISPLAY` are both unset |
| `WSSP_PROMPT_MODE=create` | Tell `wss-prompter` to show the "set new password" UI |

## Testing with `secret-tool`

Build both binaries first, then in one terminal:

```bash
cargo build && WSSP_PROMPTER_PATH=./target/debug/wss-prompter ./target/debug/wss-daemon
```

In another terminal:

```bash
# Store a secret (triggers unlock prompt on first run)
secret-tool store --label="Test" service myapp username alice

# Retrieve it
secret-tool lookup service myapp username alice

# List items
secret-tool search service myapp
```

## D-Bus Inspection

### Verify the service is online

```bash
busctl --user list | grep freedesktop.secrets
```

### Inspect the object tree

```bash
busctl --user tree org.freedesktop.secrets
```

Expected output after daemon start:
```
└─ /org/freedesktop/secrets
   ├─ /org/freedesktop/secrets/aliases
   │  └─ /org/freedesktop/secrets/aliases/default
   └─ /org/freedesktop/secrets/collection
      └─ /org/freedesktop/secrets/collection/login
```

### Query the `Collections` property

```bash
busctl --user get-property org.freedesktop.secrets \
    /org/freedesktop/secrets \
    org.freedesktop.Secret.Service \
    Collections
```

Expected: `ao 1 "/org/freedesktop/secrets/collection/login"`

### Test `ReadAlias`

```bash
busctl --user call org.freedesktop.secrets \
    /org/freedesktop/secrets \
    org.freedesktop.Secret.Service \
    ReadAlias s "default"
```

Expected: `o "/org/freedesktop/secrets/collection/login"`

### Open a plain-text session

```bash
busctl --user call org.freedesktop.secrets \
    /org/freedesktop/secrets \
    org.freedesktop.Secret.Service \
    OpenSession ss "plain" ""
```

Expected: `vs o "" "/org/freedesktop/secrets/session/s<hex>"`

## Running Tests

```bash
# All workspace tests
cargo test

# Crypto unit tests only
cargo test -p wss-daemon session::tests

# Vault tests
cargo test -p wss-core
```

The `session::tests` module contains:
- `hkdf_matches_libsecret_reference` — verifies our HKDF output matches the manual
  HMAC-based reference implementation from secretstorage/libsecret
- `full_dh_roundtrip` — simulates a complete client-server DH exchange and asserts both
  sides derive the same AES session key

## Debugging the DH Key Exchange

If you see `AES decryption/unpad failed: Unpad Error`, the session keys don't match.

**Quick check**: add temporary logging in `calculate_dh_shared_secret` to print the first 4 bytes
of the padded shared secret before and after HKDF:

```rust
eprintln!("shared[:4]  = {:02x?}", &shared_bytes[..4]);
eprintln!("sym_key[:4] = {:02x?}", &sym_key[..4]);
```

Compare with `dbus-monitor --session` to capture what the client sent:

```bash
dbus-monitor --session "type='method_call',interface='org.freedesktop.Secret.Service'"
```

The client's DH public key arrives as the `v` (variant) argument to `OpenSession`. Its
first 4 bytes should match what the daemon logs as `client_pub`.

## Isolated D-Bus Session

To avoid interfering with your running desktop keyring:

```bash
# Start a throw-away session bus
eval $(dbus-launch --sh-syntax)
echo "Session bus: $DBUS_SESSION_BUS_ADDRESS"

# In the same shell, run the daemon
cargo run -p wss-daemon

# In another shell, set the same DBUS_SESSION_BUS_ADDRESS and use secret-tool
```

## PAM Module Development

The PAM module requires root to install and a real PAM stack to test end-to-end. For unit
testing:

1. Build: `cargo build -p wss-pam`
2. Simulate its behaviour manually:
   ```bash
   echo -n "mypassword" > /run/user/$(id -u)/wssp-pam-token
   chmod 600 /run/user/$(id -u)/wssp-pam-token
   ```
3. Start `wss-daemon` — it should auto-unlock and log:
   `PAM token found; attempting automatic unlock.`

To install the module (system-wide):
```bash
sudo cp target/release/libwss_pam.so /lib/security/pam_wssp.so
# Add to /etc/pam.d/login (after the pam_unix.so auth line):
# auth optional pam_wssp.so
```

## Troubleshooting

### `Decryption failed: Unpad Error`
The client and daemon derived different AES session keys. Likely causes:
- Key derivation mismatch (must be HKDF-SHA256, not plain SHA256)
- D-Bus variant type mismatch when extracting the client's DH public key

Run `cargo test -p wss-daemon session::tests::full_dh_roundtrip` — if it passes, the
daemon's own DH is internally consistent. If the error still occurs with `secret-tool`,
use `dbus-monitor` to capture the raw public key bytes.

### `D-Bus Error: Name already owned`
Another process holds `org.freedesktop.secrets`:
```bash
busctl --user status org.freedesktop.secrets
pkill wss-daemon      # or stop gnome-keyring
```

### `wssp.sock already in use`
The daemon cleans up stale sockets on startup. If it still fails:
```bash
rm $XDG_RUNTIME_DIR/wssp.sock
```

### Prompter does not appear
- Check `WAYLAND_DISPLAY` is set
- Run `./target/debug/wss-prompter` directly to see GTK errors
- Check daemon log for the exact command it tried: look for `Spawned wss-prompter`
- Set `WSSP_PROMPTER_PATH` to an absolute path

### Vault decryption fails after a crash
If Argon2id parameters changed between builds, the derived key changes. Delete the vault
and start fresh:
```bash
rm -rf ~/.local/share/wssp/
```
