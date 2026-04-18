# Wayland Secret Service Provider (WSSP)

WSSP is a cryptographically secure implementation of the
[`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/)
Secret Service API for modern Wayland-based Linux desktops. It is designed to be a
lightweight, headless-friendly drop-in replacement for gnome-keyring and KWallet.

## Key Features

- **Strong cryptography**: XChaCha20-Poly1305 (AEAD) at-rest encryption; Argon2id key
  derivation for password-protected vaults.
- **Secure transit**: Full DH key exchange (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) so
  secrets are never exposed in plaintext on the D-Bus wire.
- **Zero-friction unlock**: PAM module auto-unlocks the vault at login and re-unlocks after
  screensaver dismissal — no separate password prompt.
- **Two vault modes**: password-protected (recommended without FDE) or no-password/keyfile
  (recommended with full-disk encryption). See [docs/unlock-strategies.md](docs/unlock-strategies.md).
- **Headless support**: daemon runs without a display; secrets can be injected via
  `WSSP_PASSWORD` for IoT/server deployments.
- **Broad compatibility**: works with browsers (Chrome, Firefox), VS Code, `secret-tool`,
  and any application using `libsecret`.

## Quick Start

### 1. Build

```bash
cargo build --release
```

### 2. Install binaries and service

```bash
sudo cp target/release/wssp-daemon /usr/bin/
sudo cp target/release/wssp-prompter /usr/bin/
sudo cp target/release/wssp-cli /usr/bin/
mkdir -p ~/.config/systemd/user/
cp systemd/user/wssp-daemon.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now wssp-daemon.service
```

On first start the daemon automatically initializes a no-password vault. If you want
password protection instead, stop the daemon and initialize explicitly:

```bash
systemctl --user stop wssp-daemon.service
wssp-cli init <your-password>
systemctl --user start wssp-daemon.service
```

### 3. PAM integration (recommended)

Enables automatic unlock at login and re-unlock after screensaver dismissal.

```bash
# Build and install the PAM module
sudo cp target/release/libwssp_pam.so /lib/security/pam_wssp.so

# Add to login PAM stack (Arch: /etc/pam.d/system-login)
echo "auth optional pam_wssp.so" | sudo tee -a /etc/pam.d/system-login

# Add to swaylock for screensaver re-unlock
echo "auth optional pam_wssp.so" | sudo tee -a /etc/pam.d/swaylock
```

See [docs/unlock-strategies.md](docs/unlock-strategies.md) for the full setup guide and
security trade-offs.

## Vault Management

```bash
wssp-cli init <password>          # first-time setup with password
wssp-cli init --no-password       # first-time setup without password (requires FDE)
wssp-cli change-password <old> <new>
wssp-cli clear-password <current> # switch to no-password mode
wssp-cli set-password <new>       # switch from no-password to password mode
wssp-cli reset                    # wipe vault (irreversible)
```

## Security Model

| Layer | Mechanism |
|---|---|
| At rest | XChaCha20-Poly1305 with per-save random nonce |
| Key derivation | Argon2id (password mode) or OS-random keyfile (no-password mode) |
| In memory | `Zeroize` on drop for all structs holding secrets |
| In transit | AES-128-CBC over DH-negotiated session key |

See [docs/security.md](docs/security.md) for the full threat model and known limitations.

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Component layout, data flows, D-Bus hierarchy |
| [docs/unlock-strategies.md](docs/unlock-strategies.md) | Vault modes, PAM setup, screensaver integration |
| [docs/security.md](docs/security.md) | Threat model, cryptography details, known limitations |
| [docs/development.md](docs/development.md) | Build, test, debug, D-Bus inspection |
| [docs/contributing.md](docs/contributing.md) | Contribution guidelines |

## Contributing

Please read [docs/contributing.md](docs/contributing.md) before submitting pull requests.
