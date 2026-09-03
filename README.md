# credentiald

`credentiald` is a cryptographically secure implementation of the
[`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/)
Secret Service API for modern Linux desktops. It is designed to be a
lightweight, headless-friendly drop-in replacement for gnome-keyring and KWallet.

## Key Features

- **Strong cryptography**: XChaCha20-Poly1305 (AEAD) at-rest encryption; Argon2id key
  derivation for password-protected vaults.
- **Secure transit**: Full DH key exchange (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) so
  secrets are never exposed in plaintext on the D-Bus wire.
- **Zero-friction unlock**: PAM module auto-unlocks the vault at login and re-unlocks after
  screensaver dismissal — no separate password prompt.
- **Two vault modes**: password-protected (recommended without FDE) or no-password/keyfile
  (recommended with full-disk encryption). See [docs/explanation/unlock-strategies.md](docs/explanation/unlock-strategies.md).
- **Headless support**: daemon runs without a display; secrets can be injected via
  `CREDENTIALD_PASSWORD` for IoT/server deployments.
- **Broad compatibility**: works with browsers (Chrome, Firefox), VS Code, `secret-tool`,
  and any application using `libsecret`.

## Quick Start

### 1. Build

```bash
cargo build --release
```

### 2. Pre-flight: free the `org.freedesktop.secrets` D-Bus name

Only one process can own `org.freedesktop.secrets` per session. Check who currently owns it
and disable any other Secret Service provider before installing `credentiald`:

```bash
busctl --user status org.freedesktop.secrets   # shows owning PID, or fails if no owner

# Disable common conflicting providers (run only the ones that apply to you):
systemctl --user disable --now gnome-keyring-daemon.service gcr-ssh-agent.socket 2>/dev/null
systemctl --user mask  gnome-keyring-daemon.service 2>/dev/null   # GNOME / login keyring
systemctl --user disable --now kwallet5.service kwalletd5.service 2>/dev/null

# Remove any stale per-user D-Bus activation file that points the bus name elsewhere:
rm -f ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
```

If you skip this step the `credentiald` systemd unit will fail to load with
*"Two services allocated for the same bus name org.freedesktop.secrets"*. See
[docs/how-to/troubleshoot-dbus-conflicts.md](docs/how-to/troubleshoot-dbus-conflicts.md).

### 3. Install binaries and service

```bash
sudo cp target/release/credentiald /usr/bin/
sudo cp target/release/credentiald-prompter /usr/bin/
sudo cp target/release/credentiald-cli /usr/bin/
mkdir -p ~/.config/systemd/user/
cp systemd/user/credentiald.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now credentiald.service
```

### 4. Verify the daemon is the one answering

```bash
# Owning PID should match credentiald.service MainPID:
busctl --user status org.freedesktop.secrets | grep ^PID=
systemctl --user show credentiald.service --property=MainPID

# Round-trip a secret to confirm libsecret clients reach credentiald:
secret-tool store --label=credentiald-smoke smoke yes <<< ok && \
  secret-tool lookup smoke yes && \
  secret-tool clear  smoke yes
```

On first start the daemon automatically initializes a no-password vault. If you want
password protection instead, stop the daemon and initialize explicitly:

```bash
systemctl --user stop credentiald.service
credentiald-cli init
systemctl --user start credentiald.service
```

### 5. PAM integration (optional)

**Purpose.** The PAM module exists for one reason: to remove the manual unlock prompt.
It captures your login password as PAM authenticates you, hands it to `credentiald`, and
the daemon derives the vault key from it. The same hook re-runs when you dismiss
`swaylock`, so the vault re-unlocks automatically after the screensaver.

**You do not need it if** any of the following holds:
- You run a no-password (keyfile) vault — the daemon unlocks itself at startup.
- You are happy to unlock manually via `credentiald-cli unlock` or the GUI prompter.
- You are deploying headless and set `CREDENTIALD_PASSWORD=` in the unit file.

**Install only if** you want zero-friction login + screensaver unlock for a
password-protected vault, and you accept that your login password is briefly written to
`/run/user/<uid>/credentiald-pam-token` (tmpfs, mode `0600`, deleted on read).

```bash
# Build and install the PAM module
sudo cp target/release/libpam_credentiald.so /lib/security/pam_credentiald.so

# Add to login PAM stack (Arch: /etc/pam.d/system-login)
echo "auth optional pam_credentiald.so" | sudo tee -a /etc/pam.d/system-login

# Add to swaylock for screensaver re-unlock
echo "auth optional pam_credentiald.so" | sudo tee -a /etc/pam.d/swaylock
```

For Debian/Ubuntu/Fedora PAM stack paths, no-password mode trade-offs, and headless setup,
see [docs/how-to/configure-unlock.md](docs/how-to/configure-unlock.md).

## Vault Management

```bash
credentiald-cli init                 # first-time setup with password (prompted)
credentiald-cli init --no-password   # first-time setup without password (requires FDE)
credentiald-cli unlock               # unlock active session
credentiald-cli change-password      # change password
credentiald-cli clear-password       # switch to no-password mode
credentiald-cli set-password         # switch from no-password to password mode
credentiald-cli reset                # wipe vault (irreversible)
```

## Security Model

| Layer | Mechanism |
|---|---|
| At rest | XChaCha20-Poly1305 with per-save random nonce |
| Key derivation | Argon2id (password mode) or OS-random keyfile (no-password mode) |
| In memory | `Zeroize` on drop for all structs holding secrets |
| In transit | AES-128-CBC over DH-negotiated session key |

See [SECURITY.md](SECURITY.md) for the full threat model and known limitations.

## Documentation

| Document | Contents |
|---|---|
| [docs/explanation/architecture.md](docs/explanation/architecture.md) | Component layout, data flows, D-Bus hierarchy |
| [docs/explanation/unlock-strategies.md](docs/explanation/unlock-strategies.md) | Vault modes, PAM setup, screensaver integration |
| [docs/explanation/freedesktop-spec.md](docs/explanation/freedesktop-spec.md) | Secret Service specification adherence |
| [docs/how-to/configure-unlock.md](docs/how-to/configure-unlock.md) | How to configure unlock methods |
| [docs/how-to/troubleshoot-dbus-conflicts.md](docs/how-to/troubleshoot-dbus-conflicts.md) | How to troubleshoot D-Bus conflicts |
| [docs/dev/setup.md](docs/dev/setup.md) | Developer setup and building |
| [docs/dev/development.md](docs/dev/development.md) | Build, test, debug, D-Bus inspection |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.
