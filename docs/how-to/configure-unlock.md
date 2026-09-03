# How to Configure Vault Unlock

## Setup

### 1. Install the PAM module

```bash
cargo build --release -p sigil-pam
sudo cp target/release/libpam_sigil.so /lib/security/pam_sigil.so
```

### 2. Add to login PAM stack

| Distribution | File |
|---|---|
| Arch Linux | `/etc/pam.d/system-login` |
| Debian / Ubuntu | `/etc/pam.d/common-auth` |
| Fedora | `/etc/pam.d/login` |

```
auth optional pam_sigil.so
```

### 3. Add to swaylock PAM stack

```
# /etc/pam.d/swaylock
auth optional pam_sigil.so
```

### 4. Switch to no-password mode (if using FDE)

```bash
systemctl --user stop sigil.service
sigil-cli clear-password   # prompts for current vault password
systemctl --user start sigil.service
```

To revert to password mode:

```bash
systemctl --user stop sigil.service
sigil-cli set-password     # prompts for new password (confirmed)
systemctl --user start sigil.service
```

---

## Password Management

```bash
# Change vault password (password mode only)
# Stop the daemon first to avoid vault file conflicts.
systemctl --user stop sigil.service
sigil-cli change-password  # prompts for old password, then new password (confirmed)
systemctl --user start sigil.service

# Wipe all secrets and start over (irreversible)
sigil-cli reset
sigil-cli reset --force   # skip confirmation prompt
```

---

## Headless / IoT Deployments

Neither mode above applies to headless systems (no display, no PAM login session). Set the
vault password via environment variable:

```ini
# ~/.config/systemd/user/sigil.service [Service]
Environment="SIGIL_PASSWORD=your_device_password"
```

The daemon detects the absence of `WAYLAND_DISPLAY` and `DISPLAY`, waits up to 30 seconds
for a display to appear, and falls back to this variable if none is found.
