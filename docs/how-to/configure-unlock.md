# How to Configure Vault Unlock

## Setup

### 1. Install the PAM module

```bash
cargo build --release -p credentiald-pam
sudo cp target/release/libpam_credentiald.so /lib/security/pam_credentiald.so
```

### 2. Add to login PAM stack

| Distribution | File |
|---|---|
| Arch Linux | `/etc/pam.d/system-login` |
| Debian / Ubuntu | `/etc/pam.d/common-auth` |
| Fedora | `/etc/pam.d/login` |

```
auth optional pam_credentiald.so
```

### 3. Add to swaylock PAM stack

```
# /etc/pam.d/swaylock
auth optional pam_credentiald.so
```

### 4. Switch to no-password mode (if using FDE)

```bash
systemctl --user stop credentiald.service
credentiald-cli clear-password   # prompts for current vault password
systemctl --user start credentiald.service
```

To revert to password mode:

```bash
systemctl --user stop credentiald.service
credentiald-cli set-password     # prompts for new password (confirmed)
systemctl --user start credentiald.service
```

---

## Password Management

```bash
# Change vault password (password mode only)
# Stop the daemon first to avoid vault file conflicts.
systemctl --user stop credentiald.service
credentiald-cli change-password  # prompts for old password, then new password (confirmed)
systemctl --user start credentiald.service

# Wipe all secrets and start over (irreversible)
credentiald-cli reset
credentiald-cli reset --force   # skip confirmation prompt
```

---

## Headless / IoT Deployments

Neither mode above applies to headless systems (no display, no PAM login session). Set the
vault password via environment variable:

```ini
# ~/.config/systemd/user/credentiald.service [Service]
Environment="CREDENTIALD_PASSWORD=your_device_password"
```

The daemon detects the absence of `WAYLAND_DISPLAY` and `DISPLAY`, waits up to 30 seconds
for a display to appear, and falls back to this variable if none is found.
