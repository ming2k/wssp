# How to Configure Vault Unlock

## Setup

### 1. Install the PAM module

```bash
cargo build --release -p wssp-pam
sudo cp target/release/libwssp_pam.so /lib/security/pam_wssp.so
```

### 2. Add to login PAM stack

| Distribution | File |
|---|---|
| Arch Linux | `/etc/pam.d/system-login` |
| Debian / Ubuntu | `/etc/pam.d/common-auth` |
| Fedora | `/etc/pam.d/login` |

```
auth optional pam_wssp.so
```

### 3. Add to swaylock PAM stack

```
# /etc/pam.d/swaylock
auth optional pam_wssp.so
```

### 4. Switch to no-password mode (if using FDE)

```bash
systemctl --user stop wssp-daemon.service
wssp-cli clear-password   # prompts for current vault password
systemctl --user start wssp-daemon.service
```

To revert to password mode:

```bash
systemctl --user stop wssp-daemon.service
wssp-cli set-password     # prompts for new password (confirmed)
systemctl --user start wssp-daemon.service
```

---

## Password Management

```bash
# Change vault password (password mode only)
# Stop the daemon first to avoid vault file conflicts.
systemctl --user stop wssp-daemon.service
wssp-cli change-password  # prompts for old password, then new password (confirmed)
systemctl --user start wssp-daemon.service

# Wipe all secrets and start over (irreversible)
wssp-cli reset
wssp-cli reset --force   # skip confirmation prompt
```

---

## Headless / IoT Deployments

Neither mode above applies to headless systems (no display, no PAM login session). Set the
vault password via environment variable:

```ini
# ~/.config/systemd/user/wssp-daemon.service [Service]
Environment="WSSP_PASSWORD=your_device_password"
```

The daemon detects the absence of `WAYLAND_DISPLAY` and `DISPLAY`, waits up to 30 seconds
for a display to appear, and falls back to this variable if none is found.
