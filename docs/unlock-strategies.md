# Vault Unlock Strategies

WSSP offers two vault protection modes and two unlock mechanisms. Choose based on your
disk encryption setup and tolerance for friction.

---

## Two Vault Protection Modes

### Password Mode

The vault is encrypted with a key derived from a password via Argon2id. Without the password,
the vault file (`vault.enc`) cannot be decrypted — even if an attacker has physical access to
the disk.

**When it matters**: the password protects against disk theft when there is no full-disk
encryption (FDE).

### No-Password Mode (keyfile)

The vault is encrypted with a randomly generated 256-bit key stored in `vault.key` (mode
`0600`) alongside the vault file. No password is ever entered. The only protection is OS
file permissions.

**Practical implication**: if an attacker gets your disk, they get both `vault.enc` and
`vault.key` and can decrypt the vault immediately. The vault is only as secure as your
filesystem.

**When it is safe**: when full-disk encryption (LUKS or equivalent) is active. LUKS
encrypts the entire disk — an attacker cannot read `vault.key` without the LUKS passphrase,
so the vault remains protected. WSSP's own encryption becomes a redundant inner layer that
adds friction with no security benefit.

---

## Recommendation

```
Have full-disk encryption (LUKS)?
  YES → use no-password mode  (zero friction, security comes from FDE)
  NO  → use password mode     (vault password = login password via PAM)
```

This matches how GNOME Keyring works: the "login" keyring uses the login password as the key,
but users on encrypted disks often set no separate keyring password and rely on FDE instead.
SSH private keys without passphrases follow the same logic.

---

## Unlock Mechanisms

Regardless of which protection mode you use, WSSP unlocks the vault automatically — no
separate prompt is needed. Two mechanisms work together:

### A — PAM (login-time unlock)

`pam_wssp.so` intercepts the authentication token during login and writes it to a temporary
file. The daemon reads it at startup and unlocks.

- **Password mode**: the token content is used to derive the vault key.
- **No-password mode**: the token is used only as a signal that login succeeded; the actual
  key comes from `vault.key`.

### B — Screensaver integration (swaylock)

Add `pam_wssp.so` to swaylock's PAM stack so the daemon re-unlocks automatically when the
screensaver is dismissed.

Lock → vault locks (logind `Session.Lock` signal).
Unlock → swaylock writes PAM token → daemon detects it via inotify → re-unlocks.

---

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
wssp-cli clear-password <current-vault-password>
systemctl --user start wssp-daemon.service
```

To revert to password mode:

```bash
systemctl --user stop wssp-daemon.service
wssp-cli set-password <new-password>
systemctl --user start wssp-daemon.service
```

---

## Password Management

```bash
# Change vault password (password mode only)
# Stop the daemon first to avoid vault file conflicts.
systemctl --user stop wssp-daemon.service
wssp-cli change-password <old> <new>
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
