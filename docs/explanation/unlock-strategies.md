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
