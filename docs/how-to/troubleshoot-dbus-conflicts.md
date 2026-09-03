# How to Troubleshoot D-Bus Name Conflicts

The well-known D-Bus name `org.freedesktop.secrets` may only have one owner per user session.
When something else has already claimed the name — or two activation files both try to claim
it — `credentiald.service` will not start, or the wrong binary will answer libsecret calls.

This guide walks through diagnosing and resolving the most common conflicts.

## Symptom: `credentiald.service` fails to load

```
systemctl --user status credentiald.service
# Loaded: error (Reason: Unit credentiald.service failed to load properly, ...: File exists)
# credentiald.service: Two services allocated for the same bus name org.freedesktop.secrets, refusing operation.
```

systemd refuses to load any `Type=dbus` unit if another loaded unit declares the same `BusName=`.

### 1. Find every systemd unit claiming the bus name

```bash
grep -rl 'BusName=org.freedesktop.secrets' \
  /usr/lib/systemd/user/ \
  /etc/systemd/user/ \
  ~/.config/systemd/user/ 2>/dev/null
```

Expected: exactly one path — `/usr/lib/systemd/user/credentiald.service` (or `~/.config/systemd/user/credentiald.service`). Anything else
(`wssp-daemon.service`, `gnome-keyring-secrets.service`, an old hand-edited copy in
`~/.config/systemd/user/`) is a conflict.

### 2. Disable and remove the conflicting units

```bash
systemctl --user disable --now <conflicting-unit>
rm ~/.config/systemd/user/<conflicting-unit>
systemctl --user daemon-reload
systemctl --user reset-failed <conflicting-unit>
```

### 3. Start credentiald and confirm

```bash
systemctl --user start credentiald.service
systemctl --user status credentiald.service   # should be active (running)
```

---

## Symptom: a different binary answers `org.freedesktop.secrets`

You expected `credentiald` to own the bus, but `secret-tool` is hitting gnome-keyring, an old
debug build, or a stale dev binary.

### 1. Identify the current owner

```bash
busctl --user status org.freedesktop.secrets | grep ^PID=
# PID=2526
ps -p 2526 -o pid,user,cmd --no-headers
# 2526 ming /usr/bin/credentiald
```

If the path is not `/usr/bin/credentiald` (or whatever you installed), something else launched it.

### 2. Find every D-Bus activation file claiming the bus name

```bash
grep -rl 'Name=org.freedesktop.secrets' \
  /usr/share/dbus-1/services/ \
  /usr/local/share/dbus-1/services/ \
  /etc/xdg/dbus-1/services/ \
  ~/.local/share/dbus-1/services/ 2>/dev/null
```

`credentiald` relies on systemd's `BusName=` activation. Any file you find from a prior dev workflow or a competing package is a
conflict.

### 3. Remove the activation file and kill the stale process

```bash
rm ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
kill <stale-pid>
systemctl --user daemon-reload
systemctl --user restart credentiald.service
```

### 4. Re-verify ownership

```bash
busctl --user status org.freedesktop.secrets | grep ^PID=
systemctl --user show credentiald.service --property=MainPID
# Both PIDs should match.
```

---

## Symptom: GNOME Keyring keeps coming back

The GNOME Keyring's Secret Service component is auto-started by `gnome-keyring-daemon`,
which is itself launched from the GNOME session, an XDG autostart entry, or PAM.

```bash
systemctl --user disable --now gnome-keyring-daemon.service
systemctl --user mask gnome-keyring-daemon.service

# XDG autostart
mkdir -p ~/.config/autostart
for f in /etc/xdg/autostart/gnome-keyring-*.desktop; do
  cp "$f" ~/.config/autostart/
  echo 'Hidden=true' >> ~/.config/autostart/"$(basename "$f")"
done

# PAM (Debian/Ubuntu typically)
# Comment out lines invoking pam_gnome_keyring.so in /etc/pam.d/common-{auth,session}
```

Log out and back in. Confirm with `busctl --user status org.freedesktop.secrets` that `credentiald`
now owns the name.

---

## Reference: what each conflict source looks like

| Source | Path | How it activates the daemon |
|---|---|---|
| credentiald systemd unit (intended) | `/usr/lib/systemd/user/credentiald.service` | systemd `Type=dbus` + `BusName=` |
| Stale dev D-Bus activation file | `~/.local/share/dbus-1/services/org.freedesktop.secrets.service` | dbus-daemon fork-execs the `Exec=` binary on first method call |
| Old hand-edited systemd unit | `~/.config/systemd/user/<anything>.service` with `BusName=org.freedesktop.secrets` | Same as the intended unit — only one is allowed |
| GNOME Keyring | `/usr/lib/systemd/user/gnome-keyring-daemon.service` + XDG autostart + PAM | Multiple paths; see above |
| KWallet | `/usr/share/dbus-1/services/org.kde.kwalletd5.service` | dbus-daemon activation |

See [../explanation/architecture.md](../explanation/architecture.md#service-activation) for
why `credentiald` uses systemd `BusName=` activation rather than a standalone `.service` file.
