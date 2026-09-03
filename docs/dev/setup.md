# Developer Setup

This guide will walk you through setting up your local environment to develop, compile, and run `credentiald`.

## 1. Prerequisites

### System Libraries

`credentiald` relies on D-Bus for IPC, GTK4 / Libadwaita for the prompter UI, and PAM for the
auto-unlock module.

| Distribution | Install command |
|---|---|
| Debian / Ubuntu | `sudo apt install libgtk-4-dev libadwaita-1-dev libdbus-1-dev libpam0g-dev pkg-config` |
| Arch Linux | `sudo pacman -S gtk4 libadwaita dbus pam pkgconf` |
| Fedora | `sudo dnf install gtk4-devel libadwaita-devel dbus-devel pam-devel pkgconf` |

### Useful Debugging Tools

To manually interact with the D-Bus daemon and monitor messages:

| Distribution | Install command |
|---|---|
| Debian / Ubuntu | `sudo apt install systemd libsecret-tools d-feet dbus-monitor` |
| Arch Linux | `sudo pacman -S systemd libsecret d-feet` |
| Fedora | `sudo dnf install systemd libsecret d-feet dbus-tools` |

`busctl` ships with systemd; `secret-tool` ships with libsecret.

### Rust Toolchain
Ensure you have the latest stable Rust toolchain installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable
```

## 2. Building the Project

`credentiald` is organized as a Cargo workspace. You can build all components at once or focus on the daemon for faster iteration.

```bash
# Build the entire workspace (daemon, cli, prompter, pam, core, common)
cargo build

# Build only the daemon (useful when working on core logic)
cargo build -p credentiald
```

## 3. Running the Daemon for Development

The daemon registers the well-known D-Bus name `org.freedesktop.secrets`. Only one process
per session can own this name, so before either approach below you must stop **every**
existing owner — `gnome-keyring`, `kwallet`, *and* an installed `credentiald.service`:

```bash
systemctl --user stop credentiald.service 2>/dev/null
pkill -x gnome-keyring-daemon 2>/dev/null
pkill -x kwalletd5 2>/dev/null
busctl --user status org.freedesktop.secrets 2>&1 | grep -q PID= && \
  echo "WARNING: something still owns the bus name — find and kill it"
```

For diagnosing why something keeps re-acquiring the name, see
[../how-to/troubleshoot-dbus-conflicts.md](../how-to/troubleshoot-dbus-conflicts.md).

### Approach A: Isolated D-Bus Session (Recommended)
This approach is perfect for testing how third-party applications (like `agy cli`, Chrome, or VS Code) interact with `credentiald`. It creates a "sandbox" D-Bus, ensuring your tests don't pollute your real system passwords, and your system's keyring doesn't intercept the test app.

**Terminal 1 (The Sandbox Daemon):**
```bash
# 1. Start a throw-away session bus and export its address
eval $(dbus-launch --sh-syntax)
echo "Session bus: $DBUS_SESSION_BUS_ADDRESS"

# 2. Run the daemon in this shell
RUST_LOG=debug cargo run -p credentiald
```

**Terminal 2 (The 3rd-Party App):**
```bash
# 1. Export the EXACT SAME address printed in Terminal 1
export DBUS_SESSION_BUS_ADDRESS="unix:abstract=/tmp/dbus-...,guid=..."

# 2. Run your third-party application. It will now talk EXCLUSIVELY to your dev daemon.
# For example:
secret-tool store --label="Test Secret" test test
```

### Approach B: Replacing your Desktop Keyring
If you want to test the full PAM/UI flow in your actual session:

```bash
# Kill the existing secret service
pkill gnome-keyring-daemon || pkill kwalletd5

# Run credentiald with the prompter path explicitly provided so the UI works
CREDENTIALD_PROMPTER_PATH=./target/debug/credentiald-prompter RUST_LOG=debug cargo run -p credentiald
```

## 4. Key Environment Variables

| Variable | Effect |
|----------|--------|
| `RUST_LOG` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace`. Setting `RUST_LOG=debug` is highly recommended for development. |
| `CREDENTIALD_PROMPTER_PATH` | Absolute or relative path to the compiled `credentiald-prompter` binary. Required for the daemon to spawn the unlock UI. |
| `CREDENTIALD_PASSWORD` | Used for headless/IoT testing. Skips the GUI prompt when `WAYLAND_DISPLAY` and `DISPLAY` are both unset. |

## 5. Cleanup After a Dev Session

Two artifacts from typical dev workflows commonly leak into your production session and
silently take over `org.freedesktop.secrets` on next login. Remove them before you log out
of the dev session:

```bash
# 1. Per-user D-Bus activation file pointing at target/{debug,release}/.
#    credentiald itself never creates this; if you created one to test third-party apps without
#    setting DBUS_SESSION_BUS_ADDRESS, remove it now.
rm -f ~/.local/share/dbus-1/services/org.freedesktop.secrets.service

# 2. Any hand-installed user-level systemd unit shadowing the packaged one.
ls ~/.config/systemd/user/*.service 2>/dev/null | xargs -r grep -l 'BusName=org.freedesktop.secrets'
# If anything is listed, disable + remove it, then daemon-reload.

# 3. Purge stale build artifacts:
cargo clean
```

A full diagnostic procedure for "the wrong binary is answering" is in
[../how-to/troubleshoot-dbus-conflicts.md](../how-to/troubleshoot-dbus-conflicts.md).

## 6. Running the Test Suite

```bash
# Unit tests across the workspace
cargo test

# Single crate (faster iteration on cryptography or D-Bus serialization)
cargo test -p credentiald-core
cargo test -p credentiald
```

End-to-end D-Bus testing is currently done manually with `busctl`, `secret-tool`, and
`dbus-monitor` against an isolated session bus — see `docs/dev/development.md` for the
recipes.

## 7. Next Steps

- Testing strategy and D-Bus debugging recipes: `docs/dev/development.md`.
- D-Bus API implementation details and spec compliance: `docs/explanation/freedesktop-spec.md`.
- Component layout and service-activation rationale: `docs/explanation/architecture.md`.
