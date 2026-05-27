# Developer Setup

This guide will walk you through setting up your local environment to develop, compile, and run WSSP.

## 1. Prerequisites

### System Libraries (Debian/Ubuntu)
WSSP relies on D-Bus for IPC, and GTK4/Libadwaita for the prompter UI.
```bash
sudo apt update
sudo apt install libgtk-4-dev libadwaita-1-dev libdbus-1-dev pkg-config
```

### Useful Debugging Tools
To manually interact with the D-Bus daemon and monitor messages:
```bash
sudo apt install busctl secret-tool d-feet dbus-monitor
```

### Rust Toolchain
Ensure you have the latest stable Rust toolchain installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable
```

## 2. Building the Project

WSSP is organized as a Cargo workspace. You can build all components at once or focus on the daemon for faster iteration.

```bash
# Build the entire workspace (daemon, cli, prompter, pam, core, common)
cargo build

# Build only the daemon (useful when working on core logic)
cargo build -p wssp-daemon
```

## 3. Running the Daemon for Development

The daemon registers the well-known D-Bus name `org.freedesktop.secrets`. If you are running a desktop environment (like GNOME or KDE), you likely already have `gnome-keyring` or `kwallet` running, which will conflict.

### Approach A: Isolated D-Bus Session (Recommended)
This approach is perfect for testing how third-party applications (like `agy cli`, Chrome, or VS Code) interact with WSSP. It creates a "sandbox" D-Bus, ensuring your tests don't pollute your real system passwords, and your system's keyring doesn't intercept the test app.

**Terminal 1 (The Sandbox Daemon):**
```bash
# 1. Start a throw-away session bus and export its address
eval $(dbus-launch --sh-syntax)
echo "Session bus: $DBUS_SESSION_BUS_ADDRESS"

# 2. Run the daemon in this shell
RUST_LOG=debug cargo run -p wssp-daemon
```

**Terminal 2 (The 3rd-Party App):**
```bash
# 1. Export the EXACT SAME address printed in Terminal 1
export DBUS_SESSION_BUS_ADDRESS="unix:abstract=/tmp/dbus-...,guid=..."

# 2. Run your third-party application. It will now talk EXCLUSIVELY to your dev daemon.
# For example:
agy cli auth login
```

### Approach B: Replacing your Desktop Keyring
If you want to test the full PAM/UI flow in your actual session:

```bash
# Kill the existing secret service
pkill gnome-keyring-daemon || pkill kwalletd5

# Run WSSP with the prompter path explicitly provided so the UI works
WSSP_PROMPTER_PATH=./target/debug/wssp-prompter RUST_LOG=debug cargo run -p wssp-daemon
```

## 4. Key Environment Variables

| Variable | Effect |
|----------|--------|
| `RUST_LOG` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace`. Setting `RUST_LOG=debug` is highly recommended for development. |
| `WSSP_PROMPTER_PATH` | Absolute or relative path to the compiled `wssp-prompter` binary. Required for the daemon to spawn the unlock UI. |
| `WSSP_PASSWORD` | Used for headless/IoT testing. Skips the GUI prompt when `WAYLAND_DISPLAY` and `DISPLAY` are both unset. |

## 5. Next Steps

- For testing cryptographic logic or D-Bus interactions, see the testing section in `docs/dev/development.md`.
- To understand the D-Bus API implementation details, read `docs/explanation/freedesktop-spec.md`.
