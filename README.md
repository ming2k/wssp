# Wayland Secret Service Provider (WSSP)

WSSP is a high-performance, cryptographically secure, and headless Secret Service Provider (org.freedesktop.secrets) designed for modern Wayland-based Linux desktops and resource-constrained IoT/Ecological monitoring devices.

## Key Features
- **Industry Standard Cryptography**: XChaCha20-Poly1305 (AEAD) at-rest encryption and Argon2id key derivation.
- **Secure Transit**: Full support for Diffie-Hellman (dh-ietf1024-sha256-aes128-cbc-pkcs7) to prevent D-Bus eavesdropping.
- **Headless-First Architecture**: Decouples the crypto daemon from the UI, supporting zero-touch IoT deployment via environment variables.
- **Seamless Integration**: Fully compatible with browsers (Chrome/Firefox), VS Code, and standard tools (secret-tool).
- **Automatic Unlock**: Includes a native PAM module for secure login-time vault unlocking.

## Deployment Guide

### 1. Installation
Ensure you have the Rust toolchain installed. Build the workspace:
```bash
cargo build --release
```

### 2. Daemon Setup (systemd)
Copy the service unit file to your local systemd directory:
```bash
mkdir -p ~/.config/systemd/user/
cp systemd/user/wss-daemon.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now wss-daemon.service
```

### 3. Automatic Unlock (PAM Module)
To enable automatic unlocking upon system login:
1. Compile the PAM module: `cargo build --release -p wss-pam`.
2. Install the binary: `sudo cp target/release/libpam_wssp.so /lib/security/pam_wssp.so`.
3. Add to your PAM configuration (e.g., `/etc/pam.d/login`):
   ```text
   auth optional pam_wssp.so
   ```

## Security Model
- **At-Rest**: Encrypted using unique nonces for every save.
- **In-Memory**: Sensitive structs utilize `Zeroize` to wipe memory on drop.
- **Transit**: Secrets are encrypted over D-Bus during transmission.

## Contributing
Please read [CONTRIBUTING.md](./docs/contributing.md) before submitting Pull Requests.
