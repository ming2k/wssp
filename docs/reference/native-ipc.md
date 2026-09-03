# Native IPC Protocol Reference

## Overview

The native IPC interface is a private, high-performance transport between `sigil` and trusted desktop session infrastructure (primarily `xdg-desktop-portal-aegis`).

## Socket Location

- **Default Path**: `$XDG_RUNTIME_DIR/sigil/native.sock`
- **Permissions**: Mode `0600` (restricted to current user)
- **Parent Directory**: Mode `0700`

## Transport & Framing

Communication occurs over a Unix Domain Socket with 4-byte big-endian length-prefixed JSON frames:

```text
+-------------------+-----------------------------------------+
| Length (4 bytes)  | Payload (JSON encoded UTF-8 bytes)      |
| uint32_be         |                                         |
+-------------------+-----------------------------------------+
```

Maximum frame size is bounded to 64 KiB for safety.

## Authentication (SO_PEERCRED)

Upon receiving a connection, `sigil` queries `getsockopt(SO_PEERCRED)` on Linux:
- The caller's effective UID MUST equal the daemon's effective UID.
- Unauthorized connections receive an `AccessDenied` response and are immediately closed.

## Protocol Messages

### Requests (`IpcRequest`)

```rust
pub enum IpcRequest {
    /// Retrieve / derive an application secret
    GetApplicationSecret {
        namespace: String,
        subject: String,
        purpose: String,
    },
    /// Query lock state
    GetLockStatus,
    /// Lock the vault and purge in-memory keys
    Lock,
    /// Ping daemon
    Ping,
}
```

### Responses (`IpcResponse`)

```rust
pub enum IpcResponse {
    /// 32-byte derived secret
    Secret(Vec<u8>),
    /// Current lock status (Locked, Unlocked, Uninitialized)
    LockStatus(LockState),
    /// Success with no return value
    Success,
    /// Operation blocked because vault is locked
    Locked,
    /// User cancelled prompt
    Cancelled,
    /// Access denied by daemon policy
    AccessDenied(String),
    /// Generic daemon error
    Error(String),
}
```
