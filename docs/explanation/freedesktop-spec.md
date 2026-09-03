# The Secret Service API Specification

`credentiald` is a provider for the [freedesktop.org Secret Service API](https://specifications.freedesktop.org/secret-service/latest/). This specification defines a standard D-Bus interface for securely storing and retrieving passwords and other secrets on Linux systems.

Implementing this specification involves several nuances, particularly around state management, asynchronous prompting, and cryptographic data exchange.

## 1. D-Bus Object Hierarchy

`credentiald` maps its internal state to the D-Bus object paths defined by the spec:

*   `/org/freedesktop/secrets`: The root `Service` object. Handles global operations like opening sessions, creating collections, and searching across all collections.
*   `/org/freedesktop/secrets/collection/<id>`: A `Collection` of secrets (conceptually similar to a "keyring" or a "folder"). The default collection is often aliased as `login`.
*   `/org/freedesktop/secrets/collection/<id>/<item_id>`: An `Item`. Represents a single credential (e.g., a username/password pair for a website), containing both queryable attributes and the encrypted secret payload.
*   `/org/freedesktop/secrets/session/s<id>`: A cryptographic `Session`.
*   `/org/freedesktop/secrets/prompt/p<id>`: A `Prompt` object used for asynchronous user interaction (like unlocking the vault).

## 2. The `Locked` Property and the Prompt Mechanic

A core concept in the API is that Collections and Items can be **Locked**.

### The `Locked` Property
The `org.freedesktop.Secret.Collection` and `org.freedesktop.Secret.Item` interfaces MUST expose a boolean `Locked` property.

Clients (like `go-keyring` or `libsecret`) check this property before attempting to read or write. If `Locked` is true, the client is expected to call the `Unlock` method on the `Service` object.

### The `Unlock` Flow
When a client calls `Service.Unlock`, the daemon must:
1.  Check if the requested objects are already unlocked. If so, return them immediately.
2.  If they are locked, the daemon returns an empty list of unlocked objects and the object path to a newly created `Prompt`.
3.  The client then subscribes to the `Completed` signal of that `Prompt` object.
4.  The daemon spawns an external UI (like `credentiald-prompter`) to ask the user for the master password.
5.  Once the UI returns the password and the daemon decrypts the vault, the daemon fires the `Completed` signal on the `Prompt` object, informing the client that the vault is now unlocked.

**Crucially:** Mutating methods (`CreateItem`, `Delete`, `SetSecret`) or reading the payload (`GetSecret`) must explicitly reject calls with an `org.freedesktop.Secret.Error.IsLocked` D-Bus error if the vault is locked. Silent failures will cause client libraries to behave unpredictably.

## 3. The D-Bus Signature Trap: `GetSecret`

D-Bus relies heavily on exact Type Signatures. A common pitfall in Rust `zbus` implementations occurs with the `Item.GetSecret` method.

According to the specification, `GetSecret` returns exactly ONE `OUT` parameter named `secret` of type `Secret`.

The `Secret` type in the spec is a struct with the signature `(oayays)`:
1.  `ObjectPath`: The session path.
2.  `Array of Byte`: DH Parameters (typically empty for AES).
3.  `Array of Byte`: The ciphertext of the secret payload.
4.  `String`: The content type (e.g., `text/plain`).

### The Rust Tuple Issue
If a Rust function is defined to return a tuple:
```rust
async fn get_secret(...) -> Result<(ObjectPath, Vec<u8>, Vec<u8>, String)>
```
The `zbus` macro expands this into **four separate OUT parameters** on the D-Bus, not a single struct. This violates the spec and causes strict clients (like Go's `dbus.Store`) to panic with `length mismatch` errors.

### The Solution
The data must be wrapped in a explicitly defined struct that implements `zbus::zvariant::Type` and enforces the struct signature:

```rust
#[derive(serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
#[zvariant(signature = "(oayays)")]
pub struct SecretStruct(pub OwnedObjectPath, pub Vec<u8>, pub Vec<u8>, pub String);
```
Returning `SecretStruct` ensures `zbus` packages the data as a single D-Bus Struct parameter, perfectly aligning with the Secret Service specification.

## 4. Cryptographic Sessions

To prevent secrets from being sniffed by other processes listening on the D-Bus session bus, the API requires an encrypted transit layer.

1.  **OpenSession**: The client calls `Service.OpenSession` proposing an algorithm (usually `dh-ietf1024-sha256-aes128-cbc-pkcs7`).
2.  **Key Exchange**: The client provides its Diffie-Hellman public key. The daemon generates its own DH keypair, computes the shared secret, and returns its public key.
3.  **Key Derivation**: `credentiald` and the client both use **HKDF-SHA256** (with no salt and empty info) to derive a 128-bit AES key from the DH shared secret. *(Note: The spec text says "SHA256", but the canonical `libsecret` implementation uses HKDF. Interoperability requires HKDF).*
4.  **Transit**: When `GetSecret` or `SetSecret` is called, the payload is AES-128-CBC encrypted (with PKCS#7 padding) using the derived session key.

This ensures that even if another application monitors the D-Bus socket, it only sees AES ciphertext, while the actual password remains secure.
