# Changelog

All notable changes to this project will be documented in this file.

## [1.2.1] - 2026-09-05

- Migrated `sigil-prompter` to native Optics (iris/lens) stack, completely removing GTK4 and Libadwaita dependencies.
- Updated Optics stack dependencies to v0.0.34.

## [1.2.0] - 2026-09-04

### Changed
- **Project renamed to `sigil`**:
  - Workspace crates renamed: `sigil`, `sigil-core`, `sigil-crypto`, `sigil-store`, `sigil-service`, `sigil-ipc`, `sigil-client`, `sigil-secret-service`, `sigil-cli`, `sigil-prompter`, `sigil-pam`. Public types renamed (`SigilError`, `SigilClient`, `SigilService`); domain types (`CredentialId`, `MasterKey`, `SecretBytes`, etc.) unchanged.
  - Daemon binary and systemd unit renamed to `sigil` / `sigil.service`.
  - PAM module artifact renamed to `pam_sigil.so` (token path `/run/user/<uid>/sigil-pam-token`).
  - Prompter GTK application ID updated to `org.sigil.Prompter`.
  - Runtime paths changed (`~/.local/share/sigil`, `$XDG_RUNTIME_DIR/sigil/native.sock`) and environment variable prefix changed to `SIGIL_` (`SIGIL_DATA_DIR`, `SIGIL_SOCKET_PATH`, `SIGIL_PROMPTER_PATH`, `SIGIL_PASSWORD`). **Breaking**: no automatic migration of existing vaults or env vars.
  - Documentation, CI release workflow, DBus/systemd service files updated. Wire-protocol contracts preserved unchanged (`aegis.portal.Secret/v1` namespace, `org.freedesktop.secrets` bus name).

## [1.1.4] - 2026-08-24

### Security & Hardening
- **Crash-safe atomic persistence**: Implemented `atomic_replace` with tempfile sync, atomic rename, and directory fsync across vault operations.
- **Argon2id KDF parameter persistence**: Persist explicit Argon2id parameters in `vault.kdf` sidecar with legacy migration and crash fallback.
- **In-memory secret protection**: Applied `mlock` and `MADV_DONTDUMP` to sensitive master key buffers in `wssp-core` and secure zeroization on drop.
- **Two-phase staged re-keying**: Introduced `.next` staging protocol in `wssp-cli` for crash-resilient password changes and mode transitions.
- **Interactive credential zeroization**: Ensured CLI interactive password buffers are zeroized immediately after prompt completion.
- **Session lock eviction**: Daemon now clears in-memory item secrets and locks the vault upon receiving `org.freedesktop.login1.Session` `Lock` signals.
- **Per-application secret derivation**: Implemented per-app HKDF secret derivation for xdg-desktop-portal Secret isolation.
- **PAM lifecycle hardening**: Moved unlock token planting to `pam_sm_setcred` / `pam_sm_open_session` for reliable session initialization.
- **D-Bus service activation**: Added standard D-Bus session activation configuration (`org.freedesktop.secrets.service`).

## [1.1.3] - 2026-06-19

### Fixed
- **`CreateItem` missing replace logic**: `CreateItem` now correctly honors the `replace` argument. If `replace` is true, existing items with the same attributes are deleted before inserting the new item. This prevents token accumulation in the vault.
- **`SearchItems` double array bug**: Fixed an issue where `Service::SearchItems` cloned identical matching items into both the unlocked and locked returned D-Bus arrays, violating the DBus Secret Service Spec.
- **Removed dead code**: Removed an unnecessary return statement in `wssp-cli/src/main.rs`.

## [1.1.2] - 2026-05-27

### Fixed
- **`Item.GetSecret` D-Bus signature**: zbus 5.x was flattening the returned `SecretStruct`
  into four separate OUT args (`oayays`) instead of one struct OUT arg (`(oayays)`), causing
  libsecret/`secret-tool` to reject the reply (`returned (oayays), expected ((oayays))`) and
  godbus-based clients to fail with `dbus.Store: length mismatch`. Third-party apps fell back
  to file storage and lost their tokens across restarts. Wrapped the return in a 1-tuple
  `(SecretStruct,)` so zbus emits a single struct OUT arg per the Secret Service spec.
- **Vault locking enforcement**: `is_unlocked` is now checked on all mutating operations
  (`create_collection`, `create_item`, `delete`, `set_secret`) and reads (`get_secret`,
  `delete`) to prevent silent data loss or unauthorized access while locked.
- **`sync_to_vault`** now returns early with a warning if called while locked or with no
  vault present, instead of writing partial state.
- **`Item.SetSecret`** now decrypts the incoming D-Bus `Secret` ciphertext before storing
  it in memory; previously the encrypted bytes were saved verbatim, corrupting the secret.
- **`Item.GetSecrets`** (batch read) now serializes secrets via `SecretStruct` so the map
  values have the correct `(oayays)` struct signature.

### Added
- Required `Locked` property on the D-Bus `Collection` and `Item` interfaces, per the
  freedesktop Secret Service spec.

## [1.1.1] - 2026-04-18

### Security
- **Interactive password input**: all `wssp-cli` commands that accept a password now prompt
  interactively with hidden input (`rpassword`) instead of reading from command-line arguments.
  Passwords no longer appear in shell history or `ps` output. Affected commands: `init`,
  `unlock`, `change-password`, `clear-password`, `set-password`.
- New password commands (`init`, `change-password`, `set-password`) now require confirmation
  before accepting a new password.

## [1.1.0] - 2026-04-18

### Added
- **No-password mode**: vault can now be initialized with a randomly generated keyfile
  (`vault.key`) instead of a user-supplied password. Recommended when full-disk encryption
  (LUKS) is active — FDE provides the actual protection, eliminating double-password friction.
- **Screensaver integration**: daemon now locks the vault on `org.freedesktop.login1.Session`
  `Lock` signal (screen lock) and re-unlocks automatically via inotify when the PAM token
  file is written by swaylock on screensaver dismissal.
- **`wssp-cli init`**: first-time vault initialization from the command line, supporting both
  `init <password>` (password mode) and `init --no-password` (keyfile mode).
- **`wssp-cli change-password`**: change the vault master password without losing secrets.
- **`wssp-cli clear-password`**: migrate an existing password-protected vault to no-password
  (keyfile) mode.
- **`wssp-cli set-password`**: migrate a keyfile-mode vault back to password mode.
- **`wssp-cli reset`**: wipe all vault files and start over, with `--force` flag to skip
  the confirmation prompt.
- **Auto-init on first run**: daemon automatically initializes a no-password vault on first
  startup if no vault exists — no manual setup or prompter interaction required.
- **Boot-time display retry**: daemon waits up to 30 seconds for `WAYLAND_DISPLAY` to appear
  before concluding the environment is headless, fixing unlock failures on early-boot service
  starts.
- `XDG_SESSION_ID` added to systemd `PassEnvironment` for reliable logind session lookup.

### Changed
- **Renamed all components** from `wss-*` to `wssp-*` to match the project name:
  `wssp-daemon`, `wssp-prompter`, `wssp-cli`, `wssp-pam`, `wssp-core`, `wssp-common`.
  Binaries, crate names, systemd service file, and all internal references updated.
- **Prompter responsibility reduced**: `wssp-prompter` is now a pure unlock dialog only.
  The "create vault" / `WSSP_PROMPT_MODE=create` flow has been removed; first-time vault
  initialization is handled by the daemon (auto-init) or `wssp-cli init`.
- `service.rs` unlock path no longer distinguishes `is_initial`; the daemon never creates a
  new vault through the prompter flow.
- systemd service now declares `After=graphical-session.target` for correct startup ordering.

### Fixed
- Prompter no longer silently ignores an empty password submission — an inline error label
  is shown instead, and the input field regains focus automatically on correction.

## [1.0.3] - 2026-04-18

### Fixed
- Fixed issue where `wssp-prompter` was not triggered due to overly restrictive systemd hardening (`ProtectSystem=strict` and missing `ReadWritePaths`).

## [1.0.2] - 2026-04-18

### Fixed
- Fixed missing `debug` macro imports in `wssp-daemon`.

## [1.0.1] - 2026-04-18 [YANKED]

### Fixed
- Fixed "swallowed keys" issue in the prompter by ensuring proper window focus and input field activation.
- Made prompter window modal and set default button for better user experience.

### Changed
- Reduced log noise by removing `[NATIVE]` and `[PORTAL]` prefixes.
- Downgraded internal D-Bus operation logs from `info` to `debug` level.

## [1.0.0] - 2026-04-18

### Added
- Initial release of WSSP (Web Secret Service Provider).
- Full implementation of `org.freedesktop.secrets` (Secret Service API).
- Native support for Flatpak via `org.freedesktop.impl.portal.Secret` implementation.
- Asynchronous secret transfer via file descriptors for enhanced security.
- Systemd user service integration.
- PAM module for automatic vault unlocking on login.
- Architecture for headless and Wayland-based desktop environments.
- Monorepo structure containing daemon, CLI, prompter, and common libraries.
