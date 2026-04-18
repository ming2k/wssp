# Changelog

All notable changes to this project will be documented in this file.

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
