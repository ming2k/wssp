# Changelog

All notable changes to this project will be documented in this file.

## [1.0.3] - 2026-04-18

### Fixed
- Fixed issue where `wss-prompter` was not triggered due to overly restrictive systemd hardening (`ProtectSystem=strict` and missing `ReadWritePaths`).

## [1.0.2] - 2026-04-18

### Fixed
- Fixed missing `debug` macro imports in `wss-daemon`.

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
