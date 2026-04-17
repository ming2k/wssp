# Changelog

All notable changes to this project will be documented in this file.

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
