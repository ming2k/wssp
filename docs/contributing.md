# Contributing to WSSP

## Reporting Issues

Open a GitHub issue with:
- Steps to reproduce
- Expected vs. actual behavior
- Environment: compositor, distro, Rust version (`rustc --version`), libsecret version

For security vulnerabilities, do **not** open a public issue. Contact the maintainer directly.

## Development Setup

See [Development Guide](./development.md) for build instructions and debugging tools.

## Submitting a Pull Request

1. Fork the repository and create a branch:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Make your changes following [Coding Conventions](./conventions.md).
3. Run the full check suite before pushing:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
4. Push and open a PR against `main`.

## PR Guidelines

**Scope**: one logical change per PR. A new D-Bus method and a UI change belong in separate PRs.

**Tests**: for any new logic in `session.rs` or `vault.rs`, add a unit test. The existing
`session::tests::full_dh_roundtrip` is the model for cryptographic tests.

**Security-sensitive files**: changes to the files below require careful review of the
cryptographic correctness and memory-safety implications:

| File | What to verify |
|------|---------------|
| `wss-daemon/src/session.rs` | HKDF parameters, AES key zeroization, DH validation |
| `wss-core/src/vault.rs` | Nonce uniqueness, Argon2 parameters, zeroize on drop |
| `wss-daemon/src/ipc.rs` | Socket permissions, timeout handling |
| `wss-pam/src/lib.rs` | File permissions (0600), ownership, prompt delete-on-read |

**Documentation**: if you change a data flow, update `docs/architecture.md`. If you change a
cryptographic primitive, update `docs/security.md`.

## What We Welcome

- Bug fixes with reproduction steps
- Completing the `org.freedesktop.portal.Secret` implementation (write master key to fd)
- Implementing `Service.Lock()` (evict decrypted secrets from memory)
- `mlock` support to prevent secret pages from being swapped
- Integration tests using a real libsecret client

## Code of Conduct

Be respectful and constructive. Harassment or abusive behavior will not be tolerated.
