# Developer & Contributor Guide

This section covers developer workflows, architecture requirements, and code standards for `sigil`.

## Getting Started

### Building the Workspace

`sigil` requires a standard Rust toolchain (2021 edition):

```bash
cargo build --workspace
```

### Running Tests

Run all unit and integration test suites:

```bash
cargo test --workspace
```

### Formatting & Linting

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
```

## Developer Guides

| Guide | Purpose |
|---|---|
| [Developer Setup](setup.md) | System dependencies, build commands, and pre-flight cleanup |
| [Development Guide](development.md) | Day-to-day daemon testing, D-Bus commands, and PAM workflow |
| [Worktree & Cross-Repository Development](cross-repository-development.md) | Linked Git worktree workflow, cache isolation, and desktop integration |
| [Coding Conventions](conventions.md) | Rust style, error handling, sensitive data handling, and commit conventions |

## Architectural Rules

1. `sigil-core` MUST NOT depend on D-Bus, Tokio, SQLite, or UI frameworks.
2. All secret-bearing data MUST use `SecretBytes` or `MasterKey` with `Zeroize` and `ZeroizeOnDrop`.
3. Secret Service and Portal adapters MUST NOT access database files directly.
4. Security boundaries MUST be compiler-enforced via crate boundaries.
5. All new documentation MUST adhere to the governance rules in `docs/governance/documentation/`.
