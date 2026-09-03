# Developer & Contributor Guide

This section covers developer workflows, architecture requirements, and code standards for `credentiald`.

## Getting Started

### Building the Workspace

`credentiald` requires a standard Rust toolchain (2021 edition):

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

## Architectural Rules

1. `credential-core` MUST NOT depend on D-Bus, Tokio, SQLite, or UI frameworks.
2. All secret-bearing data MUST use `SecretBytes` or `MasterKey` with `Zeroize` and `ZeroizeOnDrop`.
3. Secret Service and Portal adapters MUST NOT access database files directly.
4. Security boundaries MUST be compiler-enforced via crate boundaries.
5. All new documentation MUST adhere to the governance rules in `docs/governance/documentation/`.
