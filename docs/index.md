# credentiald Documentation

Welcome to the `credentiald` documentation. `credentiald` is a desktop credential infrastructure daemon implemented in Rust. It provides a freedesktop.org Secret Service API implementation and a native IPC interface for trusted desktop components such as Portal backends.

## Documentation Navigation

```text
docs/
├── explanation/       # Architecture, threat model, cryptographic concepts
├── how-to/            # Task-oriented step-by-step guides
├── reference/         # Native IPC protocol, storage formats, CLI specifications
├── dev/               # Contributor and development documentation
└── governance/        # Documentation and project governance
```

### Explanations

- [Architecture Overview](explanation/architecture.md): System decomposition, crate boundaries, and design principles.
- [Threat Model](explanation/threat-model.md): Trust boundaries, security claims, and non-claims.
- [Freedesktop Specifications](explanation/freedesktop-spec.md): Secret Service API and Portal Secret integration.
- [Unlock Strategies](explanation/unlock-strategies.md): Keyfile, PAM automatic unlock, and UI prompting.

### How-To Guides

- [Configure Unlock Strategies](how-to/configure-unlock.md): Setting up keyfile, PAM, and prompter modes.
- [Troubleshoot D-Bus Conflicts](how-to/troubleshoot-dbus-conflicts.md): Handling coexistence with GNOME Keyring or KeePassXC.

### References

- [Native IPC Specification](reference/native-ipc.md): Unix socket framing, protocol payloads, and peer authentication.
- [Storage Format](reference/storage-format.md): Encrypted vault format, Argon2id KDF sidecar, and permission invariants.
- [CLI Reference](reference/cli.md): `credentiald-cli` command reference.

### Governance & Development

- [Documentation Governance](governance/documentation/index.md): Style guide, update checklists, and review standards.
- [Development Guide](dev/index.md): Building, running tests, and contributing.
