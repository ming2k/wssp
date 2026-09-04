# Worktree and Cross-Repository Development

Use a long-lived linked Git worktree for Sigil development and cross-repository
desktop integration. The primary Sigil worktree remains on `main` as the
canonical checkout for clean verification and releases. The development
worktree normally remains on the long-lived local `dev` branch for daily
feature development, debugging, and integration testing.

## Dependency and Execution Modes

| Concern | Primary worktree (`sigil`) | Development worktree (`sigil-dev`) |
|---------|----------------------------|------------------------------------|
| Branch | `main` | `dev` (or topic branch) |
| Purpose | Canonical checkout, release packaging, clean verification | Daily development, active features, experimental testing |
| Build cache | Primary `target/` | Worktree-local `target/` |
| Cargo lockfile | Canonical and committed | Canonical; shared Git tracking |
| D-Bus session | Production or packaged user session | Isolated D-Bus sandbox bus (`dbus-launch`) |
| Storage data | Production vault (`~/.local/share/sigil/`) | Isolated test directory (`$XDG_DATA_HOME`) |
| Runtime socket | System runtime (`$XDG_RUNTIME_DIR/sigil.sock`) | Isolated test socket or dev directory |

Do not set a shared `CARGO_TARGET_DIR` for these worktrees. Separate target
directories prevent canonical release artifacts and active development builds
from invalidating each other's incremental caches.

## Create the Development Worktree

Create the linked worktree once from the primary Sigil worktree:

```bash
git worktree add -b dev ../sigil-dev main
```

The expected directory layout is:

```text
projects/
├── sigil/
├── sigil-dev/
└── xdg-desktop-portal-atrium/  # optional sibling portal
```

The primary `sigil/` worktree keeps `main` checked out. The `sigil-dev/`
worktree permanently keeps the local `dev` branch checked out.

Enter the development worktree and verify the repository state:

```bash
cd ../sigil-dev
cargo check --workspace
```

## Daily Development

Run builds, checks, and test suites directly within the development worktree:

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

### Running the Development Daemon

The daemon registers the well-known D-Bus name `org.freedesktop.secrets`.
To avoid conflicts with an installed desktop Secret Service or another
running daemon, run development instances inside an isolated session bus:

```bash
# Terminal 1: launch isolated session bus and run the daemon
eval $(dbus-launch --sh-syntax)
echo "Isolated D-Bus: $DBUS_SESSION_BUS_ADDRESS"
SIGIL_PROMPTER_PATH=./target/debug/sigil-prompter RUST_LOG=debug cargo run -p sigil
```

In a separate terminal, export the same bus address to test with CLI tools
or sibling client applications:

```bash
# Terminal 2: client testing against dev daemon
export DBUS_SESSION_BUS_ADDRESS="<value from Terminal 1>"
secret-tool store --label="Test Secret" service testapp username alice
secret-tool lookup service testapp username alice
```

## Cross-Repository Integration

Sigil provides the system Secret Service provider (`org.freedesktop.secrets`)
and native IPC backend for the desktop environment. When developing alongside
sibling repositories such as `xdg-desktop-portal-atrium`:

1. **Independent dependency trees**: Sigil and Portal maintain separate
   workspaces and `Cargo.lock` files. They interact at runtime across D-Bus
   and Unix domain sockets, not via Cargo path dependencies.
2. **Runtime isolation**: Always isolate test instances using
   `DBUS_SESSION_BUS_ADDRESS` and separate `XDG_DATA_HOME` directories to
   prevent test vaults from touching production credentials.
3. **Socket cleanup**: If a previous run terminated abnormally, remove the
   socket at `$XDG_RUNTIME_DIR/sigil.sock` before restarting the daemon.

## Commit Sigil Changes

Stage and commit changes inside `sigil-dev`:

```bash
git add .
git commit -m "feat: implement requested capability"
```

Commits created on `dev` already belong to the shared Git repository. No
file-copy, push, or pull step is required for local synchronization.
Uncommitted files in the development worktree do not enter `main`; Git merges
commits, not uncommitted working tree state.

## Synchronize with Sigil Main

When changes occur on `main` (for example, after pulling upstream releases),
update `main` in the primary worktree first:

```bash
cd ../sigil
git switch main
git pull --ff-only
```

Then rebase the development branch onto the updated `main`:

```bash
cd ../sigil-dev
git rebase main
cargo test --workspace
```

## Merge Locally and Reuse the Worktree

When work on `dev` is ready to be incorporated into `main`, fast-forward
`main` from the primary worktree:

```bash
cd ../sigil
git switch main
git merge --ff-only dev
```

Both branches now point to the same commit. Continue with the next change in
the existing development worktree (`../sigil-dev`).

## Optional Pull Request Workflow

When collaborating via a remote Git forge, start changes on a topic branch
branched from canonical `main`:

```bash
cd ../sigil-dev
git switch -c feat/<topic> main

# Implement, test, and commit
cargo test --workspace
git commit -m "feat: implement topic feature"
git push -u origin feat/<topic>

# After the PR merges upstream:
cd ../sigil
git switch main
git pull --ff-only

cd ../sigil-dev
git switch dev
git merge --ff-only main
git branch -d feat/<topic>
```

The development worktree remains in place and returns to `dev` after the
pull request is merged.

## Remove the Development Worktree

Remove the worktree only when isolated development is no longer needed:

```bash
cd ../sigil
git worktree remove ../sigil-dev
```

The local `dev` branch remains in the Git repository and can be retained or
deleted as needed.
