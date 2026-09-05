# Developing syq

Use a source build when changing syq itself. For everyday use, follow
[Install and setup](install.md).

## Build and try a remote copy

Install Rust with rustup, Git, and a C compiler, then:

```sh
git clone https://github.com/greaber/syq.git
cd syq
cargo build --locked --release
./target/release/syq --build-identity
./target/release/syq cp data --to server --into /tmp/syq-dev-copy
```

Use test data and a disposable destination. Run `./target/release/syq`
explicitly so you do not accidentally test a release installed on your `PATH`.
`--release` selects Cargo's optimized build; it is still a development version.
Source builds do not check for release updates or support `--self-update`.

For ordinary SSH copies, syq uploads its running executable automatically when
the remote host needs it. You do not need to commit or push local edits first.
The helper is cached for syq's own use; it does not install a `syq` command on
the remote `PATH`. Rebuild after edits and rerun the copy to use the new build.

The remote OS, CPU, and required system libraries must be compatible with your
executable. A Linux build can still fail on another Linux host with older
libraries. Syq reports the failure instead of substituting a released helper.

## Another platform

For an ordinary SSH copy from, for example, macOS to Linux, build syq for the
remote platform too. The simplest reproducible setup is a clean checkout of the
same commit on both machines, built with `cargo build --locked --release`.
If using uncommitted edits, reproduce those changes on both machines as well.
Compare the identities, replacing the remote path with your actual checkout:

```sh
./target/release/syq --build-identity
ssh server /home/me/syq/target/release/syq --build-identity
./target/release/syq cp data --to server --into /tmp/syq-dev-copy \
  --syq-path /home/me/syq/target/release/syq
```

Both identities must match exactly; matching `--version` alone is insufficient.
Rebuild both sides after changes. Use `--no-bootstrap` instead if the matching
remote executable is already on the remote SSH session's `PATH`. In rsync mode,
the corresponding flags are `--rsync-path` and `--syq-no-bootstrap`.

## Direct server-to-server copies

These use a restricted receiver on the destination, separate from the ordinary
SSH helper cache. Follow the SSH-agent, host-key, and TCP-port prerequisites in
[Copy between servers](remote-to-remote.md#what-you-need).

The first real copy can enroll the destination automatically, including with a
development build. A dry run cannot create an enrollment. To make setup explicit
and to refresh an existing receiver after rebuilding, run:

```sh
cargo build --locked --release
./target/release/syq receiver enroll hostB:/tmp/syq-dev-copy
./target/release/syq cp --dry-run -v --from hostA --srcs-in data \
  --to hostB --into /tmp/syq-dev-copy
./target/release/syq cp --from hostA --srcs-in data \
  --to hostB --into /tmp/syq-dev-copy
```

Repeat enrollment for the same host and root to install your current executable;
rebuilding alone does not refresh an existing receiver. Enrollment preserves
its receipt key. Use `receiver list` to find enrollment IDs and `receiver revoke
ID` to remove access when finished. If setup needs a jump host, add `--via hostA`
to `receiver enroll` or `receiver revoke`.

Enrollment uploads the local executable, so it must run on hostB. This applies
to official releases too: enrollment does not use the ordinary helper's
cross-platform download mechanism, and `--syq-path` does not select the restricted
receiver. Run the coordinating command from a compatible machine, or use
`--coordinate-at local` to relay the copy through your machine using ordinary
SSH helpers. For that relay, the manual helper selection above is available.

## Before a pull request

For Rust changes, run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --bin syq
```

Also run integration tests that exercise your change. SSH, remote-helper,
enrollment, receiver, transport, and remote-coordinator changes need
`scripts/test-real-ssh.sh`; see the [real-SSH test setup](../tests/real-ssh/README.md).
For documentation changes, run `python3 scripts/check-doc-links.py`.
See the repository's `AGENTS.md` for the full contribution workflow.
