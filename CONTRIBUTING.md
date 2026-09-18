# Developing syq

## Build and try a remote copy

Install Rust with rustup, Git, and a C compiler, then:

```sh
git clone https://github.com/greaber/syq.git
cd syq
cargo build --locked --release
./target/release/syq cp data --to server --into /tmp/syq-dev-copy
```

Use test data and a disposable destination. Run `./target/release/syq`
explicitly to test your build. Source builds upload their running executable
for SSH copies, so the remote OS, CPU, and system libraries must be compatible.
Rebuild after edits and rerun the copy. Source builds do not support self-update.

## Choose official helpers

To use released helpers on other supported platforms, compile with
`SYQ_HELPER_RELEASE` set to `v` plus the version in `Cargo.toml`:

```sh
SYQ_HELPER_RELEASE=vX.Y.Z cargo build --locked --release
```

The release must exist, and your source must be compatible with its protocol
and shared state. Use unchanged release source unless you have checked that
compatibility; matching the package version alone is insufficient. Helpers are
verified with the included public key.

Unset `SYQ_HELPER_RELEASE` and rebuild to return to self-upload. Keep
`SYQ_RELEASE_BUILD` unset for custom builds; release packaging uses it.

## Another platform with your own helpers

Build the same source on both machines, including any uncommitted edits.
Compare build identities, then select the remote executable:

```sh
./target/release/syq --build-identity
ssh server /home/me/syq/target/release/syq --build-identity
./target/release/syq cp data --to server --into /tmp/syq-dev-copy \
  --syq-path /home/me/syq/target/release/syq
```

The identities must match exactly. Rebuild both sides after edits.
Use `--no-bootstrap` if the matching executable is on the remote SSH `PATH`.
The rsync spellings are `--rsync-path` and `--syq-no-bootstrap`.

## Direct server-to-server copies

Follow the [remote-copy prerequisites](docs/remote-to-remote.md#what-you-need).
The first copy can enroll a destination automatically. To enroll explicitly,
or update an existing receiver after rebuilding:

```sh
./target/release/syq receiver enroll hostB:/tmp/syq-dev-copy
./target/release/syq cp --from hostA --srcs-in data \
  --to hostB --into /tmp/syq-dev-copy
```

Stop active copies before updating the receiver. Repeating enrollment preserves
its receipt key. Use `receiver list` and `receiver revoke ID` to remove access
when finished; add `--via hostA` if management needs a jump host.

Enrollment uploads your executable by default, so it must run on the destination.
A build selecting official helpers installs the released receiver instead.
`--syq-path` selects ordinary SSH helpers, not this receiver. For incompatible
platforms, run from a compatible machine or use `--coordinate-at local` with
matching SSH helpers to relay through your machine.

## Source archives and debugging

A source archive uses its packaged Git revision as its build identity, even
after edits. Use a Git checkout for custom changes that need distinct identities.

For an optimized build with symbols:

```sh
CARGO_PROFILE_RELEASE_STRIP=none cargo build --locked --release
```

The same override works with `python -m pip install ./sdk/python`.
`cargo build --locked` includes debug symbols, assertions, and overflow checks
at optimization level 1. For easier stepping, set `CARGO_PROFILE_DEV_OPT_LEVEL=0`;
BLAKE3 remains optimized at level 3.

## Reproduce a release binary

Install [Nix](https://nix.dev/install-nix) and check out the release tag on the
same OS and architecture as the published executable:

```sh
nix --extra-experimental-features 'nix-command flakes' build .#release --no-update-lock-file
cmp result/bin/syq /path/to/downloaded/syq
```

Use a tag containing `flake.nix` and `flake.lock`. The lock pins the toolchain
and libraries; `Cargo.lock` pins Rust dependencies. `result/bin/syq.gz` is the
compressed asset. Add `--rebuild` to compile again and compare with the first
output. Editing source or lock files changes the reproduction inputs.

The recipe trusts downloaded build tools and cached dependencies. It embeds
the public verification key and requires no signing credentials. See
[code integrity](docs/security.md#code-and-transport-integrity) for the trust boundary.

## Reproduce a Python distribution

Check out the Python release tag (`sdk-python-v<version>`) on the same OS and
architecture as the wheel:

```sh
nix --extra-experimental-features 'nix-command flakes' build .#python-dist --no-update-lock-file
```

Compare the wheel in `result/` with the downloaded PyPI file using `cmp`.
Use Linux x86-64 to compare source archives. Add `--rebuild` for a fresh build
and comparison. The tag must contain the `python-dist` recipe.

`flake.lock` pins the build environment, `sdk/python/uv.lock` pins maturin,
and `sdk/python/native-source.json` pins the native source. Installing a source
archive uses maturin and does not require Nix.

## Before a pull request

Choose checks using [AGENTS.md](AGENTS.md#verification). For Rust changes,
the usual baseline is:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --bin syq
```

Run integration tests for the affected behavior. Use
[`scripts/test-real-ssh.sh`](tests/real-ssh/README.md) for SSH integration and
`scripts/test-s3.sh` for isolated MinIO tests. To test another provider, run
`python3 tests/object-storage/check.py target/debug/syq` with
`AWS_ENDPOINT_URL_S3`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
and `SYQ_TEST_BUCKET` set. It creates and removes a unique test prefix in the
existing bucket. See `python3 tests/object-storage/benchmark.py --help` for
benchmark options.

For docs, run `python3 scripts/check-doc-links.py` and build with mdBook.
The published site defaults to the latest stable release, with tagged versions
and `master` available through the documentation selector. Archives start at
v0.2.0, the first release containing the mdBook sources. Each version uses its
own documentation and search index. Existing unversioned links to pages only
available on `master` redirect there.

To build the complete site, fetch release tags and run
`python3 scripts/build-doc-site.py` with mdBook and the GitHub CLI available.
It writes to a fresh `target/doc-site/` directory; use `--dest-dir` to choose
another directory. The build reads published stable releases from GitHub and
uses the current checkout for the `master` preview. Run
`python3 scripts/test-doc-site.py` and `node --test scripts/test-doc-selector.cjs`
to check version selection and navigation.
The Pages workflow rebuilds on documentation changes and after release
publication. A manual run on a task branch produces an artifact without
deploying it.

After CLI changes, update and check the command tables:

```sh
cargo build --locked --bin syq
python3 tests/cli_reference.py target/debug/syq
python3 tests/cli_reference.py --check target/debug/syq
```

The updater preserves prose outside marked blocks. Add sections for new commands
and update the advanced-key tables as needed. The help integration test checks coverage.

## Machine-facing completion commands

Shell adapters use `syq completion __complete SHELL INDEX -- WORDS...` or
`syq completion __complete-bash REPLACEMENT -- LINE`. `INDEX` is the zero-based
cursor-word index; `WORDS` are dequoted words including `syq`. `REPLACEMENT`
is Readline's current fragment and `LINE` ends at the cursor. These entry points
are for the generated adapters and are omitted from user help.
