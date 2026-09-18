# Developing syq

Build from source to change syq, choose compilation options, or try a platform
without a published binary. For prebuilt binaries, follow [Install and setup](install.md).

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

## Choose official helpers

To use official helpers instead of uploading your executable, set
`SYQ_HELPER_RELEASE` when compiling. It must equal `v` followed by the version in
`Cargo.toml`. Replace `vX.Y.Z` below with that release version:

```sh
SYQ_HELPER_RELEASE=vX.Y.Z cargo build --locked --release
```

This is a build-time choice. It lets a source-built client use verified official
helpers on other supported platforms, including restricted receiver enrollment.
The public verification key is included; you do not need signing credentials.
The helper release must exist and have an artifact for the destination platform.

Choosing it asserts that your source is compatible with that release, including
its wire protocol and shared state. Use it for unchanged release source or changes
you know preserve compatibility. A fork with protocol or state changes should
use its own helpers. Matching the package version alone does not establish
compatibility: an unreleased checkout can have protocol changes before its
version number changes.

`--build-identity` then reports the selected release identity. This identifies
compatibility; it does not certify that your executable is an official artifact
or has identical bytes. These source builds do not automatically install a
command at `~/.local/bin` on SSH servers or acquire standalone update ownership.
To return to self-upload, unset `SYQ_HELPER_RELEASE` and rebuild. Keep
`SYQ_RELEASE_BUILD` unset for custom builds; it is used by release packaging.

## Another platform with your own helpers

For an ordinary SSH copy from, for example, macOS to Linux, build syq for the
remote platform too. A straightforward setup is a clean checkout of the
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
SSH helper cache. Follow the SSH-agent, host-key, and connectivity prerequisites in
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

By default, enrollment uploads the source-built executable when the platforms
match. On platforms without official assets, it attempts to run your executable
instead of rejecting the platform upfront. Ordinary SSH bootstrap does the same.
The executable must run there. Source builds selecting official helpers always
install the verified release executable for hostB.
Official releases also upload the running executable when the platforms match;
for a different platform, they install the verified release executable for hostB. `--syq-path` does not select the restricted receiver. To develop
across incompatible platforms, run the coordinating command from a compatible
machine or explicitly choose `--coordinate-at local` to relay through your
machine using ordinary SSH helpers. For that relay, the manual helper
selection above is available.

## Source archives and debugging

An extracted source package uses its packaged Git revision as provenance, even
inside another Git checkout. That revision does not detect subsequent edits to
the extracted files. For custom changes that need distinct helper identities,
use a Git checkout: its revision and dirty marker identify the source changes.

To keep symbols in an optimized build:

```sh
CARGO_PROFILE_RELEASE_STRIP=none cargo build --locked --release
```

For a Python wheel built from this checkout, use the same Cargo override:

```sh
CARGO_PROFILE_RELEASE_STRIP=none python -m pip install ./sdk/python
```

The Python build backend must come from the pinned `pyproject.toml`. Published
wheels are stripped explicitly by release CI. For a standalone debug executable,
`cargo build --locked` uses optimization level 1 with debug symbols, debug
assertions, and overflow checks. Tests inherit these settings. BLAKE3 uses
level 3 in both development and test builds.

For clearer debugger stepping, temporarily use
`CARGO_PROFILE_DEV_OPT_LEVEL=0 cargo build --locked`. The BLAKE3 override still
applies.

## Reproduce a release binary

The Nix recipe builds the standalone Linux x86-64/ARM64 and macOS Intel/Apple
Silicon artifacts on a host of the same OS and architecture. The macOS
executables retain deployment targets of 10.12 on Intel and 11.0 on Apple Silicon.
Install [Nix](https://nix.dev/install-nix), check out the release tag you want to
verify, and run:

```sh
nix --extra-experimental-features 'nix-command flakes' build .#release --no-update-lock-file
./result/bin/syq --build-identity
```

Use a tag that contains `flake.nix` and `flake.lock`. The lock pins the Rust
compiler, C compiler, libraries, macOS SDK, and compression tools; `Cargo.lock`
pins the Rust dependencies. Downloads happen while Nix prepares these inputs.
Compilation uses the prepared inputs offline. Docker is not required, and the
resulting executable runs without Nix installed.

Compare `result/bin/syq` with the raw executable for your platform from that
release; `result/bin/syq.gz` is its compressed asset. For example, after downloading
`syq-linux-x86_64` into the current directory:

```sh
cmp result/bin/syq syq-linux-x86_64
```

A successful comparison means those files have identical bytes. To force another
local compilation and have Nix compare it with the first output:

```sh
nix --extra-experimental-features 'nix-command flakes' build .#release --rebuild --no-update-lock-file
```

Release CI builds each target once with this recipe. Rebuilding and comparing
an older release is a separate, manual check using that tag's locked inputs.
The recipe uses compiler and dependency substitutes from Nix's cache as trusted
inputs; it does not independently rebuild them.
The release signature covers a separate manifest of artifact hashes, so you do
not need a private signing key to reproduce the executable. See
[code integrity](security.md#code-and-transport-integrity) for the trust boundary.

This recipe deliberately enables release behavior and embeds the checked-in
public verification key. Use the ordinary Cargo commands above for custom
builds. Editing the source or updating either lock file changes the build inputs
and is not a reproduction of the published release.

## Reproduce a Python distribution

Check out the Python release tag (`sdk-python-v<version>`) on the same OS and
architecture as the wheel, then run:

```sh
nix --extra-experimental-features 'nix-command flakes' build .#python-dist --no-update-lock-file
```

`result/` contains the wheel for your platform and a source archive. Compare the
wheel with the downloaded PyPI file using `cmp`. The published source archive is
built on Linux x86-64; use that platform when comparing its bytes. To force a
fresh compilation and compare it with the first output, add `--rebuild`.

Use a release tag containing the `python-dist` recipe. `flake.lock` pins the
build environment, including Python and archive tools; `sdk/python/uv.lock`
pins maturin. `sdk/python/native-source.json` pins the native source revision
and tree hash separately from the Python SDK source. The native release's
Rust toolchain and Cargo lock select its compiler and dependencies. As with
standalone releases, input downloads and cached build tools are trusted inputs
and must remain available to rebuild later.

Publishing uses this same recipe and builds once per platform. The manual
`publish SDKs` workflow can optionally rebuild and compare distributions without
publishing. The wheel keeps its dependency inventory (SBOM); local source paths
in that inventory are normalized so temporary build directories do not change
its bytes. Installing from the source archive still uses maturin and does not
require Nix; use the pinned recipe when you need the published wheel's bytes.


## Before a pull request

For Rust changes, run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --bin syq
```

Also run integration tests that exercise your change. SSH, remote-helper,
enrollment, receiver, transport, and remote-coordinator changes need
`scripts/test-real-ssh.sh`; see the [real-SSH test setup](https://github.com/greaber/syq/blob/master/tests/real-ssh/README.md).
Object-storage changes also need `scripts/test-s3.sh`, which starts a pinned,
disposable MinIO container on loopback and checks interoperability and resume.
With provider credentials and an existing bucket, run
`python3 tests/object-storage/check.py target/debug/syq` with
`AWS_ENDPOINT_URL_S3`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, and `SYQ_TEST_BUCKET` set. Optional `SYQ_TEST_HEADERS`
is a JSON object of headers. The test creates a unique `syq-tests/` prefix and
removes only its own objects and multipart uploads. To compare an optimized
build with s5cmd under the same environment, run
`python3 tests/object-storage/benchmark.py --syq target/release/syq --s5cmd /path/to/s5cmd --output target/s3-benchmark`.
Transfer trials use each tool's built-in defaults unless you request overrides.
Use `--syq-tuning` for syq and its baseline, and `--s5cmd-workers`,
`--s5cmd-concurrency`, or `--s5cmd-part-size` (MiB) to tune s5cmd independently.
The shared `--workers`, `--concurrency`, and `--part-size` options still set
both tools when explicitly supplied; mixing shared and separate overrides is an error.
For example, `--workers 32 --concurrency 32 --part-size 64` explicitly selects
32 object workers, 32 concurrent parts, and 64 MiB parts for both tools.
The results identify whether transfer tuning uses tool defaults, shared overrides,
or per-tool overrides, and record the settings, exact commands, and binary hashes.
Check those settings before comparing results from different benchmark runs.
By default it runs the transfer workloads (`large`, `medium`, `small`) and
reports throughput. The pruning workloads (`delete`, `noop`, `mixed`) mirror
100,000 small objects with `--prune` in both directions, take much longer, and
need a bucket that has never enabled versioning; select them with
`--workloads`. Omit `--s5cmd` to measure syq alone, or add `--baseline` for an
older syq build. Each trial alternates tool
order, verifies the result, and is flagged when it falls below the ten-second
minimum; raise `--count` or `--size` in that case. Raw timings, CPU and memory
use, binary hashes, verification results, and logs are saved in the output
directory, and the test prefix is removed afterwards. Setup and verification
are untimed. The benchmark requires Python 3.11 or newer and `/usr/bin/time`.
If your provider requires a custom header, ensure both clients send it: stock
s5cmd has no arbitrary-header option. `--s5cmd-quiet` runs s5cmd without its
per-object logging as a separate control.

For documentation changes, run `python3 scripts/check-doc-links.py` and build the
book with mdBook. Command-reference tables follow the executable's complete help:

```sh
cargo build --locked --bin syq
python3 tests/cli_reference.py target/debug/syq
python3 tests/cli_reference.py --check target/debug/syq
```

The update preserves prose outside the marked table blocks. Add a section for a
new public command and update the advanced-control key references when needed.
The `help` integration test checks the tables against the built executable.
See the repository's `AGENTS.md` for the full contribution workflow.

## Machine-facing completion commands

The generated shell adapters invoke `syq completion __complete SHELL INDEX -- WORDS...`
or the Bash-specific `syq completion __complete-bash REPLACEMENT -- LINE`.
`INDEX` is the zero-based cursor-word index; `WORDS` are dequoted command words
including `syq`. `REPLACEMENT` is Readline's current fragment and `LINE` is the
command line through the cursor. These entry points serve the generated adapters
and are omitted from user help. For interactive use, generate an adapter with
`syq completion bash`, `zsh`, or `fish`; use `syq completion cache` to inspect or
clear endpoint suggestions.
