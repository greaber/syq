# Installing syq

Syq runs on Linux and macOS. The local machine needs one of the installation
paths below. With the standalone installer or Homebrew, syq installs a
matching copy of itself on remote hosts the first time it connects (see
[Remote helper bootstrap](#remote-helper-bootstrap)). A Cargo or checkout
build needs a compatible remote `syq`, as the [Cargo section](#cargo) explains.

## Standalone installer

The standalone installer needs no `sudo` and installs the matching Linux or
macOS binary in `~/.local/bin`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

That initial shell installer necessarily needs `curl` or `wget` to obtain syq
before syq exists. The installed syq, and the remote helper installation it
performs, do not depend on either command.

To inspect it first, download the same URL without piping it to `sh`. Every
release also has an immutable versioned installer, for example
`https://github.com/greaber/syq/releases/download/v0.1.8/install.sh`. To choose
another directory, download the script and run `sh install.sh --bin-dir DIR`
(or pipe it to `sh -s -- --bin-dir DIR`). The script detects your platform,
verifies the archive's embedded SHA-256 and size, runs the temporary binary to
check its version and release identity, and then replaces `syq` atomically.
Even with `--bin-dir`, either `HOME` or `XDG_CONFIG_HOME` must be set so every
successful standalone installation can record its install receipt.

## Homebrew

Homebrew is also supported through the project-owned tap:

```sh
brew install greaber/tap/syq
```

## Cargo

Rust users can instead compile and install the published source package:

```sh
cargo install --locked syq
```

Cargo installs binaries in `~/.cargo/bin` by default; make sure that directory
is on your `PATH`. Cargo builds, including the published source package, use
the [source-build remote setup](#remote-hosts-with-source-builds) below.

## Installing from master or another branch

To install the latest code on `master`, with Git, Rust, Cargo, and a C compiler
installed:

```sh
cargo install --locked --force --git https://github.com/greaber/syq.git --branch master syq
```

Replace `master` with another branch name to try that branch. To install a
specific commit, replace `--branch master` with `--rev COMMIT_SHA`. Rerun the
branch command to update; `--force` reinstalls even when the package version
number has not changed. These are optimized builds, just like
`cargo build --release`; the word “release” in Cargo's build profile does not
make them official syq releases.

The active Rust toolchain must satisfy the selected revision's `rust-version`
in `Cargo.toml`. For the exact toolchain pinned by that revision, build from a
checkout with [rustup](https://rustup.rs/) installed:

```sh
git clone --branch master https://github.com/greaber/syq.git
cd syq
cargo install --locked --force --path .
```

Rustup selects the version in `rust-toolchain.toml`. You can replace `master`
in the clone command with another branch, or run `git checkout COMMIT_SHA`
before installing to select a specific commit. To update a clean branch
checkout, run `git pull --ff-only` and repeat the install command. To build
without installing, use `cargo build --locked --release`; the binary is at
`target/release/syq`. See [Platform notes](#platform-notes) for macOS build
prerequisites.

Check which executable your shell selects and record its build identity:

```sh
command -v syq
syq --build-identity
```

Cargo normally installs into `~/.cargo/bin`. An older standalone or Homebrew
binary earlier on `PATH` can still be the one you run; adjust `PATH` or invoke
`~/.cargo/bin/syq` explicitly.

### What changes with an unreleased build

Branch builds can include changes that have not shipped in a release. Use the
documentation in that checkout when trying another branch; the documentation
site describes `master`.

`syq --version` reports the package version, which can stay the same across
many commits. `syq --build-identity` distinguishes them: a clean Git build has
an identity such as `v0.2.0+dev.0123456789ab`. Local changes add a
`.dirty.HASH` suffix. Include the full build identity when reporting a problem.
A source build from a release tag still has a development identity and does
not match the official release binary. Source archives without Git revision
metadata get a build-specific identity, so use a Git checkout when building
matching binaries on different machines.

Source builds do not automatically install remote helpers, check for release
updates, or support `syq --self-update`. Update them with Cargo or rebuild the
checkout. To return to an official binary, use the standalone installer or
Homebrew and check `command -v syq` again so a Cargo binary does not shadow it.

### Remote hosts with source builds

Local copies need no extra setup. For remote operations, install a source-built
`syq` on every participating host. All binaries must report exactly the same
`syq --build-identity`; matching package versions or branch names are not
enough. Build the same pinned commit from clean checkouts for each host's
platform, or copy your binary when it is compatible with the remote platform.
Local changes affect the identity too, so independently edited checkouts may
fail the connection handshake.

Select the remote binary explicitly. For example, after installing it at
`/home/alice/.cargo/bin/syq` on `server`:

```sh
ssh server /home/alice/.cargo/bin/syq --build-identity
syq cp --syq-path /home/alice/.cargo/bin/syq ./data server:/home/alice/data-copy
```

Native `syq cp` and remote `syq rm` use `--syq-path PATH`, or `--no-bootstrap`
when the matching binary is on the non-interactive remote `PATH`. `syq rsync`
uses `--rsync-path PATH`, or `--syq-no-bootstrap` for the same `PATH` lookup.
Without these options, source builds cannot use the default managed helper
installation, even if a matching binary is already installed on the remote.

## Shell completion

Syq can complete commands, options, endpoints, and local or remote paths. Add
the line for your shell to its startup file:

```bash
# Bash (~/.bashrc)
eval "$(syq completion bash)"

# Zsh (~/.zshrc), after `autoload -Uz compinit && compinit`
source <(syq completion zsh)
```

```fish
# fish (~/.config/fish/config.fish)
syq completion fish | source
```

Remote completion logs in with a normal noninteractive SSH session. The first
Tab on a remote endpoint can take a few seconds if syq must install the remote
helper there. `syq persist on` makes later completions much faster by keeping
the authenticated SSH connection, and a ready helper session on it,
available between commands.

## Update checks and self-update

Standalone installs download and verify one signed release manifest at most
once a day after a successful interactive command. When a newer release is
available they print a reminder; updates are never installed as a side effect
of a copy. Run `syq --self-update` to install the update (`syq --self-update --help`
explains eligibility and reminders), or set
`SYQ_NO_UPDATE_CHECK=1` to disable automatic checks and reminders. Explicit
`syq --self-update` checks still work when that variable is set. The install
receipt lives at
`$XDG_CONFIG_HOME/syq/install.json` (normally `~/.config/syq/install.json`) and
must name the running executable, so a Homebrew or source build never replaces
itself. Self-update is deliberately limited to standalone installs because a
package manager must remain the owner of its files. Update Homebrew installs
with `brew upgrade syq`.

Release binaries are published for Linux x86-64/ARM64 and macOS Apple
Silicon/Intel. Terminal downloads and Homebrew normally do not attach macOS's
quarantine attribute, which is why command-line tools installed this way do not
usually produce Gatekeeper prompts. The binaries are not Developer ID signed
or notarized by Apple, so a browser download may prompt or be blocked by
Gatekeeper. Use the terminal installer or Homebrew for the documented
installation path.

## Remote helper bootstrap

With an official release build, nothing needs to be installed on the remote
host in advance. Syq installs a helper of exactly its own version, kept on the
remote under `~/.cache/syq/helpers/`.
On first use of a version it detects the remote
platform and checks for a downloader, SHA-256 implementation, and `gzip`. When
that complete toolchain is available, the remote downloads the matching
compressed binary and signed manifest from that version's GitHub release. It
relays the manifest and computed digest over SSH, then waits while the local
client verifies the manifest signature and compares its expected digest. Only
an explicit approval from the client lets the remote install the helper
atomically. This path therefore works even when the local machine cannot reach
the release host. Later runs execute that exact path without an extra probe
connection.

If the remote toolchain is unavailable, a tool fails, or the download times
out or otherwise fails, the local client downloads the archive for that
platform with its own built-in HTTPS client (rustls) instead. It verifies both the archive and
decompressed binary, caches the verified binary under
`$XDG_CACHE_HOME/syq/helpers/` (normally `~/.cache/syq/helpers/`), and uploads it
through the configured SSH command.
This fallback does not require a remote downloader, hasher, or decompressor.
Remote filesystem and installation errors fail immediately because uploading
the same helper cannot fix them. A completed download with the wrong digest is
discarded and produces an integrity warning even if the verified upload then
succeeds.

The helper cache accepts only a verified release binary. To opt out of
automatic helper installation, install a compatible binary yourself. Native `syq cp` and
remote `syq rm` use `--syq-path /path/to/syq`, or `--no-bootstrap` when the
binary is on the non-interactive remote `PATH`; `syq rsync` uses `--rsync-path
/path/to/syq` or `--syq-no-bootstrap`.

The local client verifies the manifest's embedded Ed25519 signature over its
normalized JSON form (RFC 8785). A remote download uses `curl` or `wget`, `gzip`,
and one of `sha256sum`, `shasum`, or `openssl`; those programs are optional
because missing or unusable tools select verified SSH upload instead. Version
directories coexist and either helper cache can be removed at any time; syq
recreates the helper it needs on the next connection. After launch, both sides
must have the same build identity: the release tag for official binaries, or the
Git-derived identity when an explicit source-built helper is used.

## SSH requirements

Syq runs your own `ssh`, so your configuration, keys, agent, and known hosts
apply unchanged. Copies between your machine and a remote host need nothing
special. A copy between two remote machines forwards the constrained agent
broker (a temporary local SSH agent that signs only for the intended
destination) to the coordinator, the host that runs the copy, by default.
This relies on OpenSSH features from release 8.9
(February 2022):
the client on your machine and on the coordinator host must be 8.9 or newer,
and so must the `sshd` on the other remote. Syq checks the two clients it runs
and stops with a message naming the older one. Ubuntu 22.04, Debian 12, RHEL 9
with current updates, and macOS 13 or newer qualify; RHEL 8, Ubuntu 20.04, and
Debian 11 do not. On such hosts pass `--peer-auth own-credentials` and keep credentials
on the coordinator host, or choose `--peer-auth full-agent` or an
explicit `--rsh` policy. `syq cp -vv` prints the client version it found.

On macOS, Apple's `ssh` ships without a built-in FIDO provider, so a
hardware-backed `sk-` key works only with an external `SecurityKeyProvider`
library configured in `ssh_config`. The simplest route is to install `openssh`
with Homebrew, which has the provider built in, and put its `bin` directory
first on `PATH`; syq picks up whichever `ssh` that resolves to.

## Platform notes

- **macOS (Apple Silicon / Intel):** build natively on the Mac with
  `cargo build --release` (needs the Xcode command-line tools, `xcode-select
  --install`, for the bundled zstd C library). The tool is otherwise pure Rust
  and uses only POSIX calls; Linux-only optimizations (`fallocate`,
  glibc `mallopt`) are compiled out automatically. The destination-side
  same-machine copy fast path is Linux-only; on macOS those copies use the
  normal path. macOS also cannot hold open a file or directory it may not
  read, so a copy that Linux completes through an open handle that needs no
  read permission (for example a mode `000` source file) fails on macOS with
  a permission error. On
  macOS, `/tmp`, `/var`, and `/etc` are symlinks into `/private`. Native
  commands refuse a symlink in a path they are given unless you pass
  `--follow-src`, `--follow-dst`, or `--follow`, so spell such paths as
  `/private/tmp/...` or pass the follow option.
- For a manually installed binary that is portable across distributions (for
  example, a host with an older glibc), build a static binary:
  `RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-gnu`
  (building for musl also works if `musl-gcc` is installed, which `zstd-sys` needs).
