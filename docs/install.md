# Installing syq

Syq runs on Linux and macOS, on x86-64 and ARM64. Choose an installation method:

| Method | Installs remote helpers automatically | How to update |
| --- | --- | --- |
| Standalone installer | Yes | `syq --self-update` |
| Homebrew | Yes | `brew upgrade syq` |
| Cargo or Git checkout | No; [set up remote hosts yourself](#remote-hosts-with-source-builds) | Rerun Cargo or rebuild |

**Source builds do not automatically install remote helpers, check for release
updates, or support `syq --self-update`.** This includes `cargo install syq`
and builds from release tags. Only standalone installs check for updates.

## Standalone installer

Install the latest release into `~/.local/bin`, without `sudo`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Make sure `~/.local/bin` is on your `PATH`. To inspect the script first or
choose another directory, download it and run `sh install.sh --bin-dir DIR`.
The installer verifies the download before replacing the binary. Versioned
installers are also available on the [releases page](https://github.com/greaber/syq/releases).

## Homebrew

```sh
brew install greaber/tap/syq
```

## Cargo

With Rust, Cargo, and a C compiler installed:

```sh
cargo install --locked syq
```

Cargo installs into `~/.cargo/bin` by default. Make sure it is on your `PATH`;
`command -v syq` shows whether an older installation takes precedence.
Rerun the command to update. For remote copies, follow
[Remote hosts with source builds](#remote-hosts-with-source-builds).

## Installing from master or another branch

```sh
cargo install --locked --force --git https://github.com/greaber/syq.git --branch master syq
```

Replace `master` with a branch name, or use `--rev COMMIT_SHA` instead of
`--branch master` to select a commit. Rerun the command to update; `--force`
reinstalls even when the package version has not changed.

Your Rust toolchain must satisfy that revision's `rust-version` in
`Cargo.toml`. To use its pinned toolchain, install [rustup](https://rustup.rs/)
and build from a checkout:

```sh
git clone --branch master https://github.com/greaber/syq.git
cd syq
cargo install --locked --force --path .
```

Rustup selects the version in `rust-toolchain.toml`. To update a clean branch
checkout, run `git pull --ff-only` and repeat the install command. To build
without installing, run `cargo build --locked --release`; the binary is
`target/release/syq`. On macOS, building also needs the Xcode command-line tools
(`xcode-select --install`).

### What changes with an unreleased build

Use the documentation in the checkout for the branch you are trying.
`syq --version` shows the package version; `syq --build-identity` identifies
the build, including its commit and local changes. Include that identity when
reporting a problem. Cargo's `--release` profile produces an optimized source
build, not an official release binary.

### Remote hosts with source builds

Local copies need no extra setup. For remote operations, install `syq` on
every participating host with **exactly the same `syq --build-identity`**.
Matching package versions or branch names are not enough, and a source build
from a release tag does not match the official binary.

Build the same pinned commit from clean Git checkouts for each host's platform,
or copy your binary if it is compatible with the remote platform. Avoid source
archives without Git metadata when building matching binaries separately:
they get build-specific identities.

Then select the remote binary explicitly, for example:

```sh
ssh server /home/alice/.cargo/bin/syq --build-identity
syq cp --syq-path /home/alice/.cargo/bin/syq ./data server:/home/alice/data-copy
```

| Command | Explicit remote binary | Use the remote `PATH` |
| --- | --- | --- |
| `syq cp` or remote `syq rm` | `--syq-path PATH` | `--no-bootstrap` |
| `syq rsync` | `--rsync-path PATH` | `--syq-no-bootstrap` |

One of these options is required even if a matching binary is already
installed. The `PATH` option uses the non-interactive SSH session's `PATH`.

## Update checks and self-update

Standalone installs check for updates at most once a day after a successful
interactive command and print a reminder when one is available. They never
install an update automatically. Run `syq --self-update` to update.

Set `SYQ_NO_UPDATE_CHECK=1` to disable automatic checks and reminders; explicit
`syq --self-update` still works. Self-update requires the install receipt at
`$XDG_CONFIG_HOME/syq/install.json` (normally `~/.config/syq/install.json`)
to name the running executable.

Update Homebrew with `brew upgrade syq` and source builds with Cargo or a
rebuild. To switch from source to an official binary, use the standalone
installer or Homebrew, then check `command -v syq` so a Cargo binary does not
shadow it.

## Remote helper bootstrap

With the standalone installer or Homebrew, you do not need to install syq on
remote hosts in advance. On first connection, syq installs its matching helper
under `~/.cache/syq/helpers/` on the remote host.

Syq verifies the release signature and checksums before installing the helper.
It tries downloading on the remote host first; if the download fails or the
required tools are missing, it downloads locally and uploads over SSH. Either your
machine or the remote host must be able to reach GitHub for the initial
download. Later connections reuse the cached helper. You can remove the cache;
syq recreates it when needed.

To manage remote binaries yourself, use the options under
[Remote hosts with source builds](#remote-hosts-with-source-builds).
The local and remote build identities must match.

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

Mac binaries are not Developer ID signed or notarized by Apple. Browser
downloads may trigger Gatekeeper; use the terminal installer or Homebrew.

- **macOS (Apple Silicon / Intel):** copies of unreadable files (for example, mode
  `000`) can fail where Linux can copy through an open handle. The same-machine
  copy fast path is Linux-only. On macOS, `/tmp`, `/var`, and `/etc` are
  symlinks into `/private`. Native commands refuse a symlink in a path they are given unless you pass
  `--follow-src`, `--follow-dst`, or `--follow`, so spell such paths as
  `/private/tmp/...` or pass the follow option.
- For a manually installed binary that is portable across distributions (for
  example, a host with an older glibc), build a static binary:
  `RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-gnu`
  (building for musl also works if `musl-gcc` is installed, which `zstd-sys` needs).
