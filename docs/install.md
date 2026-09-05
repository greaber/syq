# Installing syq

## Standalone installer

Install the latest release on Linux or macOS (x86-64 or ARM64), without `sudo`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

The binary goes in `~/.local/bin`; make sure that directory is on your `PATH`.
To choose another directory, download the script and run
`sh install.sh --bin-dir DIR`.

Syq installs matching remote helpers on first use. Standalone installs also
check for updates and print a reminder; run `syq --self-update` to update.
Set `SYQ_NO_UPDATE_CHECK=1` to disable reminders. Updates are never installed
automatically.

## Homebrew

```sh
brew install greaber/tap/syq
```

Remote helpers are installed automatically. Update with `brew upgrade syq`.

## Cargo

With Rust, Cargo, and a C compiler installed:

```sh
cargo install --locked syq
```

Cargo installs into `~/.cargo/bin`. Rerun the command to update.
**Source builds do not check for release updates or support `syq --self-update`.**
For remote operations, they upload their own binary, so the remote must be able
to run it. A Mac build cannot install a Linux helper this way.

## Installing from master or another branch

```sh
cargo install --locked --force --git https://github.com/greaber/syq.git --branch master syq
```

Replace `master` with another branch, or replace `--branch master` with
`--rev COMMIT_SHA` to test a particular commit. Rerun to update.

To test local edits, build from your checkout:

```sh
cargo build --locked --release
./target/release/syq cp ./data --to server --into /tmp
```

No commit or published branch is needed. Syq uploads this build to compatible
remote hosts automatically. For Linux servers, build and run it on a compatible
Linux machine. Matching OS and CPU are required; the remote also needs any
system libraries the binary uses. Syq checks that the uploaded helper runs
before installing it.

Use [rustup](https://rustup.rs/) to select the checkout's pinned Rust toolchain.
On macOS, building also needs the Xcode command-line tools. `command -v syq`
shows which installed binary your shell selects; `syq --build-identity` shows
its source revision and local changes.

## Remote helper bootstrap

On first use, syq installs a matching helper in `~/.cache/syq/helpers/` on the
remote host. Later connections reuse it.

Official releases download a helper for the remote platform and verify its
signed manifest. Source builds upload the running executable over SSH; they
cannot download a matching build for another platform.

### Remote hosts with source builds

If automatic upload cannot work, install a compatible build yourself. Its
`syq --build-identity` must exactly match the local build: use the same commit
and source changes. A source build does not match an official release binary.

Choose **one** of these options:

| Command | Specify the remote binary | Find it on the remote `PATH` |
| --- | --- | --- |
| `syq cp` or remote `syq rm` | `--syq-path /path/to/syq` | `--no-bootstrap` |
| `syq rsync` | `--rsync-path /path/to/syq` | `--syq-no-bootstrap` |

An explicit path disables automatic installation by itself. You do not also
pass `--no-bootstrap`. The `PATH` option uses the non-interactive SSH session's
`PATH`.

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

Syq uses your `ssh` configuration, keys, and known hosts. The default
[remote-to-remote authentication](remote-to-remote.md) needs OpenSSH 8.9 or
newer on the local and coordinating hosts, and on the other remote's SSH
server. Copies between your machine and one remote do not need these newer
features.
