# Install

Syq runs on Linux and macOS, on x86-64 and ARM64.

## Standalone installer

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Installs into `~/.local/bin` without `sudo`. Make sure that directory is on your
`PATH`. To choose another directory, download the script and run
`sh install.sh --bin-dir DIR`.

## Homebrew

```sh
brew install greaber/tap/syq
```

## Try a benchmark

Compare syq with rsync on your own machines, or with rsync and cp locally:

```sh
curl --proto '=https' --tlsv1.2 -fLsS https://raw.githubusercontent.com/greaber/syq/master/scripts/try-benchmark.sh | bash
```

The script asks whether to copy locally, send to an SSH host, or fetch from
one; which workloads to try; the test size; and where to put temporary files.
You can choose another disk or an NFS mount for a local comparison. No
syq-bench installation is needed. If syq is missing, it offers to run the
normal installer locally.

It needs Bash, rsync, OpenSSL, and standard Unix utilities on your machine.
Terminal runs also need Perl to keep SSH prompts available while allowing
immediate cancellation.
SSH tests also need SSH access and rsync on the remote machine. Use an SSH
config alias for custom ports or IPv6 addresses. No remote system packages are
installed; syq performs its usual remote helper setup.

The quick test copies a 64 MiB file and 1,024 files of 8 KiB each. Each tool
runs three times. Temporary test files are removed on success, failure, or Ctrl-C. If SSH is
unreachable during cleanup, the script prints the remote scratch path for
you to remove later. It never uses your existing files as test data.

To inspect the script first, download it with curl's `-o try-benchmark.sh`,
then run `bash try-benchmark.sh`. Use `--help` for repeatable command-line
options, including `--yes` to use defaults without questions and `--install`
to install syq if missing. See [how to interpret the comparison](speed.md#quick-comparison).

## Updates

Use `syq --self-update` for a standalone installation, or `brew upgrade syq`
for Homebrew.

Standalone installs print an update reminder; nothing updates automatically.
Set `SYQ_NO_UPDATE_CHECK=1` to disable reminders.

## Shell completion

Add the line for your shell to its startup file:

```bash
# Bash (~/.bashrc)
eval "$(syq completion bash)"

# Zsh (~/.zshrc), after autoload -Uz compinit && compinit
source <(syq completion zsh)
```

```fish
# fish (~/.config/fish/config.fish)
syq completion fish | source
```

Path completion also shows file details. In Bash, press Tab again until the
match list appears (or press Alt+? to list matches directly). Zsh shows one
entry per line; fish shows details in its completion pager. Completing or
selecting an entry still inserts only its path.

The listing shows permissions, owner, group, human-readable file size, and
modification time in UTC. Symlinks include their targets. A directory's size
is shown as `—`: completion does not scan its contents or calculate tree totals.
Owner and group names come from the machine holding the files, with numeric
IDs when names are unavailable. Files that disappear or cannot be inspected
are marked `[metadata unavailable]`. If fetching details takes more than two
seconds after the names arrive, completion keeps the names and marks their
metadata unavailable.

Bash fetches metadata only when listing matches. Zsh and fish fetch it while
preparing their menus. Remote completion uses the same SSH login as copying;
connection persistence is optional. After upgrading, open a new shell or
source the completion adapter again to use the new display.

## Keep connections open

Avoid repeated logins when running several network copies:

```sh
syq persist on
syq persist status
syq persist off
```

Persistence also enables [background receiving](receive.md) from the server
accounts syq connects to. Those accounts can send files to your home directory
automatically. Use `syq recv off` to keep only ordinary connection reuse, or
`syq recv on --root DIRECTORY` to contain receiving in an existing directory.

Ordinary SSH connections can stay reusable for up to ten minutes after your last command.
During that window, other processes running as your user can reuse the login
without another key touch or agent approval. Return connections stay available
until stopped. `persist off` closes both.
