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

Connections can stay reusable for up to ten minutes after your last command.
During that window, other processes running as your user can reuse the login
without another key touch or agent approval. `off` closes the connections.
