# Install

Syq runs on Linux and macOS, on x86-64 and ARM64.

## Standalone installer

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://dl.syq.christmas/latest/install.sh | sh
```

Installs into `~/.local/bin` without `sudo`. Make sure that directory is on your
`PATH`. To choose another directory, download the script and run
`sh install.sh --bin-dir DIR`.

## Homebrew

```sh
brew install greaber/tap/syq
```

## Build from source

See [source builds](https://github.com/greaber/syq/blob/master/CONTRIBUTING.md) for Cargo builds, custom compilation options,
and choosing between your own executable and compatible official SSH helpers.

## Automatic installation on SSH servers

Syq installs its SSH helper on the server when needed. Official releases also
try to make `syq` available at `~/.local/bin/syq` for commands you run there.
Existing commands and shell startup files are left alone.

Use `syq --self-update` on the server to update that command, or the standalone
installer above if it is missing. See [SSH helper installation](environment.md#ssh-helper-installation)
for custom helpers and installation exceptions.

## Try a benchmark

Compare syq with rsync on your own machines, or with rsync and cp locally.
See [Quick comparison](speed.md#quick-comparison) for the script and how to
read its results.

## Updates

Use `syq --self-update` for a standalone installation, or `brew upgrade syq`
for Homebrew.

Standalone and Homebrew installs may print an update reminder in a terminal,
at most once a day after a successful command, naming the upgrade command for
that install. Nothing updates automatically. Set `SYQ_NO_UPDATE_CHECK=1` or
`DO_NOT_TRACK=1` to disable reminders.

### Update-check data

Downloads and the daily reminder check go through `dl.syq.christmas`, a host
run by the maintainer that serves the GitHub release files from a cache. It
records each request's time, syq version, platform, the connection's IP
address, and the country, region, and city derived from that address, so the
project can see how many installs exist and which versions are in use.
Nothing identifies an install, and the check sends nothing else.
Non-interactive use never makes the reminder check. An installed official syq
verifies self-updates and helper downloads against a signed release manifest.
See [Downloaded executables](security.md#downloaded-executables) for how that
verification works and how trust is established during the first installation.

## Shell completion

Add the line for your shell to its startup file:

```bash
# Bash (~/.bashrc)
eval "$(syq completion bash)"

# Zsh (~/.zshrc), after autoload -Uz compinit && compinit
source <(syq completion zsh)

# fish (~/.config/fish/config.fish)
syq completion fish | source
```

Completion suggests options, hosts, and paths, with file details beside path
matches. In Bash, press Tab again to list matches. Remote paths use your usual
SSH login. Open a new shell after adding the setup line or upgrading syq.
See [`syq completion`](commands/completion.md) for all options.

## Keep connections open

Use [persistence](persistence.md) to reuse SSH connections across syq commands
and make your laptop available to connected servers.
