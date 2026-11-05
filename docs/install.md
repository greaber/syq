# Install

Syq runs on Linux and macOS, on x86-64 and ARM64. HTTPS downloads need a system
CA trust store, usually provided by `ca-certificates` on Linux. See
[HTTPS certificates](security.md#https-certificates) for private CAs.

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

## Choose a version for a script

Put `--use-version VERSION` after `syq`, before the command and its options,
to run an exact official release:

```sh
syq --use-version 0.7.1 cp photos --into backup
```

Syq downloads and verifies that release the first time it is needed and keeps
it in `~/.local/lib/syq`; later calls run it offline. Your normal installation
stays unchanged. The selected release runs the whole command, including its
remote helpers, so an older release also brings its older limitations and bugs.
`latest` and version ranges are not accepted. Stored releases stay until you
delete them; see [stored releases](environment.md#stored-releases-and-helpers).

### Check the invoked version

Use `--version-is EXPR` to check the version of the syq you invoked before it
runs your command:

```sh
syq --version-is '>=0.7.1, <0.8.0 | >=1.0.0' cp photos --into backup
```

Compare with `==`, `!=`, `<`, `<=`, `>`, or `>=`; `,` means and, and `|` means
or. Quote the expression for the shell, and put `--version-is` before the
command, like `--use-version`. A mismatch or a development build exits with
status 1 before the command runs, and an invalid expression or misplaced
option exits with status 2. See [`syq`](commands/index.md#syq) for the full syntax.

## Automatic installation on SSH servers

Syq installs its SSH helper on the server when needed, in the server's
`~/.local/lib/syq`, and leaves it there for later copies. Official releases also
try to make `syq` available at `~/.local/bin/syq` for commands you run there,
without changing existing commands or shell startup files.
Use `syq --self-update` on the server to update that command, or the standalone
installer above if it is missing. See [SSH helper installation](environment.md#ssh-helper-installation)
for custom helpers and installation exceptions.

<a id="try-a-benchmark"></a>

## Updates

Use `syq --self-update` for a standalone installation, or `brew upgrade syq`
for Homebrew. Commands already running keep their own version. Receiving
connections started before the update switch to the new version by themselves
once nothing is in progress.

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
Non-interactive use never makes the reminder check. Self-updates and helper
downloads are verified against a signed release manifest; see
[Downloaded executables](security.md#downloaded-executables).

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

Completion suggests options, hosts, and paths, including remote paths over
your usual SSH login. Open a new shell after adding the setup line or
upgrading syq. See [`syq completion`](commands/completion.md) for all options.

## Keep connections open

Use [persistence](persistence.md) to reuse SSH connections across syq commands
and make your laptop available to connected servers.
