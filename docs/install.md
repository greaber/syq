# Install

Syq runs on Linux and macOS, on x86-64 and ARM64. HTTPS downloads need a system
CA trust store, usually provided by `ca-certificates` on Linux. See
[HTTPS certificates](security.md#https-certificates) for private CAs.

## Standalone installer

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://dl.syq.christmas/latest/install.sh | sh
```

The script installs syq into `~/.local/bin` without `sudo`; make sure that
directory is on your `PATH`. To choose another directory, download the script
and run `sh install.sh --bin-dir DIR`.

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

The first time, syq downloads and verifies that release and keeps it in
`~/.local/lib/syq`; later runs work offline. Your normal installation stays
unchanged. The selected release runs the whole command, including on servers,
so an older release brings its older limitations and bugs too. Receiving or the
SSH authorization provider that such a command starts on your laptop outlasts
it; your normal installation switches them to its own version, [as after an
update](persistence-reference.md#connection-lifetime-and-waits). Stored
releases stay until you delete them; see
[stored releases](environment.md#stored-releases-and-helpers).

### Check the invoked version

Use `--version-is EXPR` to check the version of the syq you invoked before it
runs your command:

```sh
syq --version-is '>=0.7.1, <0.8.0 | >=1.0.0' cp photos --into backup
```

Compare with `==`, `!=`, `<`, `<=`, `>`, or `>=`; `,` means and, and `|` means
or. Quote the expression for the shell, and put `--version-is` before the
command, like `--use-version`. If the version doesn't match, or syq is a
development build, syq exits with status 1 without running the command. An
invalid expression or misplaced option exits with status 2. See
[`syq`](commands/index.md#syq) for the full syntax.

## Automatic installation on SSH servers

When a command needs syq on a server, syq installs a matching copy in the
server's `~/.local/lib/syq` and keeps it for later commands. Official releases
also try to add a `syq` command at `~/.local/bin/syq` for you to use in the
server's shell, without changing existing commands or shell startup files. To
update that command, run `syq --self-update` on the server; if it's missing,
use the standalone installer above. See
[SSH helper installation](environment.md#ssh-helper-installation) for custom
helpers and installation exceptions.

<a id="try-a-benchmark"></a>

## Updates

Use `syq --self-update` for a standalone installation, or `brew upgrade syq`
for Homebrew. Commands already running keep their own version. Receiving
switches to the new version once nothing is in progress, by itself or when you
next run syq, and `syq persist status` says why it hasn't yet. If it needs you
to unlock or touch your SSH key, it waits until you next run a syq copy or ssh
command, or `syq persist status`, in a terminal.

When a newer release is out, standalone and Homebrew installs remind you in a
terminal, at most once a day after a successful command, and name the upgrade
command. Nothing updates automatically. Set `SYQ_NO_UPDATE_CHECK=1` or
`DO_NOT_TRACK=1` to turn reminders off.

### Update-check data

Downloads, and the daily reminder check in a terminal, go through
`dl.syq.christmas`, a host run by the maintainer that serves the GitHub release
files from a cache. It records each request's time, syq version, platform, the
connection's IP address, and the country, region, and city derived from that
address, so the project can see how many installs exist and which versions are
in use. Nothing identifies an install, and the check sends nothing else.
When an installed syq downloads a release, it verifies it against a signed
release manifest; see [Downloaded executables](security.md#downloaded-executables).

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
your usual SSH login. Open a new shell after adding the setup line. See
[`syq completion`](commands/completion.md) for all options.

## Keep connections open

Use [persistence](persistence.md) to reuse SSH connections across syq commands
and make your laptop available to connected servers.
