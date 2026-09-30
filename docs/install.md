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

## Choose a version for a script

Put `--use-version VERSION` after `syq`, before the command and its options,
to run an exact official release:

```sh
syq --use-version 0.7.1 cp photos --into backup
```

Syq downloads and verifies that release when needed, keeps it alongside other
versions, and runs it with your command's arguments and environment. Your normal
installation stays unchanged. Later calls can use the cached release offline.
The first download needs network access and a writable cache; an unavailable
release or unsupported platform is an error. `latest` and version ranges are
not accepted.

Official and source builds support this option. The syq you invoke must
understand `--use-version`; the selected release does not need to. That release interprets the command and controls its remote helpers
and shared state. Selecting an older release also selects its limitations and
bugs; this option does not add newer behavior to it.

### Check the invoked version

Use `--version-is EXPR` to check the release version of the syq executable you
invoked before it runs your command:

```sh
syq --version-is '0.7.1' cp photos --into backup
syq --version-is '>=0.7.1, <0.8.0' cp photos --into backup
syq --version-is '>=0.7.1, <0.8.0 | >=1.0.0, <2.0.0' cp photos --into backup
```

Expressions use a small numeric comparison language:

| Syntax | Meaning |
| --- | --- |
| `x.y.z` or `==x.y.z` | Exactly that version |
| `!=x.y.z` | Any supported release version except that version |
| `<`, `<=`, `>`, `>=` followed by `x.y.z` | Numeric version comparison |
| `comparison, comparison` | Both comparisons must hold (AND) |
| `group \| group` | At least one AND group must hold (OR) |

AND binds more tightly than OR. Each version has three nonnegative decimal
integer components, compared in order, so `1.10.0` is newer than `1.9.9`.
Leading zeros do not change the number; each component must fit in 64 bits.
Spaces around comparisons, operators, commas, and bars are allowed. Quote the
expression to protect `<`, `>`, and `|` from the shell. Partial versions,
wildcards, `~`, `^`, parentheses, and `||` are not supported.

Put `--version-is` and `--use-version` before the command and all other options.
Each can occur once, in either order. When both are present, syq checks the
initially invoked executable before downloading or running the selected release:

```sh
syq --version-is '>=0.7.1' --use-version 0.7.0 cp photos --into backup
```

The check is consumed by the initial executable; it is not passed to the selected
release or remote helpers. A version mismatch or a development build exits with
status 1 before the command runs. Invalid expressions or misplaced options exit
with status 2. Only release builds with numeric `x.y.z` versions are supported;
prerelease and development-build identities cannot be used in expressions.

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
