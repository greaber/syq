# Command reference

Look up commands and options here. For copy examples, start with
[Copy files](../reference.md). Three option groups have their own pages:

- [Performance tuning](../tuning.md): workers, request sizes, and copy methods.
- [Resource limits](../resource-limits.md): bandwidth and concurrency ceilings.
- [Integrity checking](../integrity-checking.md): comparisons and checksums.

Angle brackets mark values you supply; square brackets mark optional arguments,
and `...` allows repetition.

## syq

<!-- CLI: syq -->
```text
syq [--version-is EXPR] [--use-version VERSION] <COMMAND> [OPTIONS]
syq --self-update
```

| Command | Purpose |
|---|---|
| [`cp`](cp.md) | Copy files and directories, optionally removing destination-only files |
| [`ssh`](ssh.md) | Open an SSH shell or run a command, using your own or approved SSH access |
| [`exec`](exec.md) | From a server, run a command on a receiving machine after it approves |
| [`rm`](rm.md) | Remove selected files and directory trees |
| [`clean-partials`](clean-partials.md) | Delete partial files that interrupted syq copies left in directory trees |
| [`map`](map.md) | Print source-to-destination mappings as NDJSON |
| [`rsync`](rsync.md) | Copy using rsync-compatible syntax |
| [`persist`](persist.md) | Keep SSH connections open, and receive files and requests from connected servers |
| [`completion`](completion.md) | Generate shell completion and manage cached endpoint suggestions |
| [`tuning-cache`](tuning-cache.md) | Inspect and clear local transfer tuning history |
| [`receiver`](receiver.md) | Manage restricted copying on server accounts |
| [`help`](#syq-help) | Show help for any command or nested command |

**Options**

| Argument / option | Meaning |
|---|---|
| `--version-is <EXPR>` | Stop with an error, before doing anything else, unless the syq you invoked matches EXPR. Bare x.y.z means exactly that version; operators: == != < <= > >=. Commas mean AND; \| means OR, with AND binding more tightly. Quote expressions in the shell. Development builds always fail the check. Put --version-is and --use-version before the command, in either order. |
| `--use-version <VERSION>` | Run an exact official release, downloading it if needed (before the command and other options) |
| `--self-update` | Install the newest signed release (standalone installs); Homebrew: brew upgrade syq |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |
| `-V, --version` | Print version |

<!-- /CLI -->

## syq --self-update

Update a standalone installation. For Homebrew and source installations, see
[installation updates](../install.md#updates).

<!-- CLI: --self-update -->
```text
syq --self-update
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--self-update` | Update the executable registered by the standalone installer |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq help

```text
syq help [COMMAND...] [--help-all]
```

`syq help persist receive on` shows the common help for that command, as
`syq persist receive on --help` does. Add `--help-all` for every option.

## Build identity

`syq --build-identity` prints the release tag, such as `v0.7.1`. A build from
source adds its revision, as in `v0.7.1+dev.0123456789ab`; see
[development builds](https://github.com/greaber/syq/blob/master/CONTRIBUTING.md#another-platform-with-your-own-helpers).
