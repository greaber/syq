# Command reference

Look up commands and options below. For copy examples, start with
[Copy files](../reference.md).

The advanced option groups have separate references:

- [Performance tuning](../tuning.md): workers, request sizes, and copy methods.
- [Resource limits](../resource-limits.md): bandwidth and concurrency ceilings.
- [Integrity checking](../integrity-checking.md): comparisons and checksums.

Angle brackets mark values you supply; square brackets mark optional arguments,
and `...` allows repetition.

## syq

<!-- CLI: syq -->
```text
syq <COMMAND> [OPTIONS]
syq --self-update
```

| Command | Purpose |
|---|---|
| [`cp`](cp.md) | Copy files and directories, optionally removing destination-only files |
| [`exec`](exec.md) | Run a command on a named receiving machine after local approval |
| [`rm`](rm.md) | Remove selected files and directory trees |
| [`clean-partials`](clean-partials.md) | Delete syq partial files in directory trees |
| [`map`](map.md) | Print source-to-destination mappings as NDJSON |
| [`rsync`](rsync.md) | Copy using rsync-compatible syntax |
| [`persist`](persist.md) | Manage persistent connections, receiving, and return destinations |
| [`completion`](completion.md) | Generate shell completion and manage cached endpoint suggestions |
| [`receiver`](receiver.md) | Manage manual receiver enrollment and recovery |
| [`help`](#syq-help) | Show help for any command or nested command |

**Options**

| Argument / option | Meaning |
|---|---|
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

Show common help for a command or nested command, such as `syq help persist
receive on`. Add `--help-all` for its complete help. With no command, show the
root help. A trailing `--help` or `-h` selects common help.

## Build identity

`syq --build-identity` prints the executable’s build identity. See [development builds](https://github.com/greaber/syq/blob/master/CONTRIBUTING.md#another-platform-with-your-own-helpers).
