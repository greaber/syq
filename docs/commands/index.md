# Command reference

These pages list every public command and option, including advanced options and
nested subcommands. Start with [Copy files](../reference.md) for a guided introduction;
use this reference to look up a command's complete argument list.

The three advanced option groups have their own complete references:

- [Performance tuning](../tuning.md): parallelism, request sizes, and copy methods.
- [Resource limits](../resource-limits.md): bandwidth ceilings and units.
- [Integrity checking](../integrity-checking.md): comparison and payload checks.

Options in the tables belong to the command whose usage appears above them.
Angle brackets mark values you supply; square brackets in usage mark optional
arguments, and `...` allows repetition. The tables list short spellings beside
long spellings. Unset Boolean flags are off unless their description says otherwise.

## syq

Choose a command below, or use one of the standalone options.

<!-- CLI: syq -->
```text
syq <COMMAND> [OPTIONS]
syq --self-update
```

| Command | Purpose |
|---|---|
| [`cp`](cp.md) | Copy files and directories, optionally removing destination-only files |
| [`stream`](stream.md) | Stream S3 object contents to or from stdin, stdout, or an inherited descriptor |
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

Update an installation registered by the standalone installer. Homebrew users run `brew upgrade syq`; source builds must be rebuilt or reinstalled. Downloads are verified against signed release metadata. See [installation updates](../install.md#updates).

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
root help. A trailing `--help` or `-h` selects common help. Help does not start
the requested operation.

## Build identity

`syq --build-identity` prints the executable’s build identity. Use it to
compare a source build with its SSH helper; matching version numbers alone do
not establish compatibility. See [development builds](../development.md#another-platform-with-your-own-helpers).
