# syq clean-partials

Remove leftover syq partial files below one or more local or SSH directory trees.
Stop copies writing into those trees before previewing or deleting partials:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
```

The command selects regular files with the current partial-name format, including
unrelated files deliberately given that name. It keeps directories and symlinks,
does not follow symlinks, and does not select older partial formats or `.syq-swap-...`
recovery entries. See [interrupted-copy recovery](../reference.md#resume-an-interrupted-copy)
before removing recovery data manually.

Only `workers` is accepted in `--performance-tuning`. Results use the
[`rm` record format](../automation.md#removal-records). All options follow.

<!-- CLI: clean-partials -->
```text
syq clean-partials [OPTIONS] <TREE>...
```

## Sources and selection

| Argument / option | Meaning |
|---|---|
| `--on <ENDPOINT>` | Removal endpoint ([USER@]HOST[:PORT]); omitted means local |
| `-C, --cwd <DIR>` | Resolve relative trees from DIR at the removal endpoint |
| `--root <DIR>` | Confine traversal beneath DIR |
| `<TREE>...` | Directory trees to search |

## Preview and output

| Argument / option | Meaning |
|---|---|
| `-n, --dry-run` | Preview without changing copy/removal data; remote setup may still cache the helper or install syq; requested results files are still written |
| `-v, --verbose...` | List removed paths |
| `-q, --quiet` | Suppress non-error messages |

## Performance tuning

| Argument / option | Meaning |
|---|---|
| `--performance-tuning <KEY=VALUE,...>` | Choose parallelism and transfer settings. See [Performance tuning](../tuning.md) for every key, default, and restriction. |

## Progress and results

| Argument / option | Meaning |
|---|---|
| `--progress` | Show progress even when stderr is not a terminal |
| `--no-progress` | Never show the human progress display |
| `--progress-json` | Emit machine-readable progress lines (JSON) on stderr |
| `--results <FILE>` | Write the machine-readable NDJSON result stream to FILE (created fresh; an existing file is refused) |
| `--results-fd <FD>` | Write the result stream to an inherited file descriptor the caller opened (e.g. `--results-fd 3 3>run.ndjson`); must be above 2 |

## SSH and transport

| Argument / option | Meaning |
|---|---|
| `--syq-path <PATH>` | Use this exact syq executable on the remote removal endpoint |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a helper |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->

