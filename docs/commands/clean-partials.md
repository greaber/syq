# syq clean-partials

Remove syq partial files below local or SSH directories. Wait for active copies
into those directories to finish before running cleanup:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
```

Add `--on server` to clean a remote tree. For results output, see
[Removal records](../automation.md#removal-records).

## Which files are removed

`clean-partials` removes regular files named `.FILENAME.syq-tmp.RANDOM`, with
16 random characters at the end. The filename portion may be shortened or
omitted. It does not follow symlinks or remove old partial-name formats.
A regular file deliberately named like a partial is also selected, so preview
before deleting.

Interrupted replacements and macOS clones can leave `.syq-swap-...` entries
containing displaced originals or temporary clone data. Neither this command
nor pruning removes them. Stop copies using the destination, inspect these
entries, and recover anything you need before removing them manually.

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
| `--performance-tuning <KEY=VALUE,...>` | Filesystem removal workers: [workers=N](../tuning.md#transfer-controls) |

## Progress and results

| Argument / option | Meaning |
|---|---|
| `--progress` | Show progress even when stderr is not a terminal |
| `--no-progress` | Never show the human progress display |
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
