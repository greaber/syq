# syq clean-partials

Remove syq partial files below local or SSH directories. An interrupted copy
removes most of its own temporary files, but keeps partial files worth resuming
(see [Resume an interrupted copy](../reference.md#resume-an-interrupted-copy));
this command removes what remains. Wait for active copies into those
directories to finish before running cleanup:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
```

Add `--on server` to clean a remote tree. For results output, see
[Removal records](../automation.md#removal-records).

## Which files are removed

`clean-partials` removes syq partial files, named `.FILENAME.syq-tmp.RANDOM`,
and the `.syq-s3-HASH.partial` files that [S3 downloads](../object-storage.md)
leave beside the files they download; removing one of those means a later
download of that file starts over. It does not follow symlinks, and it does not
remove partial files left by older syq versions or the `.syq-stream-*` files
that a killed [descriptor copy](cp.md#completion-and-failures) can leave. A
regular file deliberately named like a partial is also selected, so preview
before deleting.

Interrupted replacements, replacements that race with another program, and
macOS clones can leave `.syq-swap-...` entries holding displaced files or
temporary clone data. Neither this command nor pruning removes them. Stop
copies using the destination, inspect these entries, and recover anything you
need before removing them yourself.

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
| `-n, --dry-run` | Preview without changing files; remote setup may still install syq, and requested results files are still written |
| `-v, --verbose...` | List removed paths |
| `-q, --quiet` | Suppress non-error messages |

## Performance tuning

| Argument / option | Meaning |
|---|---|
| `--performance-tuning <KEY=VALUE,...>` | Filesystem removal workers: [workers=N](../tuning.md#deletion) |

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
| `--syq-path <PATH>` | Run the syq at PATH on the remote machine instead of the matching copy syq installs automatically |
| `--no-bootstrap` | Run syq from the remote machine's PATH instead of the matching copy syq installs automatically |
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Whose SSH access to use: this machine's own (auto or ssh), or access approved by a receiving machine (@NAME) or SSH authorization provider (HOST) |
| `--pscope <PATH>` | Use the isolated connections and settings that `syq persist on --ephemeral` created at PATH |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->
