# syq clean-partials

An interrupted copy keeps partial files so that a retry can resume (see
[Resume an interrupted copy](../reference.md#resume-an-interrupted-copy)).
When you no longer need to resume, remove them with this command. Let copies
into the directories finish first, and preview:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
```

Add `--on server` to clean a directory on an SSH server. For `--results`
output, see [Removal records](../automation.md#removal-records).

## Which files are removed

It removes regular files named `.FILENAME.syq-tmp.RANDOM`, left by copies, and
`.syq-s3-HASH.partial`, left by [S3 downloads](../object-storage.md), including
any file of yours with such a name. It does not follow symlinks, and it leaves
the `.syq-stream-*` files of killed
[descriptor copies](cp.md#completion-and-failures) alone.

Neither this command nor pruning removes `.syq-swap-...` recovery entries.
Each holds either a file that a copy moved aside while replacing it (after an
interruption, or when another program wrote the same name at the same time) or
a killed copy's own unfinished entry. Once no copy is using the destination,
recover what you need from them and delete them yourself.

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
| `--syq-path <PATH>` | Run the remote syq at PATH instead of syq's automatically installed copy |
| `--no-bootstrap` | Run the syq found in the remote $PATH instead of syq's automatically installed copy |
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Whose SSH access to use: this machine's own (auto or ssh), or access approved by a receiving machine (@NAME) or SSH authorization provider (HOST) |
| `--pscope <PATH>` | Use the isolated connections and settings that `syq persist on --ephemeral` created at PATH |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->
