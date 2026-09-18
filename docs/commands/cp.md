# syq cp

Copy files, directories, and symlinks locally, over SSH, or to, from, and between
S3 buckets. This page lists every `cp` option. For examples and copy behavior,
see [Copy files](../reference.md); the [remote](../remote-reference.md) and
[S3](../object-storage.md) references describe route-specific restrictions.

```sh
syq cp --srcs-in project --to server --into backup --dry-run -v
```

Put source endpoints, source bases, selectors, and `--mapping` before the first
`--to` or placement option. Other options may follow the destination.
Use `--src=-name` or `--ignore=-pattern` when a value begins with a dash.

Directories are recursive, symlinks are copied as links, and modification times
are preserved. New files use source permissions filtered by the destination
umask; existing files keep their permissions unless `--preserve` requests otherwise.
Matching files are skipped by size and timestamp; selected files may be overwritten.
Unrelated destination entries remain unless you request `--prune`.

Local-only copies and pruning require a placement option. Without placement,
`--to server` copies into the remote home directory and `--from server` fetches
into the local current directory. [Receiving profiles](../receive.md#names-and-paths)
and [S3 keys](../object-storage.md) have their own destination bases.

`--mapping` replaces source selectors and cannot combine with `--as`, `--prune`,
or `--detach`. See [mapping rules](../mappings.md#semantics-and-limits).
The [overwrite policies](../reference.md#choose-which-existing-files-to-update)
explain conflicts among `--only-new`, `--only-existing`, `--skip-newer`, and
`--inplace`; [integrity checking](../integrity-checking.md) covers verification
and expected hashes. The advanced tables below link to every supported key.

`SYQ_CP_OPTIONS` supplies extra arguments before command-line arguments; see
[environment variables](../reference.md#environment-variables-and-local-files).
For exit codes and structured results, see [Automation results](../automation.md).

<!-- CLI: cp -->
```text
syq cp [OPTIONS] SOURCE... [PLACEMENT]
```

## Sources and selection

| Argument / option | Meaning |
|---|---|
| `--from <ENDPOINT>` | Source endpoint ([USER@]HOST[:PORT] or s3://BUCKET); omitted means local |
| `-C, --cwd <DIR>` | Resolve relative source selectors from DIR |
| `--root <DIR>` | Resolve source selectors beneath DIR and refuse any escape |
| `--follow` | Follow symlinks in all directly supplied filesystem paths |
| `--follow-src` | Follow symlinks in directly supplied source paths |
| `--src <PATH>` | Select a named source object; attach =PATH when it begins with `-` (repeatable) |
| `--srcs-in <DIR>` | Select a directory's contents; attach =DIR when it begins with `-` (repeatable) |
| `--src-non-dir <PATH>` | Select a named non-directory source object; attach =PATH when it begins with `-` (repeatable) |
| `--src-dir <DIR>` | Select a named source directory; attach =DIR when it begins with `-` (repeatable) |
| `--src-non-dirs <PATH>...` | Select several named non-directory source objects |
| `--src-dirs <DIR>...` | Select several named source directories |
| `--srcs <PATH>...` | Select several named source objects |
| `[PATH]...` | Named source objects (shorthand for --src) |

## Destination placement

| Argument / option | Meaning |
|---|---|
| `--to <ENDPOINT>` | Destination SSH endpoint, @NAME, or s3://BUCKET; placement defaults to --into |
| `--follow-dst` | Follow symlinks in directly supplied destination paths |
| `--into <DIR>` | Put selected names inside DIR, creating it if necessary |
| `--into-new <DIR>` | Put selected names inside DIR, which must not exist |
| `--into-existing <DIR>` | Put selected names inside an existing directory |
| `--as <PATH>` | Map one named source exactly to PATH; never follow its final entry |
| `--as-new <PATH>` | Map one named source exactly to PATH; its final entry must not exist and is never followed |
| `--as-existing <PATH>` | Map one named source exactly to PATH; its final entry must exist and is never followed |

## Copy policy and filtering

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable; S3-to-S3 metadata/tag overrides are refused) |
| `--mapping <FILE>` | Copy the entries of a local NDJSON mapping manifest (`-` reads stdin), acquired before destination changes, instead of selecting sources; entry src paths are relative to -C and dst paths are relative to the --into container |
| `--verify-only` | Compare selected contents without writing; fail on differences or inspection errors |
| `--only-new` | Copy entries found missing; keep metadata of entries found present; adding children requires write access |
| `--only-existing` | Update only entries already present; create no missing entries or directories |
| `--skip-newer` | Skip regular files newer at the destination; non-directory type replacements still occur |
| `--ignore <PATTERN>` | Skip paths matching a gitignore-style pattern (repeatable) |
| `--ignore-from <FILE>` | Securely open and read gitignore-style patterns from raw-byte FILE (repeatable; stacks in command-line order) |
| `--preserve <FEATURE>` | Preserve permissions or ownership, or copy special files (repeatable/comma-separated)<br><br>Possible values:<br>- permissions: Preserve permission bits<br>- ownership: Preserve owner and group IDs<br>- specials: Copy device nodes and special files |
| `--inplace` | Update destination files directly, using no full-sized staging file; interruption can leave them incomplete |
| `--max-size <SIZE>` | Skip regular source files larger than SIZE; --prune protects their destination paths |
| `--min-size <SIZE>` | Skip regular source files smaller than SIZE; --prune protects their destination paths |
| `--prune` | After copying, remove target-only objects in mapped directory scopes; ignored and size-excluded source paths remain protected |
| `--max-delete <N>` | With --prune, refuse all removals if more than N are planned |

## Integrity checking

| Argument / option | Meaning |
|---|---|
| `--hash` | Hash existing source and destination files instead of trusting size and modification time |
| `--expected-hash <ALGORITHM:HEX>` | Require one regular file to match ALGORITHM:HEX |
| `--integrity-checking <KEY=VALUE,...>` | Choose comparison and payload checks. See [Integrity checking](../integrity-checking.md) for every key, default, and algorithm. |

## Performance tuning

| Argument / option | Meaning |
|---|---|
| `--performance-tuning <KEY=VALUE,...>` | Choose parallelism and transfer settings. See [Performance tuning](../tuning.md) for every key, default, and restriction. |

## Resource limits

| Argument / option | Meaning |
|---|---|
| `--resource-limits <KEY=VALUE,...>` | Set resource ceilings. See [Resource limits](../resource-limits.md) for every key, unit, and restriction. |

## SSH and transport

| Argument / option | Meaning |
|---|---|
| `--no-compress` | Disable transport compression |
| `--auth-from <auto\|ssh\|@NAME>` | Authorize with a live receiving machine, or use SSH from this machine (default: auto) |
| `--via <@NAME>` | Alias for --auth-from @NAME |
| `--rsh <COMMAND>` | Remote shell command (default: ssh); the command owns SSH and agent policy when set |
| `--syq-path <PATH>` | Use this remote syq executable instead of installing a helper |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a helper |
| `--tcp-plain` | Use TCP data connections without encryption (trusted networks only) |
| `--no-tcp` | Send file data through SSH rather than separate TCP data connections |
| `--tcp-ports <LO-HI>` | Port range remote listeners use for TCP data connections<br><br>[default: 47600-47699] |
| `--tcp-congestion <ALGO>` | Use this congestion-control algorithm for TCP data sockets (Linux only) |
| `--pscope <PATH>` | Use an ephemeral SSH persistence scope created by `syq persist on --ephemeral` |

## Remote-to-remote transfers

| Argument / option | Meaning |
|---|---|
| `--receiver-max-entries <N>` | Command-restricted receiver ceiling: refuse to touch more than N destination entries |
| `--receiver-max-bytes <SIZE>` | Command-restricted receiver ceiling: refuse to write more than SIZE bytes of file data in total |
| `--receiver-receipt <DETAIL>` | Command-restricted receiver receipt detail: final sizes (default) or also final BLAKE3 file digests<br><br>Possible values:<br>- sizes: Final type and size of every path the transfer could have changed<br>- digests: Sizes plus a closure-time BLAKE3 digest of every regular file |
| `--coordinate-at <COORDINATE_AT>` | Choose the endpoint that runs the coordinator<br><br>Possible values:<br>- auto: Run locally unless both endpoints are remote, then run at the source<br>- src: Run the coordinator at the source endpoint<br>- dst: Run the coordinator at the destination endpoint<br>- local: Keep the coordinator on the invoking machine and relay the data there<br><br>[default: auto] |
| `--detach` | Run at the remote coordinator and return after launch; requires --peer-auth own-credentials or --rsh |
| `--peer-auth <MODE>` | How the coordinator authenticates to the peer (see the values below); --rsh takes over this policy entirely<br><br>Possible values:<br>- restricted: Constrained agent broker plus the command-restricted receiver on the peer<br>- broker: Constrained agent broker only; the peer runs no command-restricted receiver<br>- own-credentials: Forward nothing; the coordinator must hold its own credentials for the peer<br>- full-agent: Expose the complete local SSH agent to the coordinator, as `ssh -A` would<br><br>[default: restricted] |

## Progress and results

| Argument / option | Meaning |
|---|---|
| `--results <FILE>` | Write the machine-readable NDJSON result stream to FILE (created fresh; an existing file is refused) |
| `--results-fd <FD>` | Write the result stream to an inherited file descriptor the caller opened (e.g. `--results-fd 3 3>run.ndjson`); must be above 2 |
| `--progress` | Show progress even when stderr is not a terminal |
| `--no-progress` | Never show the human progress display |
| `--progress-json` | Emit machine-readable progress lines (JSON) on stderr |
| `--stats` | Print transfer statistics, worker waits, endpoint operations and CPU at the end |

## Preview and output

| Argument / option | Meaning |
|---|---|
| `-n, --dry-run` | Preview without changing copy/removal data; remote setup may still cache the helper or install syq; requested results files are still written |
| `-v, --verbose...` | List files with -v; explain helpers and transport with -vv |
| `-q, --quiet` | Suppress non-error messages |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->

