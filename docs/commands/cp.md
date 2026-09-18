# syq cp

Copy files, directories, and symlinks locally, over SSH, or with S3. See [Copy files](../reference.md) for examples and
[remote](../remote-reference.md) and [S3](../object-storage.md) copy details.

```sh
syq cp --srcs-in project --to server --into backup --dry-run -v
```

Put source selectors and `--mapping` before `--to` or a placement option.
For scripting, see [environment variables](../reference.md#environment-variables-and-local-files)
and [results](../automation.md).

<!-- CLI: cp -->
```text
syq cp [OPTIONS] SOURCE... [PLACEMENT]
```

## Sources and filtering

| Argument / option | Meaning |
|---|---|
| `--from <ENDPOINT>` | Source endpoint ([USER@]HOST[:PORT] or s3://BUCKET); omitted means local |
| `-C, --cwd <DIR>` | Resolve relative source selectors from DIR |
| `--root <DIR>` | Resolve source selectors beneath DIR and refuse any escape |
| `--src <PATH>` | Select a named source object; attach =PATH when it begins with `-` (repeatable) |
| `--srcs-in <DIR>` | Select a directory's contents; attach =DIR when it begins with `-` (repeatable) |
| `--src-non-dir <PATH>` | Select a named non-directory source object; attach =PATH when it begins with `-` (repeatable) |
| `--src-dir <DIR>` | Select a named source directory; attach =DIR when it begins with `-` (repeatable) |
| `--src-non-dirs <PATH>...` | Select several named non-directory source objects |
| `--src-dirs <DIR>...` | Select several named source directories |
| `--srcs <PATH>...` | Select several named source objects |
| `--ignore <PATTERN>` | Skip paths matching a gitignore-style pattern (repeatable) |
| `--ignore-from <FILE>` | Securely open and read gitignore-style patterns from raw-byte FILE (repeatable; stacks in command-line order) |
| `--max-size <SIZE>` | Skip regular source files larger than SIZE; --prune protects their destination paths |
| `--min-size <SIZE>` | Skip regular source files smaller than SIZE; --prune protects their destination paths |
| `[PATH]...` | Named source objects (shorthand for --src) |

## Destination and mapping

| Argument / option | Meaning |
|---|---|
| `--to <ENDPOINT>` | Destination SSH endpoint, @NAME, or s3://BUCKET; placement defaults to --into |
| `--into <DIR>` | Put selected names inside DIR, creating it if necessary |
| `--into-new <DIR>` | Put selected names inside DIR, which must not exist |
| `--into-existing <DIR>` | Put selected names inside an existing directory |
| `--as <PATH>` | Map one named source exactly to PATH; never follow its final entry |
| `--as-new <PATH>` | Map one named source exactly to PATH; its final entry must not exist and is never followed |
| `--as-existing <PATH>` | Map one named source exactly to PATH; its final entry must exist and is never followed |
| `--mapping <FILE>` | Copy the entries of a local NDJSON mapping manifest (`-` reads stdin), acquired before destination changes, instead of selecting sources; entry src paths are relative to -C and dst paths are relative to the --into container |

## Updates and deletion

| Argument / option | Meaning |
|---|---|
| `--only-new` | Copy entries found missing; keep metadata of entries found present; adding children requires write access |
| `--only-existing` | Update only entries already present; create no missing entries or directories |
| `--skip-newer` | Skip regular files newer at the destination; non-directory type replacements still occur |
| `--inplace` | Update destination files directly, using no full-sized staging file; interruption can leave them incomplete |
| `--prune` | After copying, remove target-only objects in mapped directory scopes; ignored and size-excluded source paths remain protected |
| `--max-delete <N>` | With --prune, refuse all removals if more than N are planned |

## Metadata and symlinks

| Argument / option | Meaning |
|---|---|
| `--follow` | Follow symlinks in all directly supplied filesystem paths |
| `--follow-src` | Follow symlinks in directly supplied source paths |
| `--follow-dst` | Follow symlinks in directly supplied destination paths |
| `--preserve <FEATURE>` | Preserve permissions or ownership, or copy special files (repeatable/comma-separated)<br><br>Possible values:<br>- permissions: Preserve permission bits<br>- ownership: Preserve owner and group IDs<br>- specials: Copy device nodes and special files |

## Verification

| Argument / option | Meaning |
|---|---|
| `--hash` | Hash existing source and destination files instead of trusting size and modification time |
| `--expected-hash <ALGORITHM:HEX>` | Require one regular file to match ALGORITHM:HEX |
| `--verify-only` | Compare selected contents without writing; fail on differences or inspection errors |
| `--integrity-checking <KEY=VALUE,...>` | [Comparison and transfer checksums](../integrity-checking.md) |

## Connections and remote execution

| Argument / option | Meaning |
|---|---|
| `--no-compress` | Disable transport compression |
| `--receiver-max-entries <N>` | Command-restricted receiver ceiling: refuse to touch more than N destination entries |
| `--receiver-max-bytes <SIZE>` | Command-restricted receiver ceiling: refuse to write more than SIZE bytes of file data in total |
| `--receiver-receipt <DETAIL>` | Command-restricted receiver receipt detail: final sizes (default) or also final BLAKE3 file digests<br><br>Possible values:<br>- sizes: Final type and size of every path the transfer could have changed<br>- digests: Sizes plus a closure-time BLAKE3 digest of every regular file |
| `--auth-from <auto\|ssh\|@NAME>` | Authorize with a live receiving machine, or use SSH from this machine (default: auto) |
| `--via <@NAME>` | Alias for --auth-from @NAME |
| `--coordinate-at <COORDINATE_AT>` | Choose the endpoint that runs the coordinator<br><br>Possible values:<br>- auto: Run locally unless both endpoints are remote, then run at the source<br>- src: Run the coordinator at the source endpoint<br>- dst: Run the coordinator at the destination endpoint<br>- local: Keep the coordinator on the invoking machine and relay the data there<br><br>[default: auto] |
| `--rsh <COMMAND>` | Remote shell command (default: ssh); the command owns SSH and agent policy when set |
| `--syq-path <PATH>` | Use this remote syq executable instead of installing a helper |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a helper |
| `--tcp-plain` | Use TCP data connections without encryption (trusted networks only) |
| `--no-tcp` | Send file data through SSH rather than separate TCP data connections |
| `--tcp-ports <LO-HI>` | Port range remote listeners use for TCP data connections<br><br>[default: 47600-47699] |
| `--tcp-congestion <ALGO>` | Use this congestion-control algorithm for TCP data sockets (Linux only) |
| `--detach` | Run at the remote coordinator and return after launch; requires --peer-auth own-credentials or --rsh |
| `--peer-auth <MODE>` | How the coordinator authenticates to the peer (see the values below); --rsh takes over this policy entirely<br><br>Possible values:<br>- restricted: Constrained agent broker plus the command-restricted receiver on the peer<br>- broker: Constrained agent broker only; the peer runs no command-restricted receiver<br>- own-credentials: Forward nothing; the coordinator must hold its own credentials for the peer<br>- full-agent: Expose the complete local SSH agent to the coordinator, as `ssh -A` would<br><br>[default: restricted] |
| `--pscope <PATH>` | Use an ephemeral SSH persistence scope created by `syq persist on --ephemeral` |

## S3 connection settings

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable; S3-to-S3 metadata/tag overrides are refused) |

## Performance and resource limits

| Argument / option | Meaning |
|---|---|
| `--performance-tuning <KEY=VALUE,...>` | [Workers, request sizes, and copy methods](../tuning.md) |
| `--resource-limits <KEY=VALUE,...>` | [Bandwidth limit](../resource-limits.md) |

## Preview, progress, and results

| Argument / option | Meaning |
|---|---|
| `--results <FILE>` | Write the machine-readable NDJSON result stream to FILE (created fresh; an existing file is refused) |
| `--results-fd <FD>` | Write the result stream to an inherited file descriptor the caller opened (e.g. `--results-fd 3 3>run.ndjson`); must be above 2 |
| `-n, --dry-run` | Preview without changing copy/removal data; remote setup may still cache the helper or install syq; requested results files are still written |
| `-v, --verbose...` | List files with -v; explain helpers and transport with -vv |
| `-q, --quiet` | Suppress non-error messages |
| `--progress` | Show progress even when stderr is not a terminal |
| `--no-progress` | Never show the human progress display |
| `--progress-json` | Emit machine-readable progress lines (JSON) on stderr |
| `--stats` | Print transfer statistics, worker waits, endpoint operations and CPU at the end |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->
