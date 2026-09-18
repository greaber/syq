# syq cp

Copy files, directories, and symlinks locally, over SSH, or with S3. See [Copy files](../reference.md) for examples and
[remote](../remote-reference.md) and [S3](../object-storage.md) copy details.

```sh
syq cp --srcs-in project --to server --into backup --dry-run -v
```

Put source selectors and `--mapping` before `--to` or a placement option.
For scripting, see [environment variables](../reference.md#environment-variables-and-local-files)
and [results](../automation.md).

## File descriptors

Use a pipe or process substitution as an explicit local source. `--src`,
`--src-non-dir`, and positional sources accept these inputs. Use `--src-fd 0`
to read stdin, or `--as-fd 1` to send one file's contents to stdout. The other
endpoint can be a local file, an SSH file, or an
[S3 object](../object-storage.md#descriptor-copies):

```sh
gzip -c data | syq cp --src-fd 0 --to server --as data.gz
syq cp --src <(gzip -c data) --to server --as data.gz
syq cp --from server data.gz --as-fd 1 | gzip -dc > data
syq cp --src-non-dir incoming.fifo --into saved
syq cp data.bin --as-fd 3 3>received.bin
```

Each stream copy takes exactly one source. Reading a FIFO waits for a writer.
A FIFO or descriptor path among several sources is an error before any files
are copied, including when a shell glob expands to both files and a FIFO.
A named FIFO has a basename:
`--into saved` puts `incoming.fifo` at `saved/incoming.fifo` as a regular file.
An inherited descriptor or process-substitution path has no usable name;
choose `--as PATH`, `--as-new PATH`, `--as-existing PATH`, or `--as-fd FD`. Syq never uses a descriptor number as an
output name. `--src-fd` replaces source paths and `--from`; `--as-fd` replaces
`--to` and destination placement. Both together copy between descriptors.
Put source arguments before destination arguments. A literal `-` is a filename.

Only explicitly selected local FIFOs are consumed. Recursive copies keep the
normal special-file behavior, and `--preserve=specials` copies FIFO nodes
instead of reading their contents. Ordinary source symlinks retain their usual
behavior; use `--follow-src` to read a symlink to a FIFO. Descriptor paths such
as `/dev/fd/N` and `/proc/self/fd/N` refer to the invoking process and are read
locally before data is sent to a helper. Remote path sources must be regular files.

Descriptors must be inherited and open in the requested direction. Descriptor
2 is reserved for diagnostics. Dedicate each descriptor to the transfer. Reads
and writes advance its current offset; append mode is respected. Syq preserves
its blocking or nonblocking mode and does not truncate, rename, or apply
metadata to a descriptor. Small native stream writes are forwarded without
waiting for a full transfer block or EOF. No progress or summary is emitted,
so stdout contains only payload when selected as the output.

Named file destinations are published after the complete input has been
written and checked. Existing regular-file permission bits are kept; new
files use `0666` filtered by the destination process's umask. Ownership follows
normal destination creation rules, and modification time is the time of writing.
Source metadata is not copied. Parent directories are created if needed.
The `-new` and `-existing` placement variants apply the same conditions as
other copies: `--as-new` and `--as-existing` check the destination entry;
`--into-new` and `--into-existing` check the container, not the file inside it.
Filesystem conditions are checked before transfer. S3 new-object writes also
refuse replacement if an object appears before publication.
Use `--cwd` to resolve a relative pathname source, or `--root` to confine it
beneath a directory (an S3 key prefix for S3 sources). An inherited descriptor
already refers to an open object and cannot be confined with `--root`.
Directly supplied symlink parents require `--follow-src` or `--follow-dst`;
a destination's final symlink is replaced, never followed.

EOF finishes input. Syq cannot distinguish a successful producer from one
that exited early. In Bash, `set -o pipefail` reports a pipeline producer or
consumer failure, but cannot undo a destination already published. Process
substitutions run separately; check their exit status separately. An output
descriptor can contain partial data after failure; require a successful syq
exit before treating it as complete. A consumer closing early makes syq fail.

Stream copies use bounded buffers and apply backpressure. File transfers over
SSH use a single SSH connection and the usual helper bootstrap and version checks.
They do not support named receiving destinations, detached execution, restart
recovery, directory selection, comparison policies, metadata preservation,
dry runs, result records, statistics, or file-copy tuning. Unsupported options
are rejected before transferring. S3 has its own
[part controls and limits](../object-storage.md#descriptor-copies).

A cancelled file upload removes its temporary file when cleanup completes;
forced termination can leave a `.syq-stream-*` file in the destination directory.

<!-- CLI: cp -->
```text
syq cp [OPTIONS] SOURCE... [PLACEMENT]
syq cp [OPTIONS] --src-fd FD --as PATH
syq cp [OPTIONS] SOURCE --as-fd FD
```

## Sources and filtering

| Argument / option | Meaning |
|---|---|
| `--src-fd <FD>` | Read raw bytes from an inherited local descriptor (0 for stdin), instead of a source path |
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
| `--as-fd <FD>` | Write raw bytes to an inherited local descriptor (1 for stdout), instead of a destination path |
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
| `--resource-limits <KEY=VALUE,...>` | [Bandwidth and concurrency ceilings](../resource-limits.md) |

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
