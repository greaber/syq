# syq cp

Copy files, directories, and symlinks locally, over SSH, or with S3. See [Copy files](../reference.md) for examples and
[remote](../remote-reference.md) and [S3](../object-storage.md) copy details.

```sh
syq cp --srcs-in project --to server --into backup --dry-run -v
```

Put source selectors and `--mapping` before `--to` or a placement option.
For scripting, see [environment variables](../environment.md)
and [results](../automation.md).

<!-- CLI: cp -->
```text
syq cp [OPTIONS] SOURCE... [PLACEMENT]
syq cp [OPTIONS] --src-fd FD --as PATH
syq cp [OPTIONS] SOURCE --as-fd FD
```

<a id="sources-and-selection"></a>

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
| `[PATH]...` | Named source objects (shorthand for --src) |

<a id="destination-placement"></a>

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

<a id="copy-policy-and-filtering"></a>

## Updates and deletion

| Argument / option | Meaning |
|---|---|
| `--only-new` | Copy entries found missing; keep metadata of entries found present; adding children requires write access |
| `--inplace` | Update destination files directly, using no full-sized staging file; interruption can leave them incomplete |
| `--prune` | After copying, remove target-only objects in mapped directory scopes; ignored source paths remain protected |
| `--max-delete <N>` | With --prune, refuse all removals if more than N are planned |

## Metadata and symlinks

| Argument / option | Meaning |
|---|---|
| `--follow` | Follow symlinks in all directly supplied filesystem paths |
| `--follow-src` | Follow symlinks in directly supplied source paths |
| `--follow-dst` | Follow symlinks in directly supplied destination paths |
| `--preserve <FEATURE>` | Preserve times, permissions or ownership, or copy special files (repeatable/comma-separated)<br><br>Possible values:<br>- times: Preserve modification times (already the default for named destinations)<br>- permissions: Preserve permission bits<br>- ownership: Preserve owner and group IDs<br>- specials: Copy device nodes and special files |

<a id="integrity-checking"></a>

## Verification

| Argument / option | Meaning |
|---|---|
| `--hash` | Hash existing source and destination files instead of trusting size and modification time |
| `--integrity-checking <KEY=VALUE,...>` | [Payload checks](../integrity-checking.md) |

<a id="ssh-and-transport"></a>

<a id="remote-to-remote-transfers"></a>

## Connections and remote execution

| Argument / option | Meaning |
|---|---|
| `--no-compress` | Disable transport compression |
| `--receiver-max-entries <N>` | Command-restricted receiver ceiling: refuse to touch more than N destination entries |
| `--receiver-max-bytes <SIZE>` | Command-restricted receiver ceiling: refuse to write more than SIZE bytes of file data in total |
| `--receiver-receipt <DETAIL>` | Command-restricted receiver receipt detail: final sizes (default) or also final BLAKE3 file hashes<br><br>Possible values:<br>- sizes: Final type and size of every path the transfer could have changed<br>- hashes: Sizes plus a closure-time BLAKE3 hash of every regular file |
| `--auth-from <auto\|ssh\|@NAME>` | Authorize with a live receiving machine, or use SSH from this machine (default: auto) |
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

<a id="performance-tuning"></a>

<a id="resource-limits"></a>

## Performance and resource limits

| Argument / option | Meaning |
|---|---|
| `--performance-tuning <KEY=VALUE,...>` | [Workers, request sizes, and copy methods](../tuning.md) |
| `--resource-limits <KEY=VALUE,...>` | [Bandwidth and concurrency ceilings](../resource-limits.md) |
| `--recycle-staging <SIZE>` | Reuse retired destination files (Linux only); old handles may see new contents. Requires exclusive destination access |

<a id="progress-and-results"></a>

<a id="preview-and-output"></a>

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
| `--stats` | Print transfer statistics, worker waits, endpoint operations and CPU at the end |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Update policies

`--into-existing` requires the destination directory to exist but allows new
files inside it. `--only-new` can add children to an existing directory, but
does not change that directory's permissions to make it writable.

`--only-new` cannot combine with `--inplace`: an interrupted write could leave
a file that a retry skips. Restricted receivers also reject `--as-new --inplace`,
because direct writes do not enforce that destination condition. S3 and named
receiving destinations do not support `--inplace`; see
[Copy limits](../persistence-reference.md#copy-limits).

These policies do not disable requested pruning. Descriptor-specific
restrictions are listed under [file descriptors](#file-descriptors).

## Pruning

`--prune` deletes only within the copied directories, after copying succeeds.
Ignored paths, syq partial files, and recovery entries are
kept. This also keeps their parent directories; extra hard links to copied
files may be kept too. An interruption during deletion can leave some extras
already removed.

Keep the source outside the destination. Syq detects overlap locally and for
remote paths using the same host name, user, and port. Different SSH aliases
or shared storage can hide overlap from this check. Wait for other copies
into the destination to finish before pruning, so their new files are not
deleted as extras.

## Filename and type conflicts

If the source has both `Report.txt` and `report.txt`, a case-insensitive
destination cannot store both. Syq does not check for that before copying,
and one file can replace the other. The same problem applies to distinct
Unicode spellings that the destination treats as one name. Rename the source
entries or use a destination that can distinguish them. Unsupported names
are reported as copy errors.

Syq refuses replacements between directories and non-directories, including
empty directories. Move or remove the conflicting destination before retrying.
Other replacements can fail if the filesystem lacks the operation needed to
replace an entry safely; the old entry is kept.

## Capacity checks

For missing or empty filesystem destinations, syq checks available bytes and
capacity for new files when the filesystem reports them. A clear shortage
fails before copying. Updates to populated destinations do not use this whole-copy
estimate: existing data may be reused or replaced. Allocation errors still
fail the affected copy.

## Metadata details

Source setuid, setgid, and sticky bits are not copied without
`--preserve=permissions`. Ownership uses numeric IDs. On macOS, an existing
destination directory must be readable before syq can temporarily repair
missing write or search permission.

Modification times are preserved for named file destinations. Output
descriptors require explicit `--preserve=times`; see below.

## File descriptors

`--src-fd 0` reads stdin; `--as-fd 1` writes stdout. Use them to connect local,
SSH, or S3 copies to other programs; see
[Shell pipelines and file descriptors](../reference.md#shell-pipelines-and-file-descriptors).
Bash process substitution also works with ordinary source syntax:

```sh
syq cp --src <(gzip -c data) --to server --as data.gz
```

Paths such as `/dev/fd/63` refer to descriptors in the local syq process.

Each stream copy takes one source. Stdin and process substitution have no
filename, so use `--as` to choose one, or `--as-fd` to write to a descriptor.
A named pipe can use `--into`: `syq cp incoming.fifo --into saved` waits for a
writer, then saves its bytes as the regular file `saved/incoming.fifo`.
A symlink to a pipe requires `--follow-src`. Selecting a pipe alongside other
sources, including through a shell glob, is an error. Directory copies never
read pipes; `--preserve=specials` copies the pipe itself.

### Completion and failures

A named destination is replaced only after the transfer succeeds. The `-new`
and `-existing` placement conditions apply as usual, before a named pipe is
opened. S3 new-object writes also refuse replacement if an object appears
during the upload.

If the producer fails halfway through, syq can still successfully save the
bytes it received: EOF does not tell it whether the producer succeeded.
Bash's `set -o pipefail` detects failures in a pipeline but cannot undo a file
already saved. Process substitution needs a separate check of the producer's
status. In Python, [managed streams](https://greaber.github.io/syq/python-reference.html#byte-streams) let you commit
only after your producer succeeds.

An output descriptor may contain incomplete data after a failure. Check syq's
exit status before using the result. A consumer closing early makes syq fail.
Forced termination can leave a `.syq-stream-*` temporary file beside the
destination.

### Options and file behavior

Progress, `--stats`, and `-v` go to stderr, leaving stdout for payload.
Statistics report bytes, elapsed time, and average rate; pipe lengths are
unknown until EOF. Use `--resource-limits bandwidth=RATE` to limit throughput.

<a id="selection-and-previews"></a>

`--only-new` skips a destination that exists. Existing directories, S3 key
prefixes, and dangling symlinks also count as existing for `--only-new`. Skips succeed without reading input or
opening a named FIFO. A shell producer can therefore receive SIGPIPE; in Python, check the writer's
`skipped` property before producing bytes. An output FD already exists, so
`--only-new --as-fd N` always skips after validating the source.

Use `--dry-run` to check source and destination placement without reading input,
opening a named pipe, or changing the destination. It cannot check a payload
hash or predict the length of a pipe. `--results` and `--results-fd` report
[`stream_result`](../automation.md#stream_result) records separately from payload;
results and payload/completion descriptors must differ.

### Transport and limits

Filesystem streams use parallel data workers over SSH or encrypted TCP, with
automatic worker tuning as in regular-file copies. They accept `workers`,
`request-size`, `pipeline-depth`, and `bw-pacing` tuning; `workers=N` fixes the
worker count, and `--no-tcp` keeps data on SSH. S3 transfers one object using
multipart controls; see [Descriptor copies](../object-storage.md#descriptor-copies).

Restart recovery, named receiving destinations, detached execution,
directory selection, and content comparison are unsupported.

### Descriptor offsets and metadata

Other inherited descriptors work too, except 2, which is reserved for
diagnostics. Dedicate each descriptor to the copy. Syq advances its offset,
respects append mode, and leaves its blocking mode alone;
it does not truncate it. A literal `-` is a filename.

When a regular file is copied to a named destination, syq preserves its
modification time. New named files use the source permissions limited by the
destination umask; existing files keep their permissions. S3 uploads store file
attributes in object metadata.

Output descriptors use the timestamps from normal writes, including when
appending to an existing file. Add `--preserve=times` to copy the source
modification time instead; this changes the whole destination file's timestamp
even for a partial write. `--preserve=permissions,ownership` copies those
attributes without changing timestamps. S3 downloads interpret object metadata
when attributes are requested; time preservation uses S3's modification time if
no syq attributes are stored.

Input pipes, sockets, and devices have no payload metadata, so they reject
`--preserve`. Their new named destinations use `0666` limited by the umask
and the time of the write; existing files keep their permissions.
Output pipes likewise cannot preserve times, permissions, or ownership. Parent
directories are created as needed. The source `--cwd` / `--root` options
apply to pathname sources. `--root` with `--src-fd` is rejected because it cannot
confine a descriptor that is already open. Symlink handling is unchanged; see [Symlinks](../reference.md#symlinks). Named remote
sources must be regular files.
