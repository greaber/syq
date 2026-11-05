# syq cp

Copy files, directories, and symlinks locally, over SSH, or with S3. See [Copy files](../reference.md) for examples and
[remote](../remote-reference.md) and [S3](../object-storage.md) copy details.

```sh
syq cp --srcs-in project --to server --into backup --dry-run -v
```

Put source selectors and `--mapping` before `--to` or a placement option.
For scripting, `SYQ_CP_OPTIONS` supplies extra arguments and `SYQ_AUTH_FROM`
chooses authorization; see [environment variables](../environment.md)
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
| `-C, --cwd <DIR>` | Resolve relative source paths from DIR |
| `--root <DIR>` | Resolve source paths inside DIR and refuse any that lead outside it |
| `--src <PATH>` | Select a named source object (repeatable) |
| `--srcs-in <DIR>` | Select a directory's contents (repeatable) |
| `--src-non-dir <PATH>` | Select a named non-directory source object (repeatable) |
| `--src-dir <DIR>` | Select a named source directory (repeatable) |
| `--src-non-dirs <PATH>...` | Select several named non-directory source objects |
| `--src-dirs <DIR>...` | Select several named source directories |
| `--srcs <PATH>...` | Select several named source objects |
| `--where <EXPR>` | Copy only the non-directory entries that match a source expression; directories are not filtered |
| `--ignore <PATTERN>` | Skip paths matching a gitignore-style pattern (repeatable) |
| `--ignore-from <FILE>` | Read gitignore-style patterns from FILE (repeatable; applied in command-line order with --ignore) |
| `[PATH]...` | Named source objects (shorthand for --src) |

<a id="destination-placement"></a>

## Destination and mapping

| Argument / option | Meaning |
|---|---|
| `--as-fd <FD>` | Write raw bytes to an inherited local descriptor (1 for stdout), instead of a destination path |
| `--to <ENDPOINT>` | Destination SSH endpoint, receiving name (@NAME), or s3://BUCKET; without a placement option, copy into its starting directory (--into .) |
| `--into <DIR>` | Put selected names inside DIR, creating it if necessary |
| `--into-new <DIR>` | Put selected names inside DIR, which must not exist |
| `--into-existing <DIR>` | Put selected names inside an existing directory |
| `--as <PATH>` | Copy one named source to exactly PATH; a symlink at PATH is not followed |
| `--as-new <PATH>` | Like --as, but PATH must not exist |
| `--as-existing <PATH>` | Like --as, but PATH must already exist |
| `--mapping <FILE>` | Copy the entries of a local NDJSON mapping file (`-` reads stdin) instead of selecting sources; src paths are relative to -C and dst paths to the --into directory. Cannot be combined with --ignore or --ignore-from |

<a id="copy-policy-and-filtering"></a>

## Updates and deletion

| Argument / option | Meaning |
|---|---|
| `--if-exists <POLICY>` | How to handle existing destination files<br><br>Possible values:<br>- error-if-different: Reject detected content differences; trusts matching size and mtime unless --hash is set<br>- error: Report an error for every existing destination file<br>- keep: Leave existing entries and their metadata alone<br>- update: Update contents when they differ and apply requested metadata<br>- update-if-older: Keep newer destinations; otherwise update differing contents<br><br>[default: update] |
| `--copy-if <EXPR>` | Update only entries satisfying a source/destination expression |
| `--in-place <MODE>` | Write files directly at their final names, with no staging file; interruption can leave them incomplete<br><br>Possible values:<br>- new: Only files the copy creates; an existing file is still replaced through a staging file<br>- update: Also existing files that syq can update where they are, writing only what changed; others are replaced. Anyone who has such a file open can read its new contents, and an interruption leaves it partly updated |
| `--prune` | After copying, remove destination entries the source does not have, within the copied directories; ignored paths are kept |
| `--prune-before` | Like --prune, but remove the extra entries before copying to free space; a later copy failure does not restore them |
| `--max-delete <N>` | With --prune or --prune-before, refuse all removals if more than N are planned |

## Metadata and symlinks

| Argument / option | Meaning |
|---|---|
| `--follow` | Follow symlinks in all the paths you give |
| `--follow-src` | Follow symlinks in the source paths you give |
| `--follow-dst` | Follow symlinks in the destination paths you give |
| `--copy-metadata <FEATURE>` | Match selected source metadata, including on unchanged files (repeatable/comma-separated)<br><br>Possible values:<br>- mtime: Match source modification times<br>- permissions: Preserve permission bits<br>- ownership: Preserve owner and group IDs<br>- specials: Copy device nodes and special files<br>- hardlinks: Preserve hard links between selected regular files<br>- acls: Preserve native Linux or macOS ACLs and permission bits<br>- xattrs: Preserve Linux or macOS extended attributes<br>- atimes: Preserve access times captured before reading<br>- crtimes: Preserve birth times; requires a macOS destination<br>- content-type: Content-Type (S3-to-S3 only)<br>- content-encoding: Content-Encoding (S3-to-S3 only)<br>- content-language: Content-Language (S3-to-S3 only)<br>- content-disposition: Content-Disposition (S3-to-S3 only)<br>- cache-control: Cache-Control (S3-to-S3 only)<br>- expires: Expires (S3-to-S3 only)<br>- website-redirect: Website redirect (S3-to-S3 only)<br>- user-metadata: User metadata, except syq-* keys (S3-to-S3 only)<br>- tags: The complete tag set (S3-to-S3 only)<br>- storage-class: Storage class (S3-to-S3 only) |
| `--widen-dirs <MODE>` | Which directories you own may briefly get the owner permission the copy needs; each is restored afterwards<br><br>Possible values:<br>- none: Never change directory permissions<br>- rsync: Directories the copy includes, as rsync does, but not the directory it copies into<br>- all: Also the directory the copy goes into and the directories above it<br><br>[default: none] |
| `--open-noatime` | Request reads without access-time updates; warn and continue if unavailable |
| `--sparse` | Turn written zero ranges into sparse holes |

<a id="integrity-checking"></a>

## Verification

| Argument / option | Meaning |
|---|---|
| `--hash` | Hash existing source and destination files instead of trusting size and modification time |
| `--hash-or-copy` | Like --hash, but compare only where the transfer strategy reuses blocks (by default, between different machines) and copy other files whole, even if identical |
| `--integrity-checking <KEY=VALUE,...>` | [Payload checks](../integrity-checking.md) |

<a id="ssh-and-transport"></a>

<a id="remote-to-remote-transfers"></a>

## Connections and remote execution

| Argument / option | Meaning |
|---|---|
| `--no-compress` | Disable transport compression |
| `--receiver-max-entries <N>` | Between two servers, refuse a restricted copy that would change more than N destination entries |
| `--receiver-max-bytes <SIZE>` | Between two servers, refuse a restricted copy that would write more than SIZE bytes of file data |
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Whose SSH access to use for servers (default: SYQ_AUTH_FROM, then the saved choice, then auto):<br>- auto: this machine's own, else a receiving machine's approval for a copy with one server<br>- ssh: only this machine's own<br>- @NAME: access approved by that receiving machine; also authorizes S3 copies<br>- HOST: access approved by an SSH authorization provider, a server holding your SSH keys |
| `--coordinate-at <WHERE>` | Choose which machine runs the copy<br><br>Possible values:<br>- auto: This machine, unless both endpoints are remote; then the source<br>- src: The source endpoint<br>- dst: The destination endpoint<br>- local: This machine, relaying the data through it<br><br>[default: auto] |
| `--rsh <COMMAND>` | Remote shell command (default: ssh); when set, it controls SSH options and agent forwarding |
| `--syq-path <PATH>` | Run the remote syq at PATH instead of syq's automatically installed copy |
| `--no-bootstrap` | Run the syq found in the remote $PATH instead of syq's automatically installed copy |
| `--no-tcp-encryption` | Send TCP data without encryption or authentication; use only on trusted networks |
| `--no-tcp` | Send file data through SSH rather than separate TCP data connections |
| `--tcp-ports <LO-HI>` | Port range that remote machines listen on for TCP data connections<br><br>[default: 47600-47699] |
| `--tcp-congestion <ALGO>` | Use this congestion-control algorithm for TCP data sockets (Linux only) |
| `--detach` | Return as soon as the copy starts on the server that runs it; requires --peer-auth own-credentials or --rsh |
| `--peer-auth <MODE>` | How the server running the copy logs in to the other server; --rsh takes over this choice<br><br>Possible values:<br>- restricted: Let the other server accept only this copy, through restricted copying (see syq receiver); forwards no agent<br>- broker: Let it use your agent for that host and user, with full access to that account<br>- own-credentials: Forward nothing; it must have its own credentials for the other server<br>- full-agent: Forward your whole SSH agent, as ssh -A does<br><br>[default: restricted] |
| `--pscope <PATH>` | Use the isolated connections and settings that `syq persist on --ephemeral` created at PATH |

## S3 connection settings

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable; S3-to-S3 metadata/tag overrides are refused) |
| `--s3-retries <N>` | Retry each S3 request up to N times after a transient failure or throttling, 0..100 (default 10; 0 disables retries) |
| `--s3-write-header <NAME: VALUE>` | Add a header to S3 requests that create or replace objects (repeatable; S3-to-S3 metadata/tag overrides are refused) |

<a id="performance-tuning"></a>

<a id="resource-limits"></a>

## Performance and resource limits

| Argument / option | Meaning |
|---|---|
| `--performance-tuning <KEY=VALUE,...>` | [Workers, request sizes, and copy methods](../tuning.md) |
| `--transfer-strategy <STRATEGY>` | Choose whether filesystem copies reuse matching blocks of the destination file they replace (default: locality; mounted network filesystems count as local).<br><br>Possible values:<br>- whole-file: Copy selected files without comparing blocks in the final destination<br>- aligned-block: Reuse matching blocks at the same offsets in the corresponding destination file<br>- locality: Whole-file when source and destination are on the same machine, aligned-block when they are on different machines |
| `--resource-limits <KEY=VALUE,...>` | [Bandwidth and concurrency ceilings](../resource-limits.md) |

<a id="progress-and-results"></a>

<a id="preview-and-output"></a>

## Preview, progress, and results

| Argument / option | Meaning |
|---|---|
| `--results <FILE>` | Write the machine-readable NDJSON result stream to FILE (created fresh; an existing file is refused) |
| `--results-fd <FD>` | Write the result stream to an inherited file descriptor the caller opened (e.g. `--results-fd 3 3>run.ndjson`); must be above 2 |
| `-n, --dry-run` | Preview without changing files; remote setup may still install syq, and requested results files are still written |
| `-v, --verbose...` | List files with -v; show connection details with -vv |
| `-q, --quiet` | Suppress non-error messages |
| `--progress` | Show progress even when stderr is not a terminal |
| `--no-progress` | Never show the human progress display |
| `--stats` | Print transfer statistics at the end |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->

<a id="copying-and-failures"></a>

<a id="capacity-checks"></a>

## Update policies

`--if-exists` chooses what happens to existing destination files; see
[existing-file policies](../reference.md#choose-which-existing-files-to-update)
for each value. A retry after a failure is subject to the same placement and
policy, so a `-new` placement or `--if-exists=error` can reject entries the
failed attempt created; see
[resuming a copy](../reference.md#resume-an-interrupted-copy).

`--in-place` cannot be combined with `--if-exists=keep` or `update-if-older`:
an interrupted copy could leave an incomplete file that a retry would then skip.
With `--in-place`, a file that must be new (an `--as-new` file, or a new file
under `--if-exists=error` or `error-if-different`) is still written under a
temporary name, so an interruption never leaves an incomplete file there. S3
destinations do not support `--in-place`. See
[In-place writes](../reference.md#in-place-writes) for which existing files
`--in-place=update` writes into.

## Pruning

Pruning keeps ignored paths, syq partial files, and
[recovery entries](clean-partials.md#which-files-are-removed). An interruption
during deletion can leave some extras already removed.

Keep the source outside the destination. Syq detects overlap for local paths
and for remote paths with the same host name, user, and port, but different SSH
aliases or shared storage can hide it. Wait for other copies into the
destination to finish before pruning, so their new files are not deleted as
extras.

## Filename and type conflicts

A case-insensitive destination cannot store both `Report.txt` and `report.txt`,
and the same goes for different Unicode spellings that the destination treats
as one name. Syq does not check for this before copying: the later file can
replace the earlier one or, under a protective `--if-exists` policy, be
reported as a conflict. Rename the source entries or use a destination that can
tell them apart.

Syq refuses to replace a directory with a non-directory or the reverse, even an
empty directory. Move or remove the conflicting destination entry before
retrying.

## Metadata details

Without `--copy-metadata=permissions`, setuid, setgid, and sticky bits are not
copied. Ownership is copied as numeric user and group IDs. On macOS,
`--widen-dirs` can widen an existing destination directory only if it is
readable.

## File descriptors

`--src-fd 0` reads stdin and `--as-fd 1` writes stdout, so you can connect
local, SSH, or S3 copies to other programs; see
[Shell pipelines and file descriptors](../reference.md#shell-pipelines-and-file-descriptors).
Bash process substitution also works as an ordinary source:

```sh
syq cp --src <(gzip -c data) --to server --as data.gz
```

Each stream copy takes one source. Stdin and process substitution have no
filename, so use `--as` to name the destination, or `--as-fd` to write to a
descriptor. A named pipe can use `--into`: `syq cp incoming.fifo --into saved`
waits for a writer, then saves its bytes as the regular file
`saved/incoming.fifo`. A symlink to a pipe requires `--follow-src`. Directory
copies never read pipes; `--copy-metadata=specials` copies the pipe itself.

Other inherited descriptors work too, except 2, which is reserved for
diagnostics. Syq advances the descriptor's offset and respects append mode; it
does not truncate it. A literal `-` is a filename.

### Completion and failures

A named destination is replaced only after the transfer succeeds. End of input
does not tell syq whether the producer succeeded, so a failed producer can still
leave a saved file. Use Bash's `set -o pipefail` or check a process
substitution's status separately; in Python,
[managed streams](https://greaber.github.io/syq/python-streams.html#byte-streams)
commit only after your producer succeeds.

An output descriptor may contain incomplete data after a failure, so check
syq's exit status before using it. A consumer that closes early makes syq fail.
A killed copy can leave a `.syq-stream-*` temporary file beside the
destination, which `syq clean-partials` does not remove; delete it once no copy
is writing there.

<a id="options-and-file-behavior"></a>

<a id="selection-and-previews"></a>

### Skips and previews

Progress, `--stats`, and `-v` go to stderr, leaving stdout for the payload.

`--if-exists=keep` skips a destination that already exists without reading
input or opening a named pipe, so a shell producer can receive SIGPIPE; in
Python, check the writer's `skipped` property first. An output descriptor
always exists, so `--if-exists=keep --as-fd N` always skips.

`--dry-run` checks source and destination placement without reading input or
changing the destination; it cannot check a payload hash or predict the length
of a pipe. `--results` and `--results-fd` report
[`stream_result`](../automation.md#stream_result) records, and must use a
different descriptor from the payload.

### Transport and limits

Filesystem streams accept only the `workers`, `request-size`, `pipeline-depth`,
and `bw-pacing` performance-tuning keys. For S3 streams, see [Descriptor copies](../object-storage.md#descriptor-copies).

Streams cannot go to receiving names, and an interrupted stream starts over.
Options for file trees, such as `--hash`, `--in-place`, `--prune`, `--where`,
`--ignore`, `--transfer-strategy`, and `--detach`, are refused. `--root` cannot
be combined with `--src-fd`.

`--if-exists` does not apply to output descriptors, except that `keep` always
skips and `update-if-older` is refused.

<a id="descriptor-offsets-and-metadata"></a>

### Descriptor metadata

Output descriptors get the timestamps of ordinary writes. Add
`--copy-metadata=mtime` to set the source modification time instead, which
changes the whole destination file's timestamp even after a partial write;
`--copy-metadata=permissions,ownership` copies those attributes.

Pipes, sockets, and devices have no metadata to copy, so they reject
`--copy-metadata` and `--if-exists=update-if-older`, and their new named
destinations get mode `0666` limited by the umask or the directory's default
ACL. Named remote sources must be regular files.
