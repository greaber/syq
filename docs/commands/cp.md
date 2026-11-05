# syq cp

Copy files, directories, and symlinks between local paths, SSH servers, and S3
buckets. For examples, start with [Copy files](../reference.md).

```sh
syq cp --srcs-in project --to server --into backup --dry-run -v
```

Put the source options (`--from`, `-C` or `--root`, `--src-fd`, selectors,
and `--mapping`) before `--to` and the placement option. In scripts,
`SYQ_CP_OPTIONS` adds arguments; see [environment variables](../environment.md).

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
| `--src <PATH>` | Select a named source object (repeatable) |
| `--srcs-in <DIR>` | Select a directory's contents (repeatable) |
| `--src-non-dir <PATH>` | Select a named non-directory source object (repeatable) |
| `--src-dir <DIR>` | Select a named source directory (repeatable) |
| `--src-non-dirs <PATH>...` | Select several named non-directory source objects |
| `--src-dirs <DIR>...` | Select several named source directories |
| `--srcs <PATH>...` | Select several named source objects |
| `--where <EXPR>` | Select non-directory entries with an expression; directories are not filtered |
| `--ignore <PATTERN>` | Skip paths matching a gitignore-style pattern (repeatable) |
| `--ignore-from <FILE>` | Read gitignore-style patterns from FILE (repeatable; applied in command-line order with --ignore) |
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
| `--follow` | Follow symlinks in all directly supplied filesystem paths |
| `--follow-src` | Follow symlinks in directly supplied source paths |
| `--follow-dst` | Follow symlinks in directly supplied destination paths |
| `--copy-metadata <FEATURE>` | Match selected source metadata, including on unchanged files (repeatable/comma-separated)<br><br>Possible values:<br>- mtime: Match source modification times<br>- permissions: Preserve permission bits<br>- ownership: Preserve owner and group IDs<br>- specials: Copy device nodes and special files<br>- hardlinks: Preserve hard links between selected regular files<br>- acls: Preserve native Linux or macOS ACLs and permission bits<br>- xattrs: Preserve Linux or macOS extended attributes<br>- atimes: Preserve access times captured before reading<br>- crtimes: Preserve birth times; requires a macOS destination<br>- content-type: Content-Type (S3-to-S3 only)<br>- content-encoding: Content-Encoding (S3-to-S3 only)<br>- content-language: Content-Language (S3-to-S3 only)<br>- content-disposition: Content-Disposition (S3-to-S3 only)<br>- cache-control: Cache-Control (S3-to-S3 only)<br>- expires: Expires (S3-to-S3 only)<br>- website-redirect: Website redirect (S3-to-S3 only)<br>- user-metadata: User metadata, except syq-* keys (S3-to-S3 only)<br>- tags: The complete tag set (S3-to-S3 only)<br>- storage-class: Storage class (S3-to-S3 only) |
| `--widen-dirs <MODE>` | Which directories you own may briefly get the owner permission the copy needs; each is restored afterwards<br><br>Possible values:<br>- none: Never change directory permissions<br>- rsync: Directories the copy includes, as rsync does, but not the directory it copies into<br>- all: Also the directory the copy goes into and the directories above it<br><br>[default: none] |
| `--open-noatime` | Request reads without access-time updates; warn and continue if unavailable |
| `--sparse` | Turn written zero ranges into sparse holes |

<a id="integrity-checking"></a>

## Verification

| Argument / option | Meaning |
|---|---|
| `--hash` | Hash existing source and destination files instead of trusting size and modification time |
| `--hash-or-copy` | Like --hash, but compare only where the transfer strategy reuses blocks (by default, with a remote syq endpoint) and copy other files whole, even if identical |
| `--integrity-checking <KEY=VALUE,...>` | [Payload checks](../integrity-checking.md) |

<a id="ssh-and-transport"></a>

<a id="remote-to-remote-transfers"></a>

## Connections and remote execution

| Argument / option | Meaning |
|---|---|
| `--no-compress` | Disable transport compression |
| `--receiver-max-entries <N>` | Refuse a restricted copy that would touch more than N destination entries |
| `--receiver-max-bytes <SIZE>` | Refuse a restricted copy that would write more than SIZE bytes of file data |
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | How to authorize, overriding SYQ_AUTH_FROM and the saved choice: auto tries native SSH and may then ask a receiving machine, ssh uses only native SSH, and @NAME or HOST asks that receiving machine or SSH provider (@NAME also authorizes S3 copies) |
| `--coordinate-at <WHERE>` | Choose which machine runs the copy<br><br>Possible values:<br>- auto: This machine, unless both endpoints are remote; then the source<br>- src: The source endpoint<br>- dst: The destination endpoint<br>- local: This machine, relaying the data through it<br><br>[default: auto] |
| `--rsh <COMMAND>` | Remote shell command (default: ssh); when set, it controls SSH options and agent forwarding |
| `--syq-path <PATH>` | Use this remote syq executable instead of installing a helper |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a helper |
| `--no-tcp-encryption` | Send TCP data without encryption or authentication; use only on trusted networks |
| `--no-tcp` | Send file data through SSH rather than separate TCP data connections |
| `--tcp-ports <LO-HI>` | Port range remote listeners use for TCP data connections<br><br>[default: 47600-47699] |
| `--tcp-congestion <ALGO>` | Use this congestion-control algorithm for TCP data sockets (Linux only) |
| `--detach` | Return as soon as the copy starts on the server that runs it; requires --peer-auth own-credentials or --rsh |
| `--peer-auth <MODE>` | How the server running the copy logs in to the other server; --rsh takes over this choice<br><br>Possible values:<br>- restricted: Reach the other server only through its enrolled restricted receiver; forwards no agent<br>- broker: Let it use your agent for that host and user, with full access to that account<br>- own-credentials: Forward nothing; it must have its own credentials for the other server<br>- full-agent: Forward your whole SSH agent, as ssh -A does<br><br>[default: restricted] |
| `--pscope <PATH>` | Use an isolated persistence domain created by `syq persist on --ephemeral` |

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
| `--transfer-strategy <STRATEGY>` | Choose whether filesystem copies reuse matching blocks of the destination file they replace (default: locality; mounted network filesystems count as local).<br><br>Possible values:<br>- whole-file: Copy selected files without comparing blocks in the final destination<br>- aligned-block: Reuse matching blocks at the same offsets in the corresponding destination file<br>- locality: Use whole-file locally and aligned-block with a remote syq endpoint |
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

`--if-exists` decides what happens to destination files that already exist;
see [existing-file policies](../reference.md#choose-which-existing-files-to-update)
and, before retrying a failed copy,
[resuming a copy](../reference.md#resume-an-interrupted-copy).

`--in-place` cannot be combined with `--if-exists=keep` or `update-if-older`,
because a retry would then skip a file left incomplete. Even with `--in-place`,
a new file that must not replace anything (`--as-new`, or a new file under
`--if-exists=error` or `error-if-different`) is written under a temporary name
first. S3 destinations do not support `--in-place`. See
[In-place writes](../reference.md#in-place-writes).

## Pruning

Before pruning, keep the source outside the destination and let other copies
into it finish; otherwise pruning can delete files you want. Syq refuses to
prune a destination that it can see contains the source, but different SSH
aliases for one server, or shared storage, can hide the overlap. Pruning never
removes ignored paths, partial files, or
[recovery entries](clean-partials.md#which-files-are-removed).

## Filename and type conflicts

On a case-insensitive destination, `Report.txt` and `report.txt` (or two
Unicode spellings of one name) collide. Syq does not check for this, so one
replaces the other or is reported as a conflict. Rename one source, or use a
destination that can tell them apart.

Syq never replaces a directory with a non-directory or the reverse, even an
empty one; move or remove the conflicting entry first.

## Metadata details

When you copy metadata to another machine, check how it carries over. Setuid,
setgid, and sticky bits are copied only with `--copy-metadata=permissions`.
Ownership and ACL entries are copied as numeric IDs (UUIDs for macOS ACLs), not
translated to account names, so on another host they apply to whichever
account has that ID there.

## File descriptors

Use a descriptor copy to connect syq to another program without a temporary
file. It streams raw bytes through an inherited file descriptor, a named pipe,
or a process substitution. `--src-fd 0` reads standard input and `--as-fd 1`
writes standard output;
[Shell pipelines and file descriptors](../reference.md#shell-pipelines-and-file-descriptors)
has examples. Process substitution and named pipes work as sources:

```sh
syq cp --src <(gzip -c data) --to server --as data.gz
syq cp incoming.fifo --into saved
```

Each descriptor copy takes one source, and input without a filename needs `--as`
or `--as-fd`. The second example waits for a writer and saves its bytes as the
regular file `saved/incoming.fifo`. Syq reads or writes from a descriptor's
current position and never truncates it. Progress and `-v` output go to
standard error, so descriptor 2 cannot carry a payload.

### Completion and failures

A named destination is replaced only after the transfer succeeds, but syq cannot
tell whether the producer succeeded: if the producer fails partway, syq still
saves the bytes it received. Check the producer's status, for example with
Bash's `set -o pipefail`; Python
[managed streams](https://greaber.github.io/syq/python-streams.html#byte-streams)
do this for you. Likewise, check syq's exit status before using what it wrote
to an output descriptor, which can be incomplete after a failure.

A killed copy can leave a `.syq-stream-*` file beside the destination; delete it
once no copy is writing there.

<a id="options-and-file-behavior"></a>

<a id="selection-and-previews"></a>

### Skips and previews

`--if-exists=keep` skips an existing destination without reading input, so a
shell producer can get SIGPIPE. An output descriptor always exists, so
`--as-fd` with `keep` always skips; `update-if-older` is refused, and other
`--if-exists` values do not apply. `--dry-run` reads no input, so it cannot
check a payload hash or a pipe's length. `--results` reports one
[`stream_result`](../automation.md#stream_result) record.

### Transport and limits

Descriptor copies refuse options for file trees, such as `--hash`, `--prune`,
`--where`, and `--detach`, and cannot use a receiving name (`@NAME`). An
interrupted one starts over. Filesystem descriptor copies accept only the
`workers`, `request-size`, `pipeline-depth`, and `bw-pacing`
[tuning keys](../tuning.md); for S3, see
[Descriptor copies](../object-storage.md#descriptor-copies).

<a id="descriptor-offsets-and-metadata"></a>

### Descriptor metadata

A file written through `--as-fd` gets ordinary write timestamps unless you add
`--copy-metadata=mtime`, which sets the time of the whole file.
`--copy-metadata=permissions,ownership` copies those attributes too. A pipe,
socket, or device source has no metadata; a new named destination for one gets
mode `0666`, limited by the umask.
