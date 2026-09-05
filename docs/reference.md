# Commands

Use `syq cp` to copy, `syq rm` to remove, and `syq map` to produce a
[placement manifest](mappings.md). For existing rsync commands, see
[rsync mode](#rsync-compatibility).

## Command-line help

```sh
syq --help
syq cp --help
syq cp --help-all
syq help receiver enroll
```

`--help` shows examples and common options; `--help-all` lists all options.
`-h` also means help, except in rsync mode, where it means human-readable sizes.

## Native commands

### Copy a directory or its contents

```sh
syq cp project --into backup
syq cp --srcs-in project --into backup
```

```text
Source                    First command        Second command
project/                  backup/              backup/
  report.txt                project/             report.txt
                              report.txt
```

A bare path copies the named file or directory. `--srcs-in DIR` copies its
contents. **Trailing slashes do not change native placement.**

To copy over SSH, add `--from` or `--to`:

```sh
syq cp project --to server --into /backup
syq cp --from server -C /data --src a --src b --into ./data
syq cp --from alice@server:2222 data --into backup
```

Omitted endpoints mean local. Endpoints use `[USER@]HOST[:PORT]`; enclose IPv6
addresses in brackets, as in `alice@[2001:db8::1]:2222`. A colon inside a
native path is just part of its name.

Remote copies may omit placement:

```sh
syq cp project --to server       # put project in your remote home directory
syq cp --from server project     # put project in your local current directory
```

The default is `--into .` at the destination. `--cwd` changes only the source
base. Local-only copies and every `--prune` copy still require explicit
placement: `syq cp a b` selects two sources, not a destination.

Finish the source specification before the destination: `--from`, `-C`,
`--root`, selectors, and `--mapping` must precede the first `--to` or
placement option. Other flags, such as `--dry-run`, may follow placement.

### Choose where files land

| Placement | Result | Requirement |
|---|---|---|
| `--into DIR` | Selected names inside `DIR` | Use or create a directory |
| `--into-new DIR` | Selected names inside `DIR` | Directory must not exist |
| `--into-existing DIR` | Selected names inside `DIR` | Directory must exist |
| `--as PATH` | One named source exactly at `PATH` | Create or update |
| `--as-new PATH` | One named source exactly at `PATH` | Path must not exist |
| `--as-existing PATH` | One named source exactly at `PATH` | Path must exist |

```sh
syq cp report.txt --as-new reports/final.txt
syq cp --srcs-in build --into-existing deploy
```

A named directory keeps its basename with `--into`; a contents selection
merges directly into the container. `--as` takes one named source, including
a directory, and chooses its exact destination name.

The `new` and `existing` conditions are checked before copying. A
non-directory source cannot replace a directory through `--as`. Multiple
sources claiming the same destination are refused before writing. These
checks do not freeze the filesystem or make the whole copy transactional.

### Select files

| Selector | Selects |
|---|---|
| Bare `PATH` or `--src PATH` | A named file, directory, or link |
| `--src-file PATH` | A named non-directory; refuses a directory |
| `--src-dir DIR` | A named directory; refuses other types |
| `--srcs-in DIR` | The directory's contents |
| `--srcs PATH...` | Several named objects |
| `--src-files PATH...`, `--src-dirs DIR...` | Several typed objects |

Singular options can be repeated. A symlink counts as a non-directory unless
you ask to follow it. Type mismatches fail before changes begin.

For option values beginning with `-`, attach the value:
`--src=--archive`, `--src-dir=-`, or `--into=-backup`.
`--mapping -` is the exception: it reads standard input.

### Resolve or confine paths

`--cwd DIR` / `-C DIR` resolves relative sources from `DIR` at the source
endpoint. For `cp` and `rm`, absolute paths and `..` may leave that base.

`--root DIR` replaces `--cwd` with a boundary: selectors must be relative
and remain beneath it. Absolute paths, `~` paths, and attempts to leave the
root are refused before changes begin. This also bounds native removal.

```sh
syq cp -C /data reports images --into backup
syq rm --root /srv --src-dir cache
```

`map` has additional rules because it emits relative paths; see
[Mappings](mappings.md#semantics-and-limits).

### Symlinks

Native commands refuse symlink traversal in paths you supply by default.
A symlink selected by name is copied as a link, or removed as a link by `rm`.
Links found inside a selected directory are never followed.

| Option | Allows traversal in |
|---|---|
| `--follow-src` | Source selectors, `--cwd`, and `--root` |
| `--follow-dst` | Copy destination placement |
| `--follow` | Both directions and control paths such as `--mapping`, `--ignore-from`, and `--results` |

```sh
syq cp --follow-src current-project --into backup
syq cp --follow-src --srcs-in current-project --into backup
```

If `current-project` points to `releases/v3`, the first command copies the
referent as `backup/current-project`; the second copies its contents into
`backup`.

An `--into` container link is followed only with `--follow-dst` or `--follow`.
With `--as`, the last component is the entry to replace: even
`--follow-dst --as link` replaces the link itself, leaving its target alone.
A dangling link counts as existing for `--as-new` and `--as-existing`.

For an explicit target, inspect it with `readlink` or use its resolved path
from `realpath`. A relative `readlink` result is relative to the link's parent.
Follow options never apply to paths inside a mapping manifest. With `--root`,
even a followed selector must remain inside the root.

### Preserve metadata

Native copy recurses, copies links as links, and preserves modification times
(the equivalent of rsync's `-rlt`). Add preservation only when needed:

```sh
syq cp --preserve=permissions,ownership project --into backup
```

| Value | Adds |
|---|---|
| `permissions` | File and directory modes |
| `ownership` | Numeric owner and group |
| `specials` | Device, FIFO, and socket nodes |

`--preserve` is repeatable and accepts comma-separated values. Owners are
set only when the destination process runs as root; group changes refused
with `EPERM` are skipped. Without permission preservation, new files use
source modes masked by the destination umask; existing files keep their modes.

Hard links, ACLs, and xattrs are not preserved. On macOS, socket nodes are
reported and skipped even when specials are requested.

### Common copy options

| Option | Effect |
|---|---|
| `-n`, `--dry-run` | Preview changes |
| `-v`, `-vv` | List changes; also show route diagnostics at `-vv` |
| `-q`, `--quiet` | Suppress non-error output |
| `--hash` | Compare existing contents instead of trusting size and mtime |
| `--ignore`, `--ignore-from` | Filter with gitignore patterns |
| `--prune`, `--max-delete N` | Remove destination extras with an optional cap |
| `--inplace` | Update final files directly; interrupted files may be incomplete |
| `--min-size SIZE`, `--max-size SIZE` | Select regular files within an inclusive size range |
| `-j N`, `--connections N` | Fix parallelism instead of tuning it automatically |
| `--bwlimit RATE` | Cap aggregate file-data throughput |
| `--no-compress` | Disable transport compression |
| `--progress`, `--no-progress` | Override progress display, normally on for terminals |
| `--stats` | Print totals and transport statistics |
| `--results FILE`, `--results-fd N` | Write [structured results](automation.md) |

A bare bandwidth rate is KiB/s; suffixes such as `K`, `M`, `G`, and `MiB` use
powers of 1024. `0` means unlimited. The cap is shared across workers and
counts uncompressed file bytes, excluding scanning, hashing, and metadata.

`--hash` compares and repairs existing contents; it does not add a second
post-transfer verification pass. Verification without writing is available
in rsync mode as `--syq-verify-only`.

## Removing files

```sh
syq rm cache old-output
syq rm --srcs-in cache
syq rm --from server --root /srv --src-dir old-output
```

The first command recursively removes the selected trees. The second empties
`cache` and keeps the directory. Add `--dry-run -v` to inspect the selection
before deleting it.

All selectors are resolved and type-checked before deletion begins. Missing
paths succeed. Duplicate or overlapping selectors are allowed and may produce
redundant work; an already removed entry counts as success.

`rm` takes the same source selectors, `--cwd`, `--root`, and source follow
options as copy. It does not take filters. A selected symlink is unlinked;
with `--follow-src`, its referent is removed and the link remains, usually
dangling. Symlinks discovered inside a directory are only unlinked.

Removal continues with independent entries after per-entry failures and exits
23. A fatal setup or transport failure exits 1. Already completed removals
are never rolled back. Remote removal is attached to its SSH connection;
detected disconnection stops scheduling further work. There is no detached
removal and no removal through the restricted receiver.

## Previewing a copy

```sh
syq cp --dry-run -v --srcs-in project --into backup
```

The summary shows where each source lands, intended changes, logical bytes,
exclusions, planned deletions, and the data route. `-v` adds a line per change:

```text
create file report.txt (destination missing)
delete old.txt (destination only)
```

Logical bytes are an upper bound: resume, compression, and kernel copies may
reduce actual I/O. An ignored directory counts as one excluded subtree;
its children are not scanned.

For a missing or empty destination, syq also checks required logical space
and available inodes when the filesystem reports them. Insufficient capacity
fails both a dry run and a real copy. This check reserves nothing and is
omitted for nonempty destinations.

Dry runs do not change copy data. They still connect and scan, may install
remote helpers or update caches, and write a requested results file. The plan
is a snapshot of current conditions, not a saved transaction. Remote-to-remote
previews have [additional requirements](remote-to-remote.md#preview-and-mirror).

## Resume

**Rerun the same command after an interruption.** Completed files whose size
and mtime match are skipped. Partial files are reused, and only mismatching
blocks need to move. Existing destination files that differ can also supply
matching blocks.

By default, changed content is written beside the destination as
`.name.syq-part.<copy-id>` and renamed into place when complete. Readers see a
whole old or new file. `--inplace` gives this up: readers can see partially
updated contents, and interruption leaves the final file incomplete.

Changing placement, preservation, ordered filters, or block size can change
the copy ID and start different partial files. Changing verbosity, connection
count, checksum checking, or bandwidth limiting does not. Abandoned partial
files may be removed manually once you no longer intend to resume that copy.

Resume compares blocks at the same offsets. Appends and in-place changes can
reuse data; an insertion near the start of a file causes the shifted tail to
be resent. Syq cannot reuse rsync's partial files.

Do not run the same logical command twice concurrently: both runs use the
same partial files. Different commands may copy into one tree, but when they
write the same path one whole-file rename wins. Do not combine concurrent
copies with pruning, which can delete the other copy's files and partials.

The destination directory must not be writable by untrusted users, especially
for privileged copies. See [Security](security.md).

## Verification and consistency

Transferred blocks are checked with BLAKE3. A mismatch fails the file rather
than reporting success. Source files whose size or mtime changes during a
copy are retried, up to three attempts, then reported as failures.

```sh
syq cp --hash --srcs-in project --into backup
syq rsync -a --syq-verify-only project/ backup/
```

The first compares existing file contents and repairs differences. The second
writes nothing and reports `DIFFERS` or `MISSING`, with a nonzero exit status
for failures or differences. Its scope respects selection and size filters.

A copy is not a snapshot. Concurrent in-place writes can produce inconsistent
contents; stop writers or use filesystem snapshots. Metadata is set but not
fully read back for verification. Syq does not `fsync` transfer data, so a
successful copy is not a guarantee of durability across power loss.

## Ignoring paths

Native copy uses `--ignore` and `--ignore-from`; rsync mode uses
`--syq-ignore` and `--syq-ignore-from`. Patterns follow gitignore syntax and
are applied in command-line order. Last match wins; `!` re-includes.

```sh
syq cp --ignore-from .gitignore --srcs-in project --into backup
syq cp --ignore node_modules --ignore '*.o' --srcs-in project --into backup
syq cp --ignore 'logs/*' --ignore '!logs/keep/' --srcs-in project --into backup
```

| Pattern | Matches |
|---|---|
| `foo` | A file or directory named `foo` at any depth |
| `/foo` | `foo` at the source root |
| `foo/` | Directories named `foo` |
| `*` | Within one path component |
| `**` | Across path components |

An ignored directory is not scanned. A later rule cannot re-include its
children unless the parent is included too. To select only JPEG files while
still descending into directories:

```sh
syq cp --ignore '*' --ignore '!*/' --ignore '!*.jpg' --srcs-in photos --into backup
```

Rules start afresh at each source root. They also protect matching destination
paths from pruning. Native `rm` does not take filters.

## Deleting extras (`--delete`)

Native `--prune` and rsync's `--delete` remove destination-only paths after
copying:

```sh
syq cp --prune --max-delete 100 --srcs-in build --into-existing deploy
syq rsync -a --delete --max-delete 100 build/ deploy/
```

Preview with `--dry-run -v` first.

- **Only mapped directories are pruned.** Copying named directories `a` and
  `b` into `dst` prunes inside `dst/a` and `dst/b`, leaving `dst/c` alone.
  A single-file source deletes nothing.
- **Ignored paths are protected.** Rsync mode's `--delete-excluded` removes
  that protection. `cache/` protects a directory, while `cache` protects a
  file or directory of that name.
- **Skipped source files still count as present.** Size filters and rsync's
  state filters do not turn their destination counterparts into extras.
- **Scan errors prevent deletion.** Both source and destination must be
  scanned successfully. Per-file read failures during transfer do not by
  themselves disable deletion; the failed source file still counts as present.
- **A positive deletion cap is all-or-nothing.** If more than N entries are
  planned, `--max-delete N` deletes none and exits 25. A zero cap reports
  extras without deleting them. Once deletion starts, an interruption may
  leave some extras removed; rerun to finish.

This copy's live partial files are protected. Orphaned partials and partials
from other logical commands are ordinary extras and may be deleted.

Native `--max-delete` requires `--prune`. In rsync mode it has no effect
without `--delete`, and `--max-delete=-1` aliases zero. Pruning cannot be
combined with mapping manifests; rsync deletion cannot be combined with
`--files-from` or verification-only mode. Restricted remote-to-remote pruning
requires an [explicit cap](remote-to-remote.md#preview-and-mirror).

## Remote options

| Option | Purpose |
|---|---|
| `--syq-path PATH` | Use a specific remote syq executable |
| `--no-bootstrap` | Use a matching syq on the remote `PATH` |
| `--rsh COMMAND` | Supply your own remote-shell and authentication policy |
| `--no-tcp` | Send file data through SSH |
| `--tcp-ports LO-HI` | Choose listening ports; default `47600–47699` |
| `--tcp-plain` | Disable data encryption; trusted networks only |
| `--tcp-congestion ALGO` | Linux: select congestion control for syq's TCP sockets |

Remote `rm` accepts helper selection through `--syq-path` or
`--no-bootstrap`; these are mutually exclusive and invalid for local removal.
Source builds upload themselves to compatible hosts automatically. See
[installation](install.md#remote-helper-bootstrap) for other platforms or
manually installed helpers.

An explicit `--rsh` controls authentication and bypasses automatic broker and
receiver setup. Native endpoint ports work with the default SSH command or
an explicit `ssh`; other wrappers must carry their own port setting.

For two remote endpoints, `--coordinate-at src` sends directly from source
to destination, `dst` selects a direct pull, and `local` relays through your
machine. The default `auto` selects the source. Explicit placements require
two remote endpoints; `auto` is accepted everywhere. Authentication choices,
receiver limits, and detached copies are in
[Copy between servers](remote-to-remote.md).

## Persistent SSH connections

Keep logins available for repeated commands and faster remote completion:

```sh
syq persist on
syq persist status
syq persist off
```

Persistence avoids repeated authentication and keeps a helper session ready.
Connections may remain reusable for up to ten minutes after your last command;
`off` ends the window immediately. During it, processes acting as your local
user can reuse those logins without another key touch or agent approval.

Scripts can create their own scope without changing the global preference:

```sh
pscope=$(syq persist on --ephemeral) || exit
trap 'syq persist off --pscope "$pscope"' EXIT
syq cp --pscope "$pscope" first --to server --into /backup
syq cp --pscope "$pscope" second --to server --into /backup
```

Scopes may be shared by parallel commands. Inspect one with
`syq persist status --pscope "$pscope"`. After a crashed script, idle
connections expire, but its inert scope directory may remain.

Persistence applies to syq's implicit SSH connections on the invoking machine.
It does not apply to explicit `--rsh`, remote coordinators, or restricted
receiver authentication; an explicit scope is refused where unsupported.
Use `--coordinate-at local` to reuse connections for a relayed copy.

If your SSH configuration uses `SendEnv`, pooled sessions use the environment
from the command that started the pool. Run `persist off`, then `persist on`,
to pick up changed values. Bulk data throughput is unaffected by persistence.

## Shell completion

[Install the adapter](install.md#shell-completion) for Bash, Zsh, or fish.
Completion covers options, endpoint names, and local and remote filenames.

Remote completion uses an ordinary noninteractive SSH login, even for a host
used as a restricted receiver. It never prompts for a password. Failures give
no candidates; set `SYQ_COMPLETION_DEBUG=1` to see diagnostics. Explicit
`--rsh` commands have no remote path completion.

Successful endpoints join suggestions from SSH configuration and known hosts.
Manage the learned cache with:

```sh
syq completion cache list
syq completion cache forget user@host:2222
syq completion cache clear
```

Clearing it removes learned suggestions, not SSH configuration, credentials,
remote data, or persistent sessions.

## Mappings

Use `syq map` to generate source/destination entries and `syq cp --mapping`
to execute them. This supports renaming and reorganizing during a copy.
See [Mappings](mappings.md) for recipes, the format, and retrying failed entries.

## Rsync compatibility

```sh
syq rsync -av project/ server:backup/project/
syq rsync -av server:data/ ./data/
syq rsync -a --dry-run -v src/ dest/
```

Syntax is `syq rsync [OPTIONS] SRC... DEST`, with at most one remote endpoint.
Syq-specific options have a `--syq-` prefix. It cannot connect to an rsync
server; `--rsync-path` must name a syq executable, not a shell fragment.
See [compatibility differences](rsync-compat.md) before replacing rsync in scripts.

### Compatibility options

| Option | Meaning |
|---|---|
| `-a`, `--archive` | Same as `-rlptgoD` |
| `-r`/`--recursive`, `-l`/`--links`, `-p`/`--perms`, `-t`/`--times`, `-g`/`--group`, `-o`/`--owner`, `-D` | Recursive; symlinks as symlinks; perms; mtimes; group; owner; devices and specials |
| `-v`/`--verbose`, `-vv` | `-v` lists files as they complete; for copies, `-vv` also explains remote helpers, candidate TCP addresses, the planned transport, and initial concurrency |
| `-q`, `--quiet` | Errors only |
| `-z`, `--compress` / `--no-compress` | Enable (the default) or disable zstd compression in syq's protocol; this is not `ssh -C` |
| `-n`, `--dry-run` | Resolve mappings and transport, estimate transfers/exclusions/deletions; leave source and destination data unchanged |
| `--syq-connections N` | Syq extension: parallel data connections (default: auto-tuned, see [Speed](speed.md#how-many-connections)) |
| `--bwlimit RATE` | Limit aggregate file-data throughput (bare rate is KiB/s; `0` disables) |
| `-B SIZE`, `--block-size SIZE` | Transfer and hash block size (default 4M) |
| `--progress` / `--no-progress` | Progress meter (default on when stderr is a terminal) |
| `-P` | Turns on `--progress` (the `--partial` half is always on; see below) |
| `--partial` | No-op for rsync compatibility (syq always keeps partial files) |
| `--numeric-ids` | No-op for rsync compatibility (syq always uses numeric uid/gid) |
| `--syq-progress-json` | Syq extension: one JSON line per second on stderr |
| `--stats` | Summary counts at the end |
| `-c`, `--checksum` | Compare every file with BLAKE3 instead of size+mtime; repair mismatches (native spelling: `--hash`) |
| `--syq-verify-only` | Syq extension: hash every file in the run's scope on both sides and report differences; write nothing |
| `--inplace` | Write directly into destination files (no partial + rename) |
| `-e CMD`, `--rsh CMD` | Remote shell command; bypasses syq's automatic agent broker, restricted receiver, and enrollment setup and controls agent forwarding itself (default `ssh`) |
| `--rsync-path PATH` | Use this exact remote `syq` instead of the helper syq installs; despite rsync's standard spelling, PATH must name syq because the wire protocols differ |
| `--syq-no-bootstrap` | Syq extension: require `syq` on the remote `PATH`; do not install syq's helper |
| `--syq-no-tcp` | Syq extension: send data over the ssh connection instead of separate TCP sockets |
| `--syq-tcp-plain` | Syq extension: TCP data connections without encryption (trusted networks only) |
| `--syq-tcp-ports LO-HI` | Syq extension: port range the remote listens on for TCP data (default 47600-47699) |
| `--syq-tcp-congestion ALGO` | Syq extension, Linux: use `ALGO` on both ends of TCP data sockets; the host default is unchanged |
| `--syq-pscope PATH` | Syq extension: use an ephemeral SSH persistence scope created by `syq persist on --ephemeral` |
| `--syq-ignore PATTERN` | Syq extension: skip paths matching a gitignore-style pattern (repeatable; see below) |
| `--syq-ignore-from FILE` | Syq extension: read ignore patterns from a file (repeatable, stacks with `--syq-ignore`) |
| `--delete` | Remove destination paths the source doesn't have (see below); `--delete-after`/`--delete-delay` are synonyms |
| `--delete-excluded` | With `--delete`, also remove destination paths the `--syq-ignore` patterns exclude |
| `--max-delete N` | With `--delete`, delete nothing if more than N deletions are planned (exit 25); unlike rsync for positive N, the limit is atomic |
| `-u`, `--update` | Skip files that are newer on the destination |
| `--existing` | Only update files that already exist on the destination; create nothing |
| `--ignore-existing` | Only create files missing on the destination; update nothing |
| `--max-size SIZE`, `--min-size SIZE` | Don't transfer regular files larger / smaller than SIZE |
| `--files-from FILE` | Copy only the listed paths (relative to the one source directory; see below) |
| `--from0` | `--files-from` entries are NUL-separated |
| `--insecure-links` | Follow symlinks in the paths you name on this machine regardless of ownership, and walk source directories by path name, through symlinked parents; never applied to a remote endpoint, as in rsync |
| `-h`, `--human-readable` | No-op for rsync compatibility; sizes are always human-readable. Use `--help` for help |
| `-V`, `--version` | Print the version |


### Path semantics

| Command | Placement |
|---|---|
| `syq rsync -a src dest` | Directory `src` becomes `dest/src` |
| `syq rsync -a src/ dest` | Contents of `src` go directly into `dest` |
| `syq rsync -a file dest` | `dest/file` if `dest` is a directory; otherwise exact name `dest` |
| `syq rsync -a a b dest` | Multiple sources require or create directory `dest` |

`src/.` selects contents too. Exactly repeated operands are scanned once but
still count as multiple sources for placement. Collisions between distinct
sources are refused.

A destination symlink in a supplied path is followed when root or the
receiving user owns it. Links inside the destination tree are replaced when
needed, never traversed. The local-only `--insecure-links` escape hatch and
its risks are described in [Security](security.md#symlinks-and-shared-directories).

`host:path` is relative to the remote home; `host:/abs` and `host:~/x` work.
A colon before the first slash means remote; spell `./x:y` for a local name.
All sources must be on the same host. Daemon syntax is unsupported.

### What `-a` does here

`-a` expands to `-rlptgoD`: recursion, links, modes, times, group, owner, and
special files. Owner is set only by root on the destination; group changes
refused with `EPERM` are skipped. Without `-p`, new files use the umask and
existing files keep their modes. Without `-t`, every file is transferred again.

Hard links, ACLs, and xattrs are not preserved by `-a` or any other option.

### Skipping by state and size

| Option | Skips |
|---|---|
| `-u`, `--update` | Regular files newer on the destination |
| `--existing` | Anything missing on the destination |
| `--ignore-existing` | Anything already present |
| `--min-size`, `--max-size` | Regular files outside the inclusive range |

`--ignore-existing` also keeps an existing file where a directory would land,
skipping that source subtree. `--update` does not prevent type replacements.
Neither `--update` nor `--ignore-existing` combines with `--inplace`: an
interrupted file could otherwise look newer and be skipped forever.

### Copying a list (`--files-from`)

```sh
syq rsync -a --files-from list.txt server:src/ dst/
```

Each line selects a path relative to one source directory. `--from0` uses
NUL separators; `--files-from -` reads stdin. Only listed paths are inspected,
and missing parents are created at the destination.

A listed directory copies without its contents unless you explicitly add
`-r`; `-a` alone does not count. Missing entries fail with exit 23 while other
entries continue. The destination must be a directory.

Blank entries and entries beginning with `#` or `;` are ignored in either
separator mode; use `./#name` for a literal comment-looking name. Leading
`/` or `./` and trailing `/` are stripped. `..` components and root entries
are refused. A symlinked source parent fails that entry unless a local source
uses `--insecure-links`; remote sources always refuse it.

`--files-from` cannot combine with ignore filters or deletion. For custom
placement, use a [mapping](mappings.md).

## Output and exit codes

Copy and removal continue if human output fails; their exit status still
reports the filesystem operation. A slow output consumer may block the thread
writing to it. Use [results](automation.md) for structured accounting, and
always check for a terminal record.

| Code | Meaning |
|---|---|
| `0` | Requested operation succeeded |
| `1` | Fatal setup, connection, or runtime failure |
| `2` | Invalid arguments or usage |
| `23` | Some entries failed; independent work continued |
| `25` | Deletions refused by a safety cap |
