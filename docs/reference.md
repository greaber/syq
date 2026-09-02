# Command reference

This is the detailed behavioral reference for syq's command surface: native
commands, the `syq rsync` compatibility surface, path semantics, the transfer
engine, resume, verification, filtering, deletion, and exit codes. The
[README](../README.md) is the overview; [Speed](speed.md),
[Remote-to-remote transfers](remote-to-remote.md), [Security](security.md),
and [Composability](composability.md) cover those topics in depth. The code is
authoritative where this document and the binary disagree; please report the
disagreement.

## Native commands

Native syntax starts with an operation and keeps endpoints, selectors, and
target placement in separate arguments:

```sh
syq cp project --to server --into /backup       # named object → /backup/project
syq cp --src-src project --to server --into /app # project contents → /app
syq cp --from server --cwd /data --src a --src b --into ./data
syq cp --src-file report --src-dir assets --into /backup
syq cp --src-files a.txt b.txt --src-dirs images fonts --into /archive
syq cp report --to server --as-new /reports/final
syq cp --hash report --to server --as-existing /reports/final
syq cp-prune --src-src build --to server --into-existing /srv/app
syq rm cache old-output
syq rm --from server --cwd /srv --src old-output
syq rm --root /srv --src-dir cache
syq rm --cwd /srv --follow --src-dir current-release
```

`--from [USER@]HOST` selects one source endpoint and `--to [USER@]HOST`
selects one target endpoint; omission means local. A local path containing `:`
stays local because native mode never guesses endpoints from path text.
`--cwd DIR`/`-C DIR` changes where relative source selectors are resolved at
the source endpoint. Copy selectors may be absolute and then ignore `--cwd`.
Removal selectors are always relative; native `rm` rejects a leading slash and
any `.` or `..` component.

Bare paths and repeatable `--src PATH` select named objects. A named directory
keeps its basename at the target; a named symlink is copied as a symlink. A
trailing slash is ordinary path spelling and has no semantic effect.
`--src-file PATH` adds the precondition that the named object is not a
directory, while `--src-dir DIR` requires a directory; on a match they copy
exactly like `--src`, including copying a selected symlink rather than following
it. These typed selectors are available to `cp`, `cp-prune`, and `rm`.
`--src-src DIR` selects a directory's contents and merges them directly into
the target container. `--srcs PATH...`, `--src-srcs DIR...`, `--src-files
PATH...`, and `--src-dirs DIR...` are bulk conveniences for the corresponding
singular selectors. Symlinks found while traversing a directory are copied as
symlinks and are never followed. Singular selector options consume their next
argument even when it begins with `-`, so every Unix filename is expressible
without losing raw path bytes.

Placement is always explicit in this initial native surface:

| Placement | Mapping | Target precondition |
|---|---|---|
| `--into DIR` | Put selected names inside `DIR` | Use or create the directory |
| `--into-new DIR` | Put selected names inside `DIR` | Must not exist |
| `--into-existing DIR` | Put selected names inside `DIR` | Must already be a directory |
| `--as PATH` | Map one named source exactly to `PATH` | Create or update the path |
| `--as-new PATH` | Map one named source exactly to `PATH` | Must not exist |
| `--as-existing PATH` | Map one named source exactly to `PATH` | Must exist |

The `new` and `existing` forms are lightweight placement-root pathname checks
during the ordinary initial destination inspection. A mismatch fails before
transfer mutation begins. After a successful check, the current engine's
ordinary pathname and publication behavior applies: these forms do not pin an
inode or provide compare-and-swap behavior against a concurrent namespace
writer. Changed regular files continue to use staged atomic publication.
Mapping a non-directory source exactly onto an existing directory is rejected
during the source's first scan batch, in both dry-run and execution.

`cp` copies or updates mapped source objects and keeps unrelated target
objects. `cp-prune` uses the same mapping and transfer engine, then applies the
existing safe deletion planner to remove target-only descendants in mapped
directory scopes. It never removes a source and requires explicit placement;
`--max-delete N` keeps its all-or-nothing deletion budget.

Native `rm` resolves every explicit selector at the endpoint and pins the
result before it makes its first change. Missing selectors are successful and
duplicate or overlapping selectors may perform redundant work; they are not
canonicalized or deduplicated. Removal then runs in an endpoint-local worker
pool relative to the pinned directory handles. A namespace entry already
removed by another selector is successful. Symlinks encountered while walking
inside a selected directory are removed as entries and are never followed.

By default, native `rm` follows no symlinks while resolving `--cwd` or a
selector. A symlink selected by name is removed as a symlink without touching
its referent. A symlink in `--cwd`, or in a selector before the selected name,
would have to be traversed; encountering one therefore aborts the entire
command before mutation. `--follow` explicitly enables that traversal. The
resolved non-symlink file or directory is then removed while the symlinks used
to reach it remain in place, usually dangling.

`--root DIR` is mutually exclusive with `--cwd`. The root path itself must
contain no symlink, even with `--follow`. Selector resolution is confined to
the pinned root and fails as soon as a relative or absolute symlink target
would leave it, even if later components would re-enter. `--cwd` is not a
containment boundary when `--follow` is used.

For removal, `--src PATH` and bare paths accept either a terminal file or
directory and remove that object, recursively for a directory. As with copy,
`--src-file PATH` requires a non-directory terminal object, while
`--src-dir DIR` requires a directory and removes its entire tree.
`--src-src DIR` requires a directory, removes its contents, and retains the
resolved directory itself. All type checks and selector resolution finish
before deletion begins. `-vv` prints the base identity, symlink hops, and final
device/inode resolution used for the operation's audit trail.

Remote native `rm` is attached to its control connection. While work remains,
the endpoint sends a result or liveness frame at least once per second. A
detected write failure cancels queued work and stops directory scans from
scheduling more removals; operations already completed or inside a filesystem
call are not rolled back. Native `rm` has no detached mode.

The first native fidelity default is exactly `-rlt`: it recurses through
directories, copies symlinks as symlinks, and retains mtimes. Owner, group,
modes, special files,
hard links, ACLs, xattrs, filtering, other copy policies, and the automation API
are intentionally not frozen by this first grammar. Use `syq rsync` when the
current compatibility options for those capabilities are needed.

All native commands accept `-n`/`--dry-run`, `-v`/`--verbose`, `-q`/`--quiet`,
`-j`/`--connections`, `--progress`/`--no-progress`, and `--progress-json` in
addition to their endpoint and selector options. `cp` and `cp-prune` also
accept `--hash`, `--no-compress`, `--bwlimit RATE`, and `--stats`. `--hash`
compares existing regular-file contents with full BLAKE3 digests instead of
trusting equal size and modification time; it does not add a second
post-transfer verification pass. The bandwidth limit applies only to file
data, not scanning, hashing, metadata, or pruning. A
command-restricted remote-to-remote receiver independently enforces the signed
aggregate limit. A receiver installed by an older syq rejects that V2 grant
safely; rerun `syq enroll HOST:DEST` to refresh an existing enrollment to the
current binary. `cp` additionally accepts `--mapping` and `--results` (see
[Mappings](mappings.md)). `cp-prune` additionally
accepts `--max-delete`; `rm` additionally accepts `--root` and `--follow` plus
its endpoint-side removal semantics.

Preservation policies, filters, other comparison and write controls, block and
split sizing, and SSH/transport configuration remain available only through `syq rsync`;
sharing the transfer engine does not expose those options in native mode.
Remote-to-remote copies still use the ordinary automatic transport. Native raw
path bytes are relayed through syq's protocol when they cannot be represented
in a direct remote shell command.

## Mappings

Placement can also be data instead of flags: `syq map` prints the resolved
selection and placement of a command as JSON lines, and `syq cp --mapping`
executes such a manifest — a generalized `--as` covering many entries, each
with its own destination. Between the two, any tool that edits JSON can
reshape a transfer:

```bash
set -o pipefail
syq map --src-src photos \
  | jq '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C photos --to nas --into /pub
```

Conflicting destinations are refused before any byte moves. See
[Mappings](mappings.md) for the format, more one-line transforms, the
`--results` outcome stream, and limits.

## Rsync compatibility

The complete previous command surface remains available under `syq rsync`:

```
syq rsync [OPTIONS] SRC... DEST
syq rsync [OPTIONS] [USER@]HOST:SRC... DEST
syq rsync [OPTIONS] SRC... [USER@]HOST:DEST
```

```sh
syq rsync -av project/ server:backup/project/       # push
syq rsync -av server:data/ ./data/                  # pull
syq rsync -a /mnt/nfs/tree /local/tree              # local → local
syq rsync -a hostA:big/ hostB:big/                  # direct remote → remote
syq rsync -a --relay hostA:big/ hostB:big/          # relay when A cannot reach B
syq rsync -av -j 16 bigdir server:dest              # fixed parallelism
syq rsync -a --dry-run -v src host:dst              # preview
syq rsync -a --verify-only src host:dst             # compare only
```

The sections below document this retained compatibility surface unless they
explicitly say otherwise.

### Compatibility options

| Option | Meaning |
|---|---|
| `-a`, `--archive` | Same as `-rlptgoD` |
| `-r` `-l` `-p` `-t` `-g` `-o` `-D` | Recursive; symlinks as symlinks; perms; mtimes; group; owner; devices and specials |
| `-v`, `-vv` | `-v` lists files as they complete; for copies, `-vv` also explains remote helpers, candidate TCP addresses, the planned transport, and initial concurrency |
| `-q` | Errors only |
| `-z`, `--compress` / `--no-compress` | Enable (the default) or disable zstd compression in syq's protocol; this is not `ssh -C` |
| `-n`, `--dry-run` | Resolve mappings and transport, estimate transfers/exclusions/deletions; change nothing |
| `-j N`, `--connections N` | Parallel data connections (default: auto-tuned, see [Speed](speed.md#how-many-connections--j)) |
| `--bwlimit RATE` | Limit aggregate file-data throughput (bare rate is KiB/s; `0` disables) |
| `--block-size SIZE` | Transfer and hash block size (default 4M) |
| `--min-split SIZE` | Don't split an in-flight file with less than this left (default 32M) |
| `--progress` / `--no-progress` | Progress meter (default on when stderr is a terminal) |
| `-P` | Turns on `--progress` (the `--partial` half is always on; see below) |
| `--partial` | No-op for rsync compatibility (syq always keeps partial files) |
| `--numeric-ids` | No-op for rsync compatibility (syq always uses numeric uid/gid) |
| `--insecure-links` | Allow a receiving process to follow destination-path symlinks owned by other users (unsafe legacy opt-out) |
| `--progress-json` | One JSON line per second on stderr |
| `--stats` | Summary counts at the end |
| `-c`, `--checksum` | Compare every file with BLAKE3 instead of size+mtime; repair mismatches (native spelling: `--hash`) |
| `--verify-only` | Hash every file in the run's scope on both sides and report differences; write nothing |
| `--inplace` | Write directly into destination files (no partial + rename) |
| `--checkpoint FILE` | Avoid completed-file destination lookups on later runs; normal resume does not need it |
| `-e CMD`, `--rsh CMD` | Remote shell command; bypasses automatic broker, receiver, and enrollment setup and controls agent forwarding itself (default `ssh`) |
| `--syq-path PATH` | Use this exact remote `syq` instead of the managed helper |
| `--no-bootstrap` | Require `syq` on the remote `PATH`; do not install a managed helper |
| `--no-tcp` | Send data over the ssh connection instead of separate TCP sockets |
| `--tcp-plain` | TCP data connections without encryption (trusted networks only) |
| `--tcp-ports LO-HI` | Port range the remote listens on for TCP data (default 47600-47699) |
| `--tcp-congestion ALGO` | Linux: use `ALGO` on both ends of direct TCP data sockets; the host default is unchanged |
| `--ignore PATTERN` | Skip paths matching a gitignore-style pattern (repeatable; see below) |
| `--ignore-from FILE` | Read ignore patterns from a file (repeatable, stacks with `--ignore`) |
| `--delete` | Remove destination paths the source doesn't have (see below); `--delete-after`/`--delete-delay` are synonyms |
| `--delete-excluded` | With `--delete`, also remove destination paths the `--ignore` patterns exclude |
| `--max-delete N` | With `--delete`, delete nothing if more than N deletions are planned (exit 25) |
| `-u`, `--update` | Skip files that are newer on the destination |
| `--existing` | Only update files that already exist on the destination; create nothing |
| `--ignore-existing` | Only create files missing on the destination; update nothing |
| `--max-size SIZE`, `--min-size SIZE` | Don't transfer regular files larger / smaller than SIZE |
| `--files-from FILE` | Copy only the listed paths (relative to the one source directory; see below) |
| `--from0` | `--files-from` entries are NUL-separated |
| `--rm` | Remove the given paths recursively and in parallel (see below) |
| `--relay` | Remote-to-remote: route data through this machine instead of running on the source host |
| `--no-forward-agent` | Remote-to-remote with default `ssh`: give hostA no agent; it must have credentials for hostB (conflicts with `-e`) |
| `--agent-broker-only` | Remote-to-remote: use destination-bound authentication without installing or using the command-restricted receiver |
| `--unrestricted-agent-forwarding` | Remote-to-remote compatibility escape hatch: expose the complete local agent to hostA instead of the constrained broker |
| `--detach` | Remote-to-remote: run the transfer detached on the source host so it survives losing this ssh session; prints the follow target even with `-q` |
| `--follow HOST:LOG` | Attach to a detached transfer's log and stream its progress |
| `-h` | No-op for rsync compatibility; sizes are always human-readable. Use `--help` for help |

Like rsync, `-q` suppresses ordinary non-error output: progress, summaries,
notices, and `-v` file listings are hidden. The warning that
`--unrestricted-agent-forwarding` exposes the complete ambient agent is never
hidden by `-q`. Copy failures are still written to stderr and reflected in the
exit status.

`--bwlimit` is one approximate limit shared by every `-j` worker, not a
per-connection limit. As in rsync, a bare rate is KiB/s, suffixes such as `K`,
`M`, `G`, and `MiB` use powers of 1024, a final `+1` or `-1` adjusts the scaled
value by one byte, and `0` means unlimited. SYQ counts uncompressed file bytes;
protocol overhead is not counted, and transport compression may make the actual
network rate lower. Scanning, hashing, and metadata operations are not limited.

Remote transfers use fast zstd level-1 compression by default. Each protocol
frame is sent compressed only when that representation is smaller, so archives,
media, and encrypted data do not expand on the wire. They still cost a fast
compression attempt; use `--no-compress` when CPU is scarcer than network
bandwidth, particularly on a very fast LAN. Compression is transport-only and
does not change file contents, hashes, resume offsets, or `--bwlimit` accounting.

### Remote-to-remote

`syq rsync hostA:src hostB:dst` copies directly from one remote host to
another. The topology, the default least-privilege authentication path, the
options that fail closed under it, enrollment lifecycle, and the escape
hatches are documented in [Remote-to-remote transfers](remote-to-remote.md).

## Path semantics

Identical to rsync:

- `syq rsync -a src dest` copies the directory itself → `dest/src`. `dest` is
  created if missing.
- An existing non-directory `dest` cannot be the parent of that `dest/src`
  mapping; dry-run rejects it instead of presenting an impossible summary.
  With `--existing`, both dry-run and the real command skip the whole mapping
  as a no-op because creating `dest/src` is outside the selected scope.
- `syq rsync -a src/ dest` copies the *contents* of `src` into `dest`. `src/.` and
  `.` behave the same way.
- A single file source goes to `dest/file` if `dest` is an existing directory,
  otherwise `dest` is the new filename.
- Several sources require (or create) a directory destination. With several
  sources syq scans them all before writing anything, so two sources mapping
  onto one destination path is refused before the destination is touched —
  not even a missing destination directory is created (the transfer starts
  once the scans finish). Naming the destination file itself as one of the
  sources doesn't change that: it would be overwritten, so it's a conflict.
  The price is memory: every scanned entry is held until the scans are
  validated, roughly a few hundred bytes per entry across all sources.
- An exactly repeated source operand is scanned once. It still counts toward
  the original source count for placement, so `syq file file new-dest` creates
  the directory `new-dest` and writes `new-dest/file`.
- An explicitly supplied destination root that is a symlink to a directory is
  that directory when the link is owned by root or by the receiver's effective
  uid (the link is kept, with or without a trailing slash). A foreign-owned
  component is refused unless `--insecure-links` is given. Each receiving
  connection retains and verifies the selected directory, so replacing the
  external destination spelling afterward cannot redirect its writes. A
  symlink encountered below the destination root is payload at that path: it is
  replaced rather than followed, even when it points to a directory.
- Recognizable `.syq-part.<job-id>` paths in a source are copied as ordinary
  payload and produce one warning summary. Before transfer starts, SYQ rejects
  the exceptional case where a mapped payload path exactly equals a sidecar
  this job would use for another mapped file.
- `host:path` is relative to the remote home; `host:/abs` and `host:~/x` work.
  A colon before the first slash means remote; `./x:y` is local. All sources
  must be on the same host. `host::module` (daemon syntax) is not supported.

### Previewing a copy

`-n` / `--dry-run` connects to the endpoints and scans both sides, but creates,
updates, and deletes nothing. Its concise preflight summary makes path
placement, intended changes, logical work, and the selected data route explicit
before a real copy:

```text
syq: dry-run summary
  mapping: ./dataset/ -> gpu01:/scratch/run42 (directory contents)
  changes: 82,411 regular files; 96 directories; 14 symlinks; 3 metadata-only entries; 2 type replacements among them
  deletions: 7 entries planned after a successful copy
  logical data: 1.70 TiB in 82,411 files needing content work (upper bound); 340 GiB in 18,204 files with unchanged content
  exclusions: 3 paths/subtrees pruned by ignore rules; 12 other entries
  route: encrypted TCP to gpu01; 16 initial connections (auto-tuned)
```

Each source gets its own `mapping` line. The annotation distinguishes directory
contents, a directory copied as a child, a file placed inside a directory, and
an exact destination path. `--files-from` is identified as a selected-path
mapping. A destination-root symlink is shown as the effective directory it
resolves to. By default, syq follows a symlink in this operator-named path only
when the link is owned by root or by the receiving process's effective user,
matching rsync. This rule is the same for every receiver; running as root makes
links owned by an unprivileged user fail it. `--insecure-links` restores the
legacy follow-any-link behavior. The `changes` line separately accounts for regular files,
directories, symlinks, special files, and metadata-only updates; type
replacements are called out as an overlapping subset. This is a current
preflight assessment, not a frozen mutation ledger that can later be executed
unchanged. When a destination leaf will be replaced by a directory, descendants
are assessed against that post-replacement directory rather than through the
old leaf (including an old symlink).

The logical-data upper bound is the full size of regular files that fail the
planning-time metadata check. Resume state, block reuse, reflinks, compression,
server-side copying, or a content comparison can make the real I/O or wire-byte
count smaller. An ignored directory is pruned without scanning its descendants,
so the exclusions line counts that directory as one `path/subtree`; it does not
invent a descendant count. Other exclusions cover state and size options and
unsupported entry types. With `--delete`, the destination is walked and the
exact deletion count is shown; scan errors and `--max-delete` guards are shown
as skipped or blocked rather than as a misleading zero.

Add `-v` for a typed explanation of each intended change, for example `create
file PATH (destination missing)`, `replace with symlink PATH -> TARGET
(destination is regular file)`, `update metadata PATH (requested file metadata
differs)`, or `delete PATH (destination only)`. The default stays compact for
large trees.

### What `-a` does here

`-rlptgoD`: recurse, symlinks as symlinks (targets copied verbatim,
dangling links included), permissions, mtimes, group, owner, and device /
fifo / socket nodes via `mknod`. Owner is only set when the *receiving* side
runs as root; group is attempted for everyone and silently skipped on
`EPERM`, as rsync does. Without `-p`, new files get the source mode masked
by the local umask and existing files keep their mode. Without `-t`, every
file is transferred every time (the quick check needs mtimes).

Directory mtimes are set last, deepest first, so writing children doesn't
disturb them. A directory syq must write into but can't (no owner write bit)
is opened up for the duration and gets its own mode back at the end — or the
source's mode with `-p`.

## How it works

One control connection per endpoint does the scan (a parallel walk on each
side, streamed in batches), the diff, directory creation and metadata.
Workers receive no file work until the mapped payload/sidecar namespace
preflight completes. For a fresh remote destination with a selected TCP route,
they begin connecting as soon as a source batch proves that file work exists,
overlapping authentication with sidecar resolution and directory creation;
an empty tree opens no worker connection.
The data connections — by default separate TCP sockets carrying AES-256-GCM
records — carry only "read range" / "write range" requests. When data uses SSH
(through `--no-tcp` or TCP fallback), a transfer consisting entirely of fresh
small files opens worker sessions over the already-authenticated OpenSSH control
connection; larger or mixed workloads retain separate `ssh` processes, TCP
flows, and cipher processes. A custom `-e` command keeps its own SSH
multiplexing policy. Files go onto a largest-first queue; when a worker runs dry
it steals the back half of the remaining range of whichever file has the most
left, so the tail of a transfer stays parallel without pre-deciding chunk
counts.

On the receiving side a file that needs content changes is written beside its
destination as `.name.syq-part.<job-id>` (preallocated with `fallocate`,
written with `pwrite` from several workers), given its metadata, and `rename`d
over the target. Newly created sidecars are mode `0600`; final metadata is
applied just before publication. When an existing final file is the comparison
basis, the receiver retains that open descriptor while its blocks are hashed.
If every block matches, metadata is applied through the descriptor without
allocating or publishing a sidecar; otherwise that exact descriptor seeds the
sidecar.
The job ID is a 128-bit digest of the normalized source/destination mapping and
content-affecting options, and is stable when the same logical command is
rerun. It includes trailing-slash mapping, order-sensitive filters, metadata
semantics and block size, but not operational controls such as checksum
checking, `-j`, verbosity, progress or bandwidth limiting. Filesystem
component limits are queried and cached per directory; long basenames are
deterministically truncated and disambiguated to fit. An exceptionally long
full path still fails that one file with a clear error (even when it is
already up to date) while the rest of the transfer continues, and so does a
destination entry — say, a directory some other tool left — already occupying
the exact path this job's sidecar for that file needs. SYQ does not `fsync` transfer data;
atomic sidecar publication provides old-or-new visibility and resumable
interrupted work, not crash-durability across power loss.
Small files still use a pipelined whole-file request, but the receiver writes
each request through its sidecar and renames it before acknowledging success.
Thus every non-`--inplace` content change appears atomically complete, while
an existing file that SYQ compares block by block and finds content-identical
keeps its inode and any destination hardlinks. The same-host kernel-copy fast
path may replace a byte-identical destination that failed the quick check,
because it deliberately avoids that comparison.
`--inplace` writes every file directly (for example, to update a large file
without room for a second copy), so readers can observe partially updated
contents and an interruption leaves the final file unfinished.

Local → local runs the same machinery in-process with N threads, which helps
on NFS and NVMe.

### Resume and checkpoints

With the default staged write path, Ctrl-C is safe: kill it and rerun the same
command. `--inplace` deliberately gives up that guarantee. No checkpoint is
needed for this normal resumption. Resume works at two levels.

**Within a file.** There is no per-file state file — the partial *is* the state:

- Files whose size and mtime already match are skipped (the rsync quick check).
- If this job's range-transfer `.name.syq-part.<job-id>` exists, both sides
  hash it and the source with full BLAKE3 digests in `--block-size` blocks and
  only the mismatching blocks are sent. A leftover is reused only when it can
  be safely opened as a singly-linked regular file without following a symlink; numeric ownership is
  deliberately not required because NFS root squashing and some FUSE/CIFS
  mounts remap it. A safe leftover that cannot be made mode `0600` is discarded
  and recreated instead of permanently blocking that file. Anything else is
  safely replaced or reported as an error.
  On NFS, reuse requires the receiver to reread the partial; syq deliberately
  keeps no separate block-completion map.
  Pipelined small files are rewritten wholesale on retry instead of paying an
  extra partial-file probe.
- If the destination file exists but differs, its blocks are hashed against
  the source too; if all match only metadata is fixed, otherwise the matching
  blocks are copied locally into a new partial and the rest transferred.

This block-level skip catches appends and in-place modifications (VM images,
databases, logs). It does **not** catch a byte inserted near the start of a
file, which rsync's rolling checksum would — for syq's intended use (fresh
uploads and downloads) that trade was made deliberately.

The partial job ID includes `--block-size` and the ordered ignore rules, so
changing either starts a separate resumable namespace. Old sidecars are not
garbage-collected automatically and may be deleted manually when the earlier
command will not be resumed. Options that do not change the copy itself, such
as `-c`, `--bwlimit`, and `-j`, do not change the partial ID.

The directory containing a destination sidecar is a trust boundary, as with
rsync's partial directories. It must not be writable by untrusted users,
especially when SYQ runs with elevated privileges. A reused sidecar may have a
filesystem-remapped numeric owner; mode and link-count validation cannot prove
who originally created a deterministic pathname in a shared writable
directory.

Versions 0.1.1 and 0.1.2 used `.name.syq-partial`. This version deliberately
does not recognize or resume that legacy form: remove any such destination
sidecars manually after an interrupted old-version transfer. A legacy-named
file in a source tree is copied as ordinary payload without a special warning.

**Across the whole job.** Ordinary copies keep no transfer history, but their
source and destination scans still skip files already complete. Deleting or
changing a destination file affects the next run just as it does with rsync.

Only when repeated destination metadata lookups are themselves too expensive
should you opt in to a checkpoint:

```sh
syq rsync -a --checkpoint ./copy.state huge-tree/ host:huge-tree/
# after an interruption, run the identical command again
```

The mode-0600 JSONL checkpoint identifies the canonical source, destination,
and copy semantics. It records regular files only after SYQ established that
the destination was complete and, for transferred files, rechecked the source.
On retry, a record whose source fingerprint still matches (size, nanosecond
mtime, and requested mode/owner/group metadata) skips that destination lookup.
Everything else follows the normal quick check, partial hashing, and transfer
path. Unfinished individual files are never checkpoint-complete; their actual
`.syq-part.<job-id>` contents remain the resume state.

The checkpoint is flushed about once a second and persists after both failed
and successful runs until you remove or stop passing it. Losing its last
buffered records only causes repeated work; if recording stops mid-run the
copy continues and a warning names the I/O error — printed even under `-q`,
while the exit code keeps describing the copy itself. Invalidation records are
flushed before a checkpoint-covered destination is removed or changes type,
but the checkpoint is not `fsync`ed and does not promise recovery across power
loss. If an existing checkpoint has completed records but an expected
destination root is missing, SYQ fails and asks you to remove the checkpoint to
restart. The checkpoint must be a regular file with exactly one hard link and
must be outside local source and destination trees; a hardlinked checkpoint is
refused because appending or changing its permissions would also affect its
other names. `-n` reads and validates existing state but never creates or
changes it. `-c`, `--verify-only`, and `--rm` conflict with `--checkpoint`. One
checkpoint file may be used by only one running copy at a time. Its filesystem
must support advisory file locking; SYQ fails rather than write checkpoint
state without single-writer exclusion.

A checkpoint is an explicit trust decision: SYQ does not inspect a destination
file covered by a matching record. If another process deleted, replaced, or
modified that destination after it was recorded, a checkpointed retry will not
notice. Do not use a checkpoint when the destination may be independently
modified; omit the option and SYQ remains history-independent. `--delete`
records what it removes in an active checkpoint, so a file the source drops
and later brings back is transferred again rather than assumed complete.

Like rsync, ordinary SYQ runs do not coordinate with each other. Different
logical commands use different partial names, so concurrent copies into one
tree produce the union of their files and one whole-file rename wins for any
path both write — but do not combine concurrent copies with `--delete`,
which mirrors *its* source and removes the other command's not-yet-shared
files and sidecars as extras. A content-identical comparison applies metadata only through
the inode it verified, so it cannot mix its metadata with another job's newly
renamed contents. Quick-check metadata repair likewise verifies the inode;
if a concurrent publication replaced it, the repair reports an error instead
of mixing metadata with the new contents.
Starting the same logical command twice at once is
unsupported: both invocations intentionally address the same resumable
sidecars. After a crash, abandoned sidecars may be deleted manually if that
command will not be resumed.

These guarantees cover other SYQ jobs, which publish complete files by rename.
They do not cover another process modifying an existing destination inode in
place while SYQ is hashing or reusing it. As with rsync, such an external
writer can invalidate a comparison after it was made; do not independently
modify destination files during a transfer.

### Verification and consistency

Always:

- Every transferred block carries a full BLAKE3 digest computed by the reader
  and checked by the receiver; a mismatch aborts that file with an error (exit
  23) rather than silently continuing — it indicates transport corruption,
  which is rare.
- After a file completes, the source is re-stat'ed. If its size or mtime
  changed during the transfer the file is redone (up to three attempts), then
  reported as an error.
- Unless `--inplace` was explicit, destination content changes appear
  atomically via rename, including new small files.
- Non-zero exit if anything failed.

On request:

- `--verify-only` hashes every file on both sides with BLAKE3 in parallel and
  reports `DIFFERS` / `MISSING`.
- `-c`/`--checksum` (`--hash` in the native interface) does the BLAKE3 block
  comparison for every file, not just ones that fail the quick check, and
  repairs what differs.

Full BLAKE3 digests replaced XXH3 for content decisions in September 2026 so a
digest match is collision-resistant rather than merely a fast corruption
check. In one release-mode, single-thread CPU microbenchmark with 4 MiB inputs
on an AMD EPYC 9454P, BLAKE3 processed 6.69 GB/s, compared with 31.25 GB/s for
XXH3 and 1.86 GB/s for SHA-256. This is design-rationale data, not an end-to-end
copy-speed claim; filesystem and transport work usually dominate, and syq
hashes concurrently across workers.

Not verified: directory and symlink metadata are set but not read back; a
source that changes *between* the final re-stat and the next block of another
file isn't noticed (same as rsync). Two chunks of one file are read at
different moments, so a file being written while copied may come out mixed —
the re-stat catches the common case, `--verify-only` afterwards catches the
rest.

Compared with rsync: ordinary content-changing writes use the same
temporary-file plus atomic rename model; `--inplace` explicitly gives that up.
Rsync chooses a random temporary suffix, while SYQ uses a deterministic job ID
so an interrupted command can find its partial again without a local state
file. The change-during-transfer check is the same idea; `--delete` runs
strictly after the transfer (see below); hardlinks aren't implemented.

## Ignoring paths (`--ignore`, `--ignore-from`)

syq has one filter mechanism instead of rsync's include/exclude/filter rules:
every `--ignore PATTERN` is a line of a virtual `.gitignore` anchored at each source
root, and `--ignore-from FILE` splices in the lines of a file. Patterns from
both are applied in command-line order with gitignore semantics (last match
wins, `!` re-includes), so anything you'd write in a `.gitignore` works here:

```sh
syq rsync -a --ignore node_modules --ignore .git src/ host:dst/ # a name matches at any depth
syq rsync -a --ignore '*.o' --ignore /build src/ host:dst/      # glob; leading / anchors to root
syq rsync -a --ignore 'logs/*' --ignore '!logs/keep/' src/ dst/ # everything in logs/ except keep/
syq rsync -a --ignore-from .gitignore --ignore '!dist/' repo/ host:repo/
syq rsync -a --ignore '*' --ignore '!*/' --ignore '!*.jpg' photos/ bak/ # copy only *.jpg
```

Rules of thumb (they're git's): `foo` matches a file or directory named `foo`
at any depth; `/foo` only at the source root; `foo/` only a directory; `*`
doesn't cross `/`, `**` does. An ignored directory is pruned, so nothing inside
it is transferred or even scanned — which is why "only `*.jpg`" needs the
`!*/` line to keep descending. Empty directories are copied like any other
(this is a filter on the walk, not git's notion of what's tracked). The source
root itself is never ignored; with several sources each is filtered from its
own root. `-n` previews the selected scope and intended changes. `--rm` does not
take filters (it always removes the whole tree), so `--ignore` conflicts with it.

As in git, a `!` rule cannot re-include something whose parent directory is
ignored: `logs/**` prunes `logs/keep` itself, so `!logs/keep/**` after it has
nothing to act on. Ignore the siblings instead (`logs/*`, which does not cross
`/`) and re-include the directory (`!logs/keep/`), as above.

## Deleting extras (`--delete`)

`syq rsync -a --delete src/ host:dst/` makes `dst` look like `src`: after the
transfer, anything under a destination directory that the source doesn't
have is removed. The rules are simpler than rsync's, deliberately:

- **Scope.** Only inside directories the sources map onto: `syq rsync --delete a b
  dst/` cleans `dst/a` and `dst/b`, never `dst/c`. A single-file source deletes
  nothing.
- **Ignored means out of scope, on both sides.** The `--ignore` patterns are applied
  to the destination walk from the same roots, so an ignored entry is neither
  copied nor deleted, and a directory that holds one is kept (`not deleting
  keep/: it holds ignored paths`, on stderr, not an error). Patterns are
  matched against each side's actual entry, with gitignore's one type
  distinction: `cache/` matches only directories, so it protects a destination
  directory named `cache` but not a destination *file* of that name, which is
  an ordinary extra (rsync behaves the same). Write `cache` without the slash
  to cover both. `--delete-excluded` drops that protection: ignored paths on
  the destination are extras too.
- **Anything the source has is safe.** A file skipped by `-u`, `--existing`,
  `--ignore-existing`, `--max-size` or `--min-size` — or a symlink or special
  file skipped for lack of `-l`/`-D` — still exists in the source, so its
  destination copy is left alone, as in rsync. Such files are reported under
  `files excluded` in `--stats`.
- With `--delete` the sidecar path of every mapped regular file stays in
  memory until deletions run (that set is what tells a live sidecar from an
  orphan); on multi-million-file trees this is the option's main memory cost.
- **After, not before.** Deletions run once every file has been transferred
  and only if the whole source scan succeeded: an unreadable source directory
  would otherwise look like one whose contents vanished (`source scan reported
  errors; skipping deletions`). The destination walk is held to the same rule:
  an unreadable directory *there* looks empty and would be removed over its
  unknown contents, so its errors also skip all deletions. A run interrupted
  during scanning or transfer therefore never starts deletion. Once deletion
  has begun, interruption can leave some planned extras removed; rerunning
  finishes the mirror. Directory mtimes are set after the deletes.
- **Sidecar-patterned files are extras unless they are this job's live
  resume state.** A `.name.syq-part.<job-id>` of *this* command whose `name`
  is still in the source stays, whatever happened to that file this run
  (failed, filtered, already up to date): the next transfer of that file
  consumes it. Everything else matching the pattern — an orphan of this
  command, or any other job id — is an ordinary extra: syq copies such names
  as payload, so the name alone proves nothing, and mirroring the source is
  what --delete is for. Note that the job identity includes the command's
  semantic options: change those (or the source/destination spelling they
  normalize to) and the previous identity's sidecars become orphans —
  removed by `--delete`, inert otherwise.
- `--max-delete N` refuses to delete anything — not the first N — when more
  than N deletions are planned, says so, and exits 25 (rsync's code for it).
- `-n --delete -v` lists every intended removal as `delete path (destination
  only)`. The preflight summary reports the number planned; a real run reports
  the number deleted. `--delete`
  conflicts with `--verify-only` (deleting is the opposite of writing
  nothing) and with `--files-from` (deletion scope under a file list is
  ambiguous).

Deletion goes through the control connection in batches of 1000 (the
destination side unlinks each batch in parallel); it isn't spread over the
`-j` data connections like `--rm` is.

## Skipping by state and size

- `-u` / `--update`: a file whose destination copy has a newer mtime is left
  alone (regular files only). Neither `-u` nor `--ignore-existing` can be
  combined with `--inplace`: an interrupted in-place write leaves a
  partially-written final file that looks newer, which those filters would
  then skip on every retry.
- `--existing`: never create anything — files, symlinks, specials,
  directories, *or the destination itself* — that isn't already there;
  existing files are still updated. `--ignore-existing` is the mirror image: create what's
  missing, never touch what exists — including an existing file or symlink
  where the source maps a *directory*: it stays, and that directory with its
  whole subtree is skipped with a notice (rsync would delete the file to
  make room). Both apply to every non-directory entry.
- `--max-size` / `--min-size`: regular files outside the range are not
  transferred (`4K`, `100M`, `2G`; the same suffixes as `--block-size`).
  Directories and symlinks are unaffected.

All of these define the scope of the run, so `--verify-only` checks the files
the same command would transfer and nothing else.

## Copying a list (`--files-from`)

`syq rsync -a --files-from list.txt host:src/ dst/` copies only the paths named in
`list.txt`, one per line (`--from0`: NUL-separated; `-` reads stdin), each
relative to the single source directory, to the same relative path under the
destination. The source is not walked, which is the point on a slow
filesystem when the list is known. Parent directories of listed paths are
created (with their metadata). A parent that is a symlink on the source is
followed — you named a path through it — and becomes a real directory on the
destination, so nothing is ever written through a destination symlink; a
parent that resolves to a file or dangles is an error. A listed directory is copied *without*
its contents unless `-r` is given on the command line itself — `-a` alone
does not count, as in rsync — so `-a -r --files-from` walks the directories
the list names (never the implied parents).
Blank entries and entries starting with `#` or `;` are ignored in both modes;
spell a literal comment-looking name as `./#name` or `./;name`. Leading `/` or
`./` and trailing `/` are stripped, and `..` components or an entry that names
the root itself are rejected. A listed path that doesn't exist is an error
(exit 23) and the rest is still copied. The destination must be a directory (an
existing file there is an error, never replaced). `--files-from` can't be
combined with `--ignore`/`--ignore-from` or `--delete`; for a remote-to-remote copy
it needs `--relay` (the list is read on this machine). To also choose each
entry's destination path, use a native mapping instead (see
[Mappings](mappings.md)).

## Parallel removal (`--rm`)

`syq rsync --rm [-j N] [-n] [-v] PATH...` removes trees the way syq copies them:
a parallel scan, files unlinked in batches across N workers, directories
removed deepest-first with each level in parallel. Symlinks are removed, not
followed. If a scanned non-directory is replaced by a directory before its
batch runs, SYQ reports the type change and never recurses into the new
directory. Remote paths (`host:path`) work. It refuses `/`, `.` and `~`. On
NFS, where every unlink is a round trip, `-j32` removed 20,000 files in 2.5 s
versus 9.7 s for `rm -rf`; on a local SSD `rm -rf` is already fast and syq is
no faster.

## Not implemented (on purpose, for now)

[rsync-compat.md](rsync-compat.md) tracks rsync compatibility in full: what matches, what
differs and why, what's missing, and the open issues. The short version:

- rsync filter rules (`--exclude`/`--include`/`--filter`); use `--ignore` (gitignore
  syntax) instead.
- `--link-dest`, `--backup`.
- `--delete-before`/`--delete-during` and `--force`. syq deletes only after
  the transfer (`--delete-after`/`--delete-delay` are accepted as synonyms).
- Hardlinks (`-H`), ACLs and xattrs (`-A`/`-X`).
- rsync daemon mode / `rsync://`. syq speaks its own protocol; it cannot talk
  to an rsync server.
- Rolling-checksum delta transfer (see Resume above).
- UDP or forward-error-correcting data transport. TCP retransmission/RTT
  counters are collected for diagnosis, but a loss-tolerant transport would be
  a separate protocol and security design.
- Preserving existing partial files from `rsync --partial`; only SYQ's own
  `.name.syq-part.<job-id>` sidecars for the same logical command are
  recognised.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Everything copied and verified |
| 23 | Finished, but some files failed (unreadable source, `DIFFERS`, changed during transfer …) — errors are on stderr |
| 25 | Finished, but `--max-delete` stopped the deletions |
| 1 | Fatal: bad arguments, couldn't connect, remote `syq` missing, connection lost |
