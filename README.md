# pcp

`pcp` is a parallel file copier with an rsync-shaped command line. It scans
source and destination, works out what differs, and moves the data over
**N independent connections at once** — encrypted TCP by default, authenticated
over ssh, falling back to ssh's own channels when a direct port can't be
reached — splitting large files into ranges
that idle workers steal from each other, so a single huge file at the end of
a transfer still uses every connection. Throughput is typically several times
that of a single ssh stream. It also has a progress meter that separates
transferred bytes from unchanged ones and automatically resumes interrupted
transfers from partial files without retransmitting their finished blocks. An
optional checkpoint can avoid repeated destination lookups for exceptionally
large or failure-prone jobs; it is not required for normal resumption. PCP can
also verify that a copy is complete.

## Install

```sh
cargo build --release          # binary at target/release/pcp
cargo install --path .         # or: put it on your PATH
```

The remote side runs `pcp --server`, but it does not need to be installed or
configured first. pcp uses an exact versioned helper under
`~/.cache/pcp/helpers/`. On first use of a version it detects the remote
platform, downloads the matching compressed binary from that version's GitHub
release, verifies its SHA-256 checksum, and installs it atomically. Later runs
execute that exact path without an extra probe connection. Linux x86-64 and
ARM64 and macOS Apple Silicon and Intel are published.

If the remote cannot reach GitHub, pcp uploads its current executable when the
local and remote platforms match. For a different-platform host without
outbound access, install a compatible binary yourself and pass
`--pcp-path /path/to/pcp`. `--no-bootstrap` disables managed helpers and
requires `pcp` on the non-interactive remote `PATH`.

The remote download uses `curl` or `wget`, `gzip`, and one of `sha256sum`,
`shasum`, or `openssl`. Version directories coexist and the helper cache can be
removed at any time; pcp recreates the helper it needs on the next connection.

- **macOS (Apple Silicon / Intel):** build natively on the Mac with
  `cargo build --release` (needs the Xcode command-line tools, `xcode-select
  --install`, for the bundled zstd C library). The tool is otherwise pure Rust
  and uses only POSIX calls; Linux-only optimizations (`fallocate`,
  glibc `mallopt`) are compiled out automatically. copy_file_range's local
  fast path is Linux-only; on macOS same-machine copies use the normal path.
- For portability across distributions (e.g. for the offline upload fallback
  to a host with an older glibc), build a static binary:
  `RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-gnu`
  (the musl target also works if `musl-gcc` is installed, which `zstd-sys` needs).

## Usage

```
pcp [OPTIONS] SRC... DEST
pcp [OPTIONS] [USER@]HOST:SRC... DEST
pcp [OPTIONS] SRC... [USER@]HOST:DEST
```

```sh
pcp -avz project/ server:backup/project/      # push
pcp -avz server:data/ ./data/                 # pull
pcp -a /mnt/nfs/tree /local/tree              # local → local (parallel scan and copy)
pcp -a hostA:big/ hostB:big/                  # remote → remote: runs on hostA, data goes A → B directly
pcp -a --relay hostA:big/ hostB:big/          # ...or relay through this machine if A can't reach B
pcp -avz -j 16 bigdir server:dest             # 16 parallel connections
pcp -a --bwlimit 50M src server:dst            # cap all connections at 50 MiB/s total
pcp -a -e 'ssh -p 2222 -i ~/.ssh/other' src host:dst
pcp -a --dry-run -v src host:dst              # show what would be copied
pcp -ac src host:dst                          # skip the quick check; compare blocks, repair differences
pcp -a --verify-only src host:dst             # compare only; transfer nothing
pcp -a src newhost:dst                        # the matching remote helper is automatic
pcp -a --checkpoint ./copy.state src host:dst # keep completed-file state for later runs
```

### Options

| Option | Meaning |
|---|---|
| `-a`, `--archive` | Same as `-rlptgoD` |
| `-r` `-l` `-p` `-t` `-g` `-o` `-D` | Recursive; symlinks as symlinks; perms; mtimes; group; owner; devices and specials |
| `-v` | List files as they complete (also new dirs, symlinks) |
| `-q` | Errors only |
| `-z`, `--compress` | zstd-compress data in transit (inside pcp's protocol, not `ssh -C`) |
| `-n`, `--dry-run` | Scan and report; change nothing |
| `-j N`, `--connections N` | Parallel data connections (default: auto-tuned, see below) |
| `--bwlimit RATE` | Limit aggregate file-data throughput (bare rate is KiB/s; `0` disables) |
| `--block-size SIZE` | Transfer and hash block size (default 4M) |
| `--min-split SIZE` | Don't split an in-flight file with less than this left (default 32M) |
| `--progress` / `--no-progress` | Progress meter (default on when stderr is a terminal) |
| `-P` | Turns on `--progress` (the `--partial` half is always on; see below) |
| `--partial` | No-op for rsync compatibility (pcp always keeps partial files) |
| `--numeric-ids` | No-op for rsync compatibility (pcp always uses numeric uid/gid) |
| `--progress-json` | One JSON line per second on stderr |
| `--stats` | Summary counts at the end |
| `-c`, `--checksum` | Compare every file block by block instead of size+mtime; repair mismatches |
| `--verify-only` | Hash every file on both sides and report differences; write nothing |
| `--inplace` | Write directly into destination files (no partial + rename) |
| `--fsync` | fsync each file, rename, and explicit checkpoint state (crash-durable; slower) |
| `--checkpoint FILE` | Avoid completed-file destination lookups on later runs; normal resume does not need it |
| `-e CMD`, `--rsh CMD` | Remote shell command (default `ssh`) |
| `--pcp-path PATH` | Use this exact remote `pcp` instead of the managed helper |
| `--no-bootstrap` | Require `pcp` on the remote `PATH`; do not install a managed helper |
| `--no-tcp` | Send data over the ssh connection instead of separate TCP sockets |
| `--tcp-plain` | TCP data connections without encryption (trusted networks only) |
| `--tcp-ports LO-HI` | Port range the remote listens on for TCP data (default 47600-47699) |
| `-i PATTERN`, `--ignore PATTERN` | Skip paths matching a gitignore-style pattern (repeatable; see below) |
| `--ignore-from FILE` | Read ignore patterns from a file (repeatable, stacks with `-i`) |
| `--delete` | Remove destination paths the source doesn't have (see below); `--delete-after`/`--delete-delay` are synonyms |
| `--delete-excluded` | With `--delete`, also remove destination paths the `-i` patterns exclude |
| `--max-delete N` | With `--delete`, delete nothing if more than N deletions are planned (exit 25) |
| `-u`, `--update` | Skip files that are newer on the destination |
| `--existing` | Only update files that already exist on the destination; create nothing |
| `--ignore-existing` | Only create files missing on the destination; update nothing |
| `--max-size SIZE`, `--min-size SIZE` | Don't transfer regular files larger / smaller than SIZE |
| `--files-from FILE` | Copy only the listed paths (relative to the one source directory; see below) |
| `--from0` | `--files-from` entries are NUL-separated |
| `--rm` | Remove the given paths recursively and in parallel (see below) |
| `--relay` | Remote-to-remote: route data through this machine instead of running on the source host |
| `--detach` | Remote-to-remote: run the transfer detached on the source host so it survives losing this ssh session |
| `--follow HOST:LOG` | Attach to a detached transfer's log and stream its progress |
| `-h` | No-op for rsync compatibility; sizes are always human-readable. Use `--help` for help |

`--bwlimit` is one approximate limit shared by every `-j` worker, not a
per-connection limit. As in rsync, a bare rate is KiB/s, suffixes such as `K`,
`M`, `G`, and `MiB` use powers of 1024, a final `+1` or `-1` adjusts the scaled
value by one byte, and `0` means unlimited. PCP counts uncompressed file bytes;
protocol overhead is not counted, and `-z` may make the actual network rate
lower. Scanning, hashing, and metadata operations are not limited.

### Remote-to-remote

`pcp hostA:src hostB:dst` starts the orchestrator *on hostA* over `ssh -A`
(agent forwarding), which then pushes to hostB with N connections, so data
flows A → B directly. Matching helpers are installed automatically on both
hosts. HostA must be able to ssh to hostB (with your forwarded agent, or its
own keys). Progress and `-v` output are streamed back. If hostA can't reach
hostB, `--relay` keeps the orchestrator here and routes every byte A → you → B
— always works, at half the bandwidth.
`pcp hostA:src hostA:dst` (same host and user on both ends) simply runs a
local copy on hostA.

Add `--detach` to let a remote-to-remote transfer outlive the ssh session that
launched it: pcp starts it on hostA, returns, and writes progress to a log on
hostA. Reattach with `pcp --follow hostA:LOG` to stream that progress.
An explicit `--checkpoint` path belongs to the machine running the
orchestrator: normally the invoking machine, but hostA for a direct or detached
remote-to-remote copy (`--relay` keeps it local).

## Path semantics

Identical to rsync:

- `pcp -a src dest` copies the directory itself → `dest/src`. `dest` is
  created if missing.
- `pcp -a src/ dest` copies the *contents* of `src` into `dest`. `src/.` and
  `.` behave the same way.
- A single file source goes to `dest/file` if `dest` is an existing directory,
  otherwise `dest` is the new filename.
- Several sources require (or create) a directory destination.
- A destination that is a symlink to a directory is that directory (the link
  is kept, with or without a trailing slash); a symlink to anything else is
  replaced like a file.
- pcp's own bookkeeping is never payload (as rsync excludes its
  `--partial-dir`): a source entry named `.name.pcp-partial` is silently left
  out. Everything else is copied.
- `host:path` is relative to the remote home; `host:/abs` and `host:~/x` work.
  A colon before the first slash means remote; `./x:y` is local. All sources
  must be on the same host. `host::module` (daemon syntax) is not supported.

### What `-a` does here

`-rlptgoD`: recurse, symlinks as symlinks (targets copied verbatim,
dangling links included), permissions, mtimes, group, owner, and device /
fifo / socket nodes via `mknod`. Owner is only set when the *receiving* side
runs as root; group is attempted for everyone and silently skipped on
`EPERM`, as rsync does. Without `-p`, new files get the source mode masked
by the local umask and existing files keep their mode. Without `-t`, every
file is transferred every time (the quick check needs mtimes).

Directory mtimes are set last, deepest first, so writing children doesn't
disturb them. A directory pcp must write into but can't (no owner write bit)
is opened up for the duration and gets its own mode back at the end — or the
source's mode with `-p`.

## How it works

One control connection per endpoint does the scan (a parallel walk on each
side, streamed in batches), the diff, directory creation and metadata.
The data connections — by default separate TCP sockets carrying AES-256-GCM
records (under `--no-tcp`, separate `ssh` processes instead), each its own flow
and cipher — carry only "read range" / "write range" requests. Files go
onto a largest-first queue; when a worker runs dry it steals the back half of
the remaining range of whichever file has the most left, so the tail of a
transfer stays parallel without pre-deciding chunk counts.

On the receiving side each file is written into `.name.pcp-partial` in its
directory (preallocated with `fallocate`, written with `pwrite` from several
processes), given its metadata, and `rename`d over the target. By default pcp
does not `fsync` each file (the rename still orders correctly, and per-file
fsync is costly on NFS); pass `--fsync` to force each file durable before the
rename for crash safety.
Small files still use a pipelined whole-file request, but the receiver writes
each request through its sidecar and renames it before acknowledging success.
Thus every non-`--inplace` final name appears atomically complete. `--inplace`
writes every file directly (for example, to update a large file without room
for a second copy), so readers can observe partially updated contents and an
interruption leaves the final file unfinished.

Local → local runs the same machinery in-process with N threads, which helps
on NFS and NVMe.

### Resume and checkpoints

With the default staged write path, Ctrl-C is safe: kill it and rerun the same
command. `--inplace` deliberately gives up that guarantee. No checkpoint is
needed for this normal resumption. Resume works at two levels.

**Within a file.** There is no per-file state file — the partial *is* the state:

- Files whose size and mtime already match are skipped (the rsync quick check).
- If a range-transfer `.name.pcp-partial` exists, both sides hash it and the
  source in `--block-size` blocks and only the mismatching blocks are sent.
  Pipelined small files are rewritten wholesale on retry instead of paying an
  extra partial-file probe.
- If the destination file exists but differs, its blocks are hashed against
  the source too; if all match only metadata is fixed, otherwise the matching
  blocks are copied locally into a new partial and the rest transferred.

This block-level skip catches appends and in-place modifications (VM images,
databases, logs). It does **not** catch a byte inserted near the start of a
file, which rsync's rolling checksum would — for pcp's intended use (fresh
uploads and downloads) that trade was made deliberately.

**Across the whole job.** Ordinary copies keep no transfer history, but their
source and destination scans still skip files already complete. Deleting or
changing a destination file affects the next run just as it does with rsync.

Only when repeated destination metadata lookups are themselves too expensive
should you opt in to a checkpoint:

```sh
pcp -a --checkpoint ./copy.state huge-tree/ host:huge-tree/
# after an interruption, run the identical command again
```

The mode-0600 JSONL checkpoint identifies the canonical source, destination,
and copy semantics. It records regular files only after PCP established that
the destination was complete and, for transferred files, rechecked the source.
On retry, a record whose source fingerprint still matches (size, nanosecond
mtime, and requested mode/owner/group metadata) skips that destination lookup.
Everything else follows the normal quick check, partial hashing, and transfer
path. Unfinished individual files are never checkpoint-complete; their actual
`.pcp-partial` contents remain the resume state.

The checkpoint is flushed about once a second and persists after both failed
and successful runs until you remove or stop passing it. Losing its last
buffered records only causes repeated work; `--fsync` makes each flush and the
initial header durable. If an existing checkpoint has completed records but an
expected destination root is missing, PCP fails and asks you to remove the
checkpoint to restart. The checkpoint must be outside local source and
destination trees. `-n` reads and validates existing state but never creates or
changes it. `-c`, `--verify-only`, and `--rm` conflict with `--checkpoint`.
One checkpoint file may be used by only one running copy at a time.

A checkpoint is an explicit trust decision: PCP does not inspect a destination
file covered by a matching record. If another process deleted, replaced, or
modified that destination after it was recorded, a checkpointed retry will not
notice. Do not use a checkpoint when the destination may be independently
modified; omit the option and PCP remains history-independent. `--delete`
records what it removes in an active checkpoint, so a file the source drops
and later brings back is transferred again rather than assumed complete.

Concurrent ordinary copies can populate different paths in one tree. For a
path both are actively staging, PCP's processes coordinate through an advisory
lock on the sidecar: one copy reports that file as an error instead of letting
both writers mix bytes in one inode. If the staging periods do not overlap,
each publication is still an atomic whole-file rename and the later one wins.
`--inplace` deliberately gives up both staging and this isolation.

### Verification and consistency

Always:

- Every block carries an xxh3 hash checked on receipt (read side and write
  side); a mismatch aborts that file with an error (exit 23) rather than
  silently continuing — it indicates transport corruption, which is rare.
- After a file completes, the source is re-stat'ed. If its size or mtime
  changed during the transfer the file is redone (up to three attempts), then
  reported as an error.
- Unless `--inplace` was explicit, destination files appear atomically via
  rename, including new small files.
- Non-zero exit if anything failed.

On request:

- `--verify-only` hashes every file on both sides in parallel and reports
  `DIFFERS` / `MISSING`.
- `-c` does the block comparison for every file, not just ones that fail the
  quick check, and repairs what differs.

Not verified: directory and symlink metadata are set but not read back; a
source that changes *between* the final re-stat and the next block of another
file isn't noticed (same as rsync). Two chunks of one file are read at
different moments, so a file being written while copied may come out mixed —
the re-stat catches the common case, `--verify-only` afterwards catches the
rest.

Compared with rsync: ordinary writes use the same temporary-file plus atomic
rename model; `--inplace` explicitly gives that up. PCP's deterministic partial
also remains reusable without publishing it under the final name. The
change-during-transfer check is the same idea; `--delete` runs strictly after
the transfer (see below); hardlinks aren't implemented.

## Not implemented (on purpose, for now)

`RSYNC-COMPAT.md` tracks rsync compatibility in full: what matches, what
differs and why, what's missing, and the open issues. The short version:

- rsync filter rules (`--exclude`/`--include`/`--filter`); use `-i` (gitignore
  syntax) instead.
- `--link-dest`, `--backup`.
- `--delete-before`/`--delete-during` and `--force`. pcp deletes only after
  the transfer (`--delete-after`/`--delete-delay` are accepted as synonyms).
- Hardlinks (`-H`), ACLs and xattrs (`-A`/`-X`).
- rsync daemon mode / `rsync://`. pcp speaks its own protocol; it cannot talk
  to an rsync server.
- Rolling-checksum delta transfer (see Resume above).
- Preserving existing partial files from `rsync --partial`; only pcp's own
  `.name.pcp-partial` files are recognised. A *source* file with such a name
  is never copied (it's assumed to be pcp's leftover), though `--delete`
  still treats it as the source's and leaves a same-named destination file.

## When parallelism helps

- **ssh CPU**: one ssh process tops out at a few hundred MB/s of cipher/MAC
  work. N processes scale roughly linearly. Multiplexed channels over one
  connection wouldn't help — same TCP stream, same single encrypting process —
  so pcp passes `-o ControlMaster=no -o ControlPath=none` for its connections
  on purpose.
- **WAN**: several TCP flows beat one against per-flow window and loss limits.
- **High-latency filesystems** (NFS, FUSE, object-backed): many small files
  are latency-bound; parallel stat and I/O hide it. The scan is parallel too.
- **NVMe / RAID** on either side.
- **Not** a single spinning disk: parallel reads of one file there mean seeks.
  Use `-j 1` or a large `--min-split`.

## How many connections (`-j`)

Without `-j`, pcp tunes the number of workers while a copy runs instead of
guessing (`--rm` keeps a fixed 8, or 32 locally: removal is metadata-bound
and short). It starts with 8 over the network (32 when both ends are
local: threads are free, connections are not) and measures: progress (bytes,
plus a small credit per completed file so small-file trees count) is sampled
every 2.5 s, and a count has been *measured* only once two consecutive
samples agree within 10 % — so a burst that gets throttled, or a link still
ramping up, is waited out (up to 20 s) rather than credited to the last
change. Each measured count is compared with the previous one: it doubles
while a doubling gains at least a third of what linear scaling would (up to
64); when a doubling doesn't, it goes back to the last good count and
refines upward in 1.3× steps; when even that buys nothing it shrinks by 1.3×
as long as that costs less than 5 % (down to 2); then it holds. It never stops
watching: after every 6 measurements it probes one step down (kept if
throughput doesn't drop — this is what saves a spinning disk from seek
thrash) or one step up (the route or a shared NAS may have freed up), and a
direction that keeps failing is tried progressively less often. Surplus
workers are parked, not closed: they keep their connections and stop taking
work, handing back the rest of their range, so un-parking is instant.
Transfers shorter than a measurement or two just run with the starting
count. The progress line shows the current count (`13 conn`), and `--stats`
reports the path it took (`connections: auto: settled at 13 (path 8 -> 10 ->
13 -> 17 -> 13, peak 17)`).

Measured from a 1 Gbit box in Germany to a host in Japan (265 ms): over TCP
data connections it settles around 8–13 at line rate; over ssh data
connections (where each stream is capped by OpenSSH's 2 MB window) it
reaches line rate (~110 MB/s, where a fixed `-j 8` managed 44) about 30 s
after the connections are up.

`-j N` fixes the count and disables tuning. Use it when you know better (a
spinning disk that must not be read in parallel: `-j 1`), or to be polite on
a shared link.

## TCP data connections

ssh caps every stream at a few hundred MB/s of cipher CPU, and its 2 MB
per-channel flow-control window caps a stream at roughly `2 MB / RTT` on long
links (≈7 MB/s at 265 ms). So by default (unless `--no-tcp`) pcp keeps ssh for
authentication and control only and moves the data over separate TCP
connections: the remote opens a listener on a port from `--tcp-ports` (default
47600-47699), and the data connections are plain TCP sockets carrying
AES-256-GCM records keyed by a secret exchanged over the ssh session
(`--tcp-plain` skips the encryption on trusted networks; `--no-tcp` sends data over the ssh connection instead). If the port can't be
reached — a firewall, typically — pcp says so once and falls back to ssh data
connections, so the default is always safe.

The remote advertises every address it has (the one your ssh session arrived
on first, then private LAN, then public, then CGNAT/Tailscale); the client
adds the name it reached ssh through — the only address that works for a
host behind NAT or port forwarding — ahead of the overlay ones, tries them
all, and prefers the best that answers. If none answers it says so and uses
ssh (silenced by `-q`). When several NICs of
comparable speed are reachable (e.g. an 8-rail RoCE fabric), pcp spreads its
data connections across all of them (multipath) — it keeps only paths within
2x of the fastest, so it never drags a fast transfer down by mixing in a slow
link. Single-homed hosts and laptops use the one best path, unchanged. With ufw:

```sh
sudo ufw allow from REMOVED/24 to any port 47600:47699 proto tcp   # LAN peers
sudo ufw allow from 203.0.113.5   to any port 47600:47699 proto tcp   # a specific client
```

Remote→remote (`pcp hostA:src hostB:dst`) works the same way: the
orchestrator on hostA connects to hostB's listener.

## Defaults chosen for network filesystems

Small files are read and written in pipelined batches, but every non-`--inplace`
write still finishes with an atomic rename. When both ends are local, 32 workers
are used. This costs one rename per file on NFS, but avoids exposing incomplete
final-named files. `--inplace` is the explicit space/safety tradeoff.

## Ignoring paths (`-i`, `--ignore-from`)

pcp has one filter mechanism instead of rsync's include/exclude/filter rules:
every `-i PATTERN` is a line of a virtual `.gitignore` anchored at each source
root, and `--ignore-from FILE` splices in the lines of a file. Patterns from
both are applied in command-line order with gitignore semantics (last match
wins, `!` re-includes), so anything you'd write in a `.gitignore` works here:

```sh
pcp -a -i node_modules -i .git src/ host:dst/   # a name matches at any depth
pcp -a -i '*.o' -i /build src/ host:dst/         # glob; leading / anchors to the root
pcp -a -i 'logs/*' -i '!logs/keep/' src/ dst/    # everything in logs/ except keep/
pcp -a --ignore-from .gitignore -i '!dist/' repo/ host:repo/
pcp -a -i '*' -i '!*/' -i '!*.jpg' photos/ bak/  # copy only *.jpg
```

Rules of thumb (they're git's): `foo` matches a file or directory named `foo`
at any depth; `/foo` only at the source root; `foo/` only a directory; `*`
doesn't cross `/`, `**` does. An ignored directory is pruned, so nothing inside
it is transferred or even scanned — which is why "only `*.jpg`" needs the
`!*/` line to keep descending. Empty directories are copied like any other
(this is a filter on the walk, not git's notion of what's tracked). The source
root itself is never ignored; with several sources each is filtered from its
own root. `-n` previews exactly what a real run would send. `--rm` does not
take filters (it always removes the whole tree), so `-i` conflicts with it.

As in git, a `!` rule cannot re-include something whose parent directory is
ignored: `logs/**` prunes `logs/keep` itself, so `!logs/keep/**` after it has
nothing to act on. Ignore the siblings instead (`logs/*`, which does not cross
`/`) and re-include the directory (`!logs/keep/`), as above.

## Deleting extras (`--delete`)

`pcp -a --delete src/ host:dst/` makes `dst` look like `src`: after the
transfer, anything under a destination directory that the source doesn't
have is removed. The rules are simpler than rsync's, deliberately:

- **Scope.** Only inside directories the sources map onto: `pcp --delete a b
  dst/` cleans `dst/a` and `dst/b`, never `dst/c`. A single-file source deletes
  nothing.
- **Ignored means out of scope, on both sides.** The `-i` patterns are applied
  to the destination walk from the same roots, so an ignored path is neither
  copied nor deleted, and a directory that holds one is kept (`not deleting
  keep/: it holds ignored paths`, on stderr, not an error). `--delete-excluded`
  drops that protection: ignored paths on the destination are extras too.
- **Anything the source has is safe.** A file skipped by `-u`, `--existing`,
  `--ignore-existing`, `--max-size` or `--min-size` — or a symlink or special
  file skipped for lack of `-l`/`-D` — still exists in the source, so its
  destination copy is left alone, as in rsync. Such files are reported under
  `files excluded` in `--stats`.
- **After, not before.** Deletions run once every file has been transferred
  and only if the whole source scan succeeded: an unreadable source directory
  would otherwise look like one whose contents vanished (`source scan reported
  errors; skipping deletions`). An interrupted run therefore never deletes
  anything, and directory mtimes are set after the deletes.
- **pcp's own leftovers count as extras.** A stale `.name.pcp-partial` — one
  whose file is already up to date, or whose source is gone — is removed.
  The partial of a file that *failed* this run is kept: it is the resume state
  for the retry.
- `--max-delete N` refuses to delete anything — not the first N — when more
  than N deletions are planned, says so, and exits 25 (rsync's code for it).
- `-n --delete -v` lists every `deleting path` line a real run would print
  (a stale partial that the real run resumes from and renames away is the one
  thing `-n` lists that it won't delete separately). The summary reports
  `N deleted` / `N would be deleted`.

Deletion goes through the control connection in batches of 1000 (the
destination side unlinks each batch in parallel); it isn't spread over the
`-j` data connections like `--rm` is.

## Skipping by state and size

- `-u` / `--update`: a file whose destination copy has a newer mtime is left
  alone (regular files only).
- `--existing`: never create anything — files, symlinks, specials,
  directories, *or the destination itself* — that isn't already there;
  existing files are still updated. `--ignore-existing` is the mirror image: create what's
  missing, never touch what exists. Both apply to every non-directory entry.
- `--max-size` / `--min-size`: regular files outside the range are not
  transferred (`4K`, `100M`, `2G`; the same suffixes as `--block-size`).
  Directories and symlinks are unaffected.

All of these define the scope of the run, so `--verify-only` checks the files
the same command would transfer and nothing else.

## Copying a list (`--files-from`)

`pcp -a --files-from list.txt host:src/ dst/` copies only the paths named in
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
Blank lines are ignored, leading `/` or `./` and trailing `/` are stripped,
and `..` components or a line that names the root itself are rejected. A listed path that doesn't exist is an
error (exit 23) and the rest is still copied. `--files-from` can't be combined
with `-i`/`--ignore-from` or `--delete`; for a remote-to-remote copy it needs
`--relay` (the list is read on this machine).

## Parallel removal (`--rm`)

`pcp --rm [-j N] [-n] [-v] PATH...` removes trees the way pcp copies them:
a parallel scan, files unlinked in batches across N workers, directories
removed deepest-first with each level in parallel. Symlinks are removed, not
followed. Remote paths (`host:path`) work. It refuses `/`, `.` and `~`. On
NFS, where every unlink is a round trip, `-j32` removed 20,000 files in 2.5 s
versus 9.7 s for `rm -rf`; on a local SSD `rm -rf` is already fast and pcp is
no faster.

## Same-machine copies (copy_file_range)

When source and destination are on the same machine, pcp copies each file with
`copy_file_range(2)` instead of streaming bytes through userspace: the kernel
does a reflink or a straight in-kernel copy, and on NFS 4.2 the *server* copies
the file internally (no client round trip). Measured: a single 8 GB file
/raid→/raid at 24.8 GB/s vs 2.5 GB/s for `cp`; NFS→NFS at 3.3 GB/s vs 0.4.
Hashing is skipped on this path (there's no wire to corrupt it); `-c`, any
existing partial, and `--bwlimit` disable this shortcut. Existing partials and
larger bwlimited files use the hash-resumable streaming path. Small new
bwlimited files that fit in one paced transfer block retain the `PutSmall`
exception described above.

## NFS

Local↔NFS copies are a local→local pcp run (`pcp -a -j16 /raid/x /mnt/nfs/x`)
and benefit from the same parallelism: measured on a 20 Gbit NFSv4.2 mount,
reads of one 4 GB file 858 MiB/s with `-j8` vs ~400 MB/s for `cp`; 20,000
small files written in 28 s vs 72 s for `cp -r`. Writes of a *single* file
were capped at ~250 MB/s regardless of `-j`, while eight files written in
parallel reached ~650 MB/s: the per-file limit comes from the NFS client's one
TCP connection and per-inode write serialization. Mounting with
`nconnect=8` (NFS 4.1+; needs an unmount/mount, not a remount) is the usual
fix for that.

## Performance notes

- pcp asks ssh for `aes128-gcm@openssh.com` first (falling back to the usual
  ciphers). On x86 with AES-NI that is noticeably faster per stream than
  OpenSSH's default chacha20-poly1305.
- Each connection costs one ssh handshake (~0.3 s on a LAN, several seconds
  across continents). The control connections always come up first
  (everything waits on them; only then do data connections start), up to 32
  at a time, and if the
  server sheds one — sshd's `MaxStartups` (default 10) randomly rejects
  sessions beyond 10 being set up at once — pcp halves that number for the
  rest of the run and retries. On a server set up for pcp (`MaxStartups
  100`, see `scripts/server-setup.sh`) 32 sessions come up in one round.
  Auto-tuning starts at 8 and only opens more once they have been shown to
  pay.
- Direct remote→remote with a *forwarded* agent authenticates every session
  through your machine; over a slow link that dominates setup time. Keys on the
  source host avoid it.
- Measured on two 160-core hosts on a 20 Gbit LAN: a single ssh stream tops out
  around 450–550 MB/s; `pcp -j8` into tmpfs reached ~1.2–1.3 GiB/s (the raw
  multi-stream ssh ceiling), while writes to the destination's ext4 NVMe capped
  everything, rsync included, at ~600 MB/s. Check the disk before blaming the
  network.
- `PCP_DEBUG=1` prints connect times and where each worker and each remote
  server spent its time (blocked on reads, pipe writes, acks; waiting, handling).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Everything copied and verified |
| 23 | Finished, but some files failed (unreadable source, `DIFFERS`, changed during transfer …) — errors are on stderr |
| 25 | Finished, but `--max-delete` stopped the deletions |
| 1 | Fatal: bad arguments, couldn't connect, remote `pcp` missing, connection lost |
