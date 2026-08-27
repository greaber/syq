# pcp — parallel copy with an rsync-shaped interface

**Status:** implemented and in use; see README.md for the current, authoritative
behavior. This document is the original design and its rationale — where it and
the code disagree, the code (and README) win. Since it was written the data
plane moved to TCP-by-default (ssh for auth), gitignore-style `--ignore`
replaced the planned `--exclude` globs, and `--rm`, `--detach`/`--follow`, and a
cross-job resume journal + destination marker were added. Still not built:
`--bwlimit`, `--delete`.

## Goal

An rsync-like tool for the common case — "upload this, download that, copy
this from server A to server B" — that:

1. uses **multiple connections** (file-level and chunk-level parallelism),
2. has a **progress meter that doesn't lie**,
3. **resumes** without redoing work and can **verify** a copy completed,
4. supports the handful of rsync options people actually use (`-avz`).

Non-goals for v1: rsync's include/exclude/filter *rule language* (pcp instead
has one gitignore-style `--ignore`, see README), `--delete`, `--link-dest`,
hardlinks (`-H`), ACLs/xattrs, rsync-daemon compatibility, rsync's
shift-tolerant rolling-checksum delta.

## Why rsync can't do this

rsync is one generator→sender→receiver pipeline over one byte stream. The
protocol is stateful and sequential; its delta algorithm is per-file. Its
consistency guarantees are modest and don't preclude parallelism:

- Destination atomicity: temp file `.<name>.XXXXXX` in the target dir, then
  `rename()`. Note this evaporates with `--partial`/`-P`, which keeps partial
  data under the *final* name.
- Source changed during transfer: whole-file checksum mismatch → retry once →
  warn.

We keep atomicity (and keep it even for partials), match the changed-source
check, and drop nothing else people rely on.

## Where parallelism helps

| Bottleneck | Helps? |
|---|---|
| ssh cipher/MAC CPU (~100–300 MB/s per process) | Yes — N independent ssh **processes**. Multiplexed channels over one connection (ControlMaster) do **not** help; data connections must opt out of it. |
| WAN per-flow TCP limits | Yes |
| Per-file latency on NFS / network FS | Yes — also parallelize the scan |
| NVMe / RAID | Yes |
| Single spinning disk | No; chunk-parallel reads of one file hurt. Thresholds are tunable. |

Local→local (esp. NFS) is a first-class mode.

## CLI

```
pcp [OPTIONS] SRC... DEST
```

Path semantics identical to rsync: `[user@]host:path`, trailing-slash rule
("copy contents" vs "copy the directory"), `~` expansion on the remote.

v1 options:

| Option | Meaning |
|---|---|
| `-a` | `-rlptgoD`: recursive, symlinks as symlinks, perms, mtimes, group, owner, devices/specials. Owner/group best-effort when not root (as rsync). |
| `-r -l -p -t -g -o -D` | individual components |
| `-v` | list files as they complete |
| `-z` | zstd compression inside our protocol (not `ssh -C`) |
| `-n` / `--dry-run` | scan and report, transfer nothing |
| `-j N` / `--connections N` | data connections (default 8) |
| `--block-size SIZE` | transfer/hash block size (default 4M) |
| `--min-split SIZE` | don't split an in-flight file with less than this left (default 32M) |
| `--progress` / `--no-progress` | default: on when stderr is a TTY |
| `--progress-json` | machine-readable progress on stderr |
| `--stats` | summary at end |
| `-c` / `--checksum` | compare every file block by block, not just size+mtime; repair mismatches |
| `--verify-only` | hash every file on both sides and report differences; transfer nothing |
| `--inplace` / `--atomic` | write in place / force partial+rename for every file |
| `--fsync` | fsync each file and its parent dir around the rename |
| `-e CMD` | remote shell command (default `ssh`) |
| `--no-tcp` / `--tcp-plain` / `--tcp-ports LO-HI` | ssh-only data / unencrypted TCP / listener port range |
| `-i` / `--ignore-from` | gitignore-style path filtering |
| `--rm` | parallel recursive removal |
| `--relay` / `--detach` / `--follow` | remote→remote routing, detached run, log follow |
| `--no-resume` | disable the destination marker and completion journal |
| `--bootstrap` | copy the pcp binary to the remote if missing |
| `-h`, `--version` | |

Data connections default to encrypted TCP (see below); `--no-tcp` keeps them on
ssh. Later: `--bwlimit`, `--delete`, `-u`, `--files-from`.

## Architecture

```
            control conn (1)              data conns (N)
 local  ───────────────────────► remote   ◄────────────► remote
 orchestrator   scan/diff/finalize agent   read/write ranges   workers
```

### Endpoints

The orchestrator talks to *endpoints* through one trait:

```
trait Endpoint {
    scan(root) -> stream<Entry>          // path, type, size, mtime, mode, uid, gid, link target
    open_data_conns(n) -> Vec<DataConn>
    chunk_hashes(path, chunk_size) -> Vec<Hash>
    prepare(path, size) -> PartialHandle // fallocate .<name>.pcp-partial
    finalize(path, meta)                 // fsync, chmod/chown/utimens, rename
    stat(path)                           // post-transfer re-check
    mkdir / symlink / mknod / set_dir_times
}
```

Implementations: `Local`, `Ssh` (spawns `ssh host pcp --server`). Everything —
push, pull, local→local, remote→remote relay — is just a choice of two
endpoints. That is what makes relay mode free.

### Control connection

- Exchanges protocol version and capabilities.
- Both sides scan in parallel (`jwalk`, breadth-first, N threads); remote
  streams entries back. Scan-first is the default so the progress total is
  exact; `--stream` (later) starts transfers during the scan.
- Diff: quick-check (size + mtime + type equal) → skip. Otherwise the file
  goes on the work list. Directories/symlinks/specials are metadata-only
  work items.
- Owns all finalization and metadata.

### Data connections

Dumb by design. Wire ops:

```
ReadRange  { path, off, len }       -> bytes (+ hash)
WriteRange { partial_id, off, len, bytes, hash }
HashRange  { path, off, len }       -> hash
```

The control connection is the only thing that creates or renames partials; the
data connections carry only range reads/writes and several of them `pwrite`
into the same partial.

By default the data connections are **separate TCP sockets** carrying
AES-256-GCM records, keyed by a secret exchanged over the ssh control session:
the remote opens a listener (port range `--tcp-ports`) and advertises its
addresses, and when several comparable-speed NICs are reachable (e.g. an 8-rail
RoCE fabric) pcp spreads connections across them (multipath). This sidesteps
ssh's per-channel flow-control window and per-process cipher ceiling. If the
port can't be reached pcp falls back to ssh data connections; `--no-tcp` forces
that, and `--tcp-plain` drops the encryption on trusted networks. Under ssh
fallback the data connections are separate `ssh` processes started with
`-o ControlMaster=no -o ControlPath=none` so each gets its own TCP flow and
cipher CPU.

### Work queue and scheduling

Work item = `(file, offset, len)`. Files are split into `--block-size` ranges;
a file is not split further once less than `--min-split` remains.
Order: largest first (avoids the long tail). Idle workers **steal** the back
half of the remaining range of an in-flight file, so the tail of "one giant
file at the end" degrades to N-way parallel automatically without
pre-deciding chunk counts.

### Write path (receiver)

1. `fallocate` `.<name>.pcp-partial` in the target directory to the final size
   (large files and existing-file updates). Small new files — up to the block
   size — are instead written straight to their final path with no preallocation
   and no rename, a measurable NFS win; `--atomic` forces the partial+rename path
   for every file.
2. Workers `pwrite` chunks; each chunk's hash is checked on arrival, mismatch
   → re-fetch.
3. All chunks done → `fsync` → set mode/owner/mtime → `rename` over target.
4. Re-stat the source; if size or mtime changed during transfer, redo the file.
5. Directory mtimes set last, deepest-first (writes into a dir bump its
   mtime).

The final name is never occupied by an incomplete file. `--inplace` skips the
partial for the no-space-for-a-copy case.

### Block-level skip (our "delta")

For a file that fails quick-check, both sides hash each block (xxh3, the same
algorithm used for `-c` verification); equal blocks are skipped. Catches appends and in-place
modification (VM images, DBs, logs); misses byte insertions that shift the
rest of the file, which rsync's rolling checksum would catch. Accepted
trade-off — the normal case is fresh uploads/downloads, not syncing edits.

### Resume

Two levels. *Within a file* there is no state file — the partial is the state:

- Completed files: quick-check skip.
- Partial found at `.<name>.pcp-partial`: hash each chunk locally, compare to
  source chunk hashes, fetch only mismatches. The partial *is* the state, so it
  can't disagree with reality.
- Ctrl-C is always safe.

*Across a whole job* pcp keeps a completion journal (JSONL, keyed to the
source→destination paths and metadata-affecting flags) under
`$XDG_STATE_HOME/pcp`, and drops a marker file on the destination filesystem
while a run is in progress. The marker is a cross-machine interlock — a second
run targeting the same destination sees a foreign session and aborts rather than
interleaving writes; it is removed on success and left behind on interruption so
the next identical run resumes, skipping journaled files without re-stat'ing the
destination. The journal is authoritative (external destination edits need `-c`
or `--no-resume`), and marker-creation failure degrades to a no-resume run
rather than failing the copy. `--no-resume` disables both. See RESUME-DESIGN.md.

### Verify

- Built in: every chunk hashed on both ends; post-transfer source re-stat;
  non-zero exit if anything failed to verify.
- `-c` / `--checksum`: block-compare every file on both sides and repair
  mismatches, not just the ones that fail the quick check. `--verify-only`
  reports differences without transferring — the "did it finish?" check.

### Remote → remote

- **Relay** (`--relay`, v1): orchestrator local, data A→local→B. Halves
  bandwidth, uses your uplink, but always works. Zero extra code.
- **Direct** (default when possible): run the orchestrator *on A*
  (`ssh -A A pcp src B:dst`), reducing to push mode. Needs A→B reachability
  and credentials (agent forwarding covers the usual case). Falls back to relay
  if A can't reach B. `--detach` runs it detached on A so it survives losing the
  launching ssh session; `--follow HOST:LOG` reattaches to its progress log.

### Compression

`-z` = per-frame zstd in our protocol. Skip compression on chunks that don't
compress (sample first 64 KB, or just check the ratio of the first frame per
file).

### Progress

After the scan the totals are exact. Show:

- bytes transferred / total **and, separately, bytes skipped as unchanged** —
  conflating these is why rsync's `--info=progress2` jumps around;
- files done / total, EWMA throughput, ETA;
- per-connection activity; in-flight files with chunk completion.

Multi-line meter on a TTY, single updating line otherwise,
`--progress-json` for scripts, rsync-style `--stats` at the end.

### Bootstrap

Single static binary — built glibc-static
(`RUSTFLAGS="-C target-feature=+crt-static"` on `x86_64-unknown-linux-gnu`; no
`musl-gcc` needed for the bundled zstd), macOS built natively. `--bootstrap`: if
`pcp` isn't on the remote's PATH, copy this binary to `~/.local/bin/pcp` over
the control ssh and retry (the remote must match the local architecture).
Version mismatch is detected at handshake.

## Rust building blocks

As built (no async runtime — plain threads, not `tokio`): `clap`, `jwalk` +
`ignore` (parallel walk, gitignore matching), `xxhash-rust` (xxh3, used for both
transfer and verify — no `blake3`), `zstd`, `serde` + `postcard` (wire framing),
`aes-gcm` + `getrandom` (TCP record layer), `serde_json` + `base64` (resume
journal), `shell-words`, and `libc` directly (`fallocate`, `pwrite`, `fchown`,
`utimensat`, `mknod`, `copy_file_range`) — no `nix`. Progress is a hand-rolled
renderer, not `indicatif`. Target `x86_64-unknown-linux-gnu` (crt-static) plus
native macOS.

## Milestones

1. **Skeleton** — CLI, endpoint trait, `pcp --server` handshake, protocol
   framing, parallel scan both sides, diff → work list. Local→local, push,
   pull; whole files; one connection.
2. **Parallel + progress** — N connections, work queue, largest-first,
   partial→rename, progress meter, `--stats`.
3. **Chunks, resume, verify** — splitting, work stealing, per-block hashing,
   resume from partials, `-c`/`--verify-only`.
4. **Relay remote→remote**, `-z`, `--bootstrap`, `--dry-run`.
5. **Direct remote→remote**, `--bwlimit`, `--exclude` globs, `--delete`.

All five milestones are implemented, plus TCP data connections, `--ignore`,
`--rm`, `--detach`/`--follow`, and cross-job resume.

## Resolved questions

- Name collision with Performance Co-Pilot's `pcp`: lived with; the binary is
  `pcp`.
- Default `-j`: 8 over ssh, `min(cpu, 32)` when everything is local.
- `--progress` on by default when stderr is a TTY: yes.
