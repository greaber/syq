# pcp — parallel copy with an rsync-shaped interface

**Status:** implemented through milestone 5's direct remote→remote mode; see README.md for usage. `--exclude` globs became `-i`/`--ignore-from` (gitignore syntax); `--delete`, `-u`, `--existing`/`--ignore-existing`, `--max-size`/`--min-size` and `--files-from` are in. Remaining from the plan: `--bwlimit`.

## Goal

An rsync-like tool for the common case — "upload this, download that, copy
this from server A to server B" — that:

1. uses **multiple connections** (file-level and chunk-level parallelism),
2. has a **progress meter that doesn't lie**,
3. **resumes** without redoing work and can **verify** a copy completed,
4. supports the handful of rsync options people actually use (`-avz`).

Non-goals for v1: rsync filter rules, `--delete`, `--link-dest`, hardlinks
(`-H`), ACLs/xattrs, rsync-daemon compatibility, rsync's shift-tolerant
rolling-checksum delta.

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
| `--chunk-size SIZE` | split threshold and chunk size (default 64M) |
| `--progress` / `--no-progress` | default: on when stdout is a TTY |
| `--progress-json` | machine-readable progress on stderr |
| `--stats` | summary at end |
| `-c` / `--verify` | hash-compare every file on both sides; with `--verify-only`, transfer nothing |
| `-e CMD` | remote shell command (default `ssh`) |
| `--relay` | force remote→remote via the local machine |
| `--bootstrap` | copy the pcp binary to the remote if missing |
| `--inplace` | write directly to target instead of partial+rename |
| `-h`, `--version` | |

Later: `--bwlimit`. Done since: `-i` (gitignore-style, not rsync rules),
`--delete`, `-u`, `--files-from` — see README.md.

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

Remote data workers are independent `pcp --server --data` processes; several
processes `pwrite` into the same preallocated partial file. The control
connection is the only thing that creates or renames partials.

Data connections are separate `ssh` processes started with
`-o ControlMaster=no -o ControlPath=none` so they get their own TCP flow and
cipher CPU.

### Work queue and scheduling

Work item = `(file, offset, len)`. Files above `--chunk-size` are split.
Order: largest first (avoids the long tail). Idle workers **steal** the back
half of the remaining range of an in-flight file, so the tail of "one giant
file at the end" degrades to N-way parallel automatically without
pre-deciding chunk counts.

### Write path (receiver)

1. `fallocate` `.<name>.pcp-partial` in the target directory to the final size.
2. Workers `pwrite` chunks; each chunk's hash is checked on arrival, mismatch
   → re-fetch.
3. All chunks done → `fsync` → set mode/owner/mtime → `rename` over target.
4. Re-stat the source; if size or mtime changed during transfer, redo the file.
5. Directory mtimes set last, deepest-first (writes into a dir bump its
   mtime).

The final name is never occupied by an incomplete file. `--inplace` skips the
partial for the no-space-for-a-copy case.

### Block-level skip (our "delta")

For a file that fails quick-check, both sides hash each chunk (xxh3; blake3
under `--verify`); equal chunks are skipped. Catches appends and in-place
modification (VM images, DBs, logs); misses byte insertions that shift the
rest of the file, which rsync's rolling checksum would catch. Accepted
trade-off — the normal case is fresh uploads/downloads, not syncing edits.

### Resume

Falls out of the above; there is no state file.

- Completed files: quick-check skip.
- Partial found at `.<name>.pcp-partial`: hash each chunk locally, compare to
  source chunk hashes, fetch only mismatches. The partial *is* the state, so
  it can't disagree with reality. (A completed-chunk bitmap is a possible
  later optimization; local sequential hashing is cheap next to network.)
- Ctrl-C is always safe.

### Verify

- Built in: every chunk hashed on both ends; post-transfer source re-stat;
  non-zero exit if anything failed to verify.
- `--verify` / `-c`: hash every file in parallel on both sides, report
  differences. `--verify-only` does this without transferring — the "did it
  finish?" check.

### Remote → remote

- **Relay** (`--relay`, v1): orchestrator local, data A→local→B. Halves
  bandwidth, uses your uplink, but always works. Zero extra code.
- **Direct** (v1.5, default when possible): run the orchestrator *on A*
  (`ssh -A A pcp src B:dst`), reducing to push mode. Needs A→B reachability
  and credentials (agent forwarding covers the usual case). Fall back to relay
  if A can't reach B.

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

Multi-line `indicatif` TUI on a TTY, single updating line otherwise,
`--progress-json` for scripts, rsync-style `--stats` at the end.

### Bootstrap

Single static binary (musl). `--bootstrap`: if `pcp` isn't on the remote's
PATH, copy this binary to `~/.local/bin/pcp` over the control ssh and retry.
Version mismatch is detected at handshake.

## Rust building blocks

`tokio` (I/O, ssh child processes), `clap`, `jwalk`, `xxhash-rust`, `blake3`,
`zstd`, `serde` + `postcard` (wire framing), `indicatif`, `nix`/`libc`
(`fallocate`, `pwrite`, `fchown`, `utimensat`, `mknod`). Target
`x86_64-unknown-linux-musl` (+ aarch64) for static binaries.

## Milestones

1. **Skeleton** — CLI, endpoint trait, `pcp --server` handshake, protocol
   framing, parallel scan both sides, diff → work list. Local→local, push,
   pull; whole files; one connection.
2. **Parallel + progress** — N connections, work queue, largest-first,
   partial→rename, progress meter, `--stats`.
3. **Chunks, resume, verify** — splitting, work stealing, per-chunk hashing,
   resume from partials, `--verify`.
4. **Relay remote→remote**, `-z`, `--bootstrap`, `--dry-run`.
5. **Direct remote→remote**, `--bwlimit`, `--exclude` globs, `--delete`.

## Open questions

- Name collision: Performance Co-Pilot ships a `pcp` binary on some distros.
  Live with it, or install as something else (`pcpy`, `prsync`)?
- Default `-j`: fixed 8, or derive from host CPU count?
- Should `--progress` be on by default even when rsync wouldn't (yes, when TTY)?
