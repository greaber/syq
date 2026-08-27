# pcp

`pcp` is a parallel file copier with an rsync-shaped command line. It scans
source and destination, works out what differs, and moves the data over
**N independent ssh connections at once** — splitting large files into ranges
that idle workers steal from each other, so a single huge file at the end of
a transfer still uses every connection. Throughput is typically several times
that of a single ssh stream. It also has a progress meter that separates
transferred bytes from unchanged ones, resumes interrupted transfers from
partial files without redoing finished work, and can verify that a copy is
complete.

## Install

```sh
cargo build --release          # binary at target/release/pcp
cargo install --path .         # or: put it on your PATH
```

The remote side needs `pcp` too, just as rsync needs `rsync` there. It is
started as `pcp --server` over the remote shell. Options:

- Install it on the remote host and make sure it is on the `PATH` of a
  non-interactive ssh shell, or pass `--pcp-path /path/to/pcp`.
- `--bootstrap`: if starting the remote `pcp` fails, copy *this* binary to
  `~/.local/bin/pcp` on the remote host and retry. The default remote command
  falls back to `~/.local/bin/pcp` automatically. The remote must be the same
  architecture as the local binary.
- **macOS (Apple Silicon / Intel):** build natively on the Mac with
  `cargo build --release` (needs the Xcode command-line tools, `xcode-select
  --install`, for the bundled zstd C library). The tool is otherwise pure Rust
  and uses only POSIX calls; Linux-only optimizations (`fallocate`,
  glibc `mallopt`) are compiled out automatically. copy_file_range's local
  fast path is Linux-only; on macOS same-machine copies use the normal path.
- For portability across distributions (e.g. to `--bootstrap` onto hosts with
  an older glibc), build a static binary:
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
pcp -a -e 'ssh -p 2222 -i ~/.ssh/other' src host:dst
pcp -a --dry-run -v src host:dst              # show what would be copied
pcp -ac src host:dst                          # skip the quick check; compare blocks, repair differences
pcp -a --verify-only src host:dst             # compare only; transfer nothing
pcp -a --bootstrap src newhost:dst            # install pcp on newhost first if needed
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
| `-j N`, `--connections N` | Parallel data connections (default 8) |
| `--block-size SIZE` | Transfer and hash block size (default 4M) |
| `--min-split SIZE` | Don't split an in-flight file with less than this left (default 32M) |
| `--progress` / `--no-progress` | Progress meter (default on when stderr is a terminal) |
| `-P` | `--progress --partial` (partials are always kept; accepted for compatibility) |
| `--progress-json` | One JSON line per second on stderr |
| `--stats` | Summary counts at the end |
| `-c`, `--checksum` | Compare every file block by block instead of size+mtime; repair mismatches |
| `--verify-only` | Hash every file on both sides and report differences; write nothing |
| `--inplace` | Write directly into destination files (no partial + rename) |
| `-e CMD`, `--rsh CMD` | Remote shell command (default `ssh`) |
| `--pcp-path PATH` | Location of `pcp` on the remote host |
| `--bootstrap` | Copy this binary to the remote's `~/.local/bin/pcp` if starting it fails |
| `--tcp` | Data over TCP sockets (AES-256-GCM) after ssh auth; falls back to ssh if unreachable |
| `--tcp-plain` | Like `--tcp` without encryption (trusted networks only) |
| `--tcp-ports LO-HI` | Port range the remote listens on for `--tcp` (default 47600-47699) |
| `-i PATTERN`, `--ignore PATTERN` | Skip paths matching a gitignore-style pattern (repeatable; see below) |
| `--ignore-from FILE` | Read ignore patterns from a file (repeatable, stacks with `-i`) |
| `--rm` | Remove the given paths recursively and in parallel (see below) |
| `--relay` | Remote-to-remote: route data through this machine instead of running on the source host |
| `-h` | Accepted for compatibility; sizes are always human-readable. Use `--help` for help |

### Remote-to-remote

`pcp hostA:src hostB:dst` starts the orchestrator *on hostA* over `ssh -A`
(agent forwarding), which then pushes to hostB with N connections, so data
flows A → B directly. That needs pcp on both hosts and hostA able to ssh to
hostB (with your forwarded agent, or its own keys). Progress and `-v` output
are streamed back. If hostA can't reach hostB, `--relay` keeps the orchestrator
here and routes every byte A → you → B — always works, at half the bandwidth.

## Path semantics

Identical to rsync:

- `pcp -a src dest` copies the directory itself → `dest/src`. `dest` is
  created if missing.
- `pcp -a src/ dest` copies the *contents* of `src` into `dest`. `src/.` and
  `.` behave the same way.
- A single file source goes to `dest/file` if `dest` is an existing directory,
  otherwise `dest` is the new filename.
- Several sources require (or create) a directory destination.
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
disturb them.

## How it works

One control connection per endpoint does the scan (a parallel walk on each
side, streamed in batches), the diff, directory creation and metadata.
`-j N` data connections — separate `ssh` processes, each its own TCP flow and
cipher process — carry only "read range" / "write range" requests. Files go
onto a largest-first queue; when a worker runs dry it steals the back half of
the remaining range of whichever file has the most left, so the tail of a
transfer stays parallel without pre-deciding chunk counts.

On the receiving side each file is written into `.name.pcp-partial` in its
directory (preallocated with `fallocate`, written with `pwrite` from several
processes), given its metadata, and `rename`d over the target. By default pcp
does not `fsync` each file (the rename still orders correctly, and per-file
fsync is costly on NFS); pass `--fsync` to force each file durable before the
rename for crash safety.
Large files and existing-file updates go through this partial + rename, so their
final name is never occupied by an incomplete file. **Small new files (up to the
block size) are the exception**: they are written straight to their final path
for speed (no rename), so a concurrent reader can observe one partially written,
and an aborted run leaves an incomplete final-named file until you rerun (a
rerun re-transfers it, since without preallocation it is detectably short — it
is never *silently* skipped as complete). Pass `--atomic` when a consumer may
read the destination while pcp is writing, to make every file appear atomically.
`--inplace` writes every file in place (e.g. to update a large file without room
for a second copy).

Local → local runs the same machinery in-process with N threads, which helps
on NFS and NVMe.

### Resume

There is no state file. On restart:

- Files whose size and mtime already match are skipped (the rsync quick check).
- If a `.name.pcp-partial` exists, both sides hash it and the source in
  `--block-size` blocks and only the mismatching blocks are sent. The partial
  *is* the state, so it can't disagree with reality.
- If the destination file exists but differs, its blocks are hashed against
  the source too; if all match only metadata is fixed, otherwise the matching
  blocks are copied locally into a new partial and the rest transferred.

Ctrl-C is therefore always safe: kill it, rerun the same command.

This block-level skip catches appends and in-place modifications (VM images,
databases, logs). It does **not** catch a byte inserted near the start of a
file, which rsync's rolling checksum would — for pcp's intended use (fresh
uploads and downloads) that trade was made deliberately.

### Verification and consistency

Always:

- Every block carries an xxh3 hash checked on receipt (read side and write
  side); a mismatch aborts that file with an error (exit 23) rather than
  silently continuing — it indicates transport corruption, which is rare.
- After a file completes, the source is re-stat'ed. If its size or mtime
  changed during the transfer the file is redone (up to three attempts), then
  reported as an error.
- Destination files appear atomically via rename — **except small new files**
  (up to the block size), which are written straight to their final path for
  speed; pass `--atomic` to make every file appear atomically.
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

Compared with rsync: the atomic rename guarantee is the same for large and
existing files (and, unlike `rsync -P`, still holds for partial files), but
small new files are written in place by default for NFS speed — use `--atomic`
to match rsync's every-file atomicity; the change-during-transfer check
is the same idea; deletes and hardlinks aren't implemented, so there is no
ordering question for them.

## Not implemented (on purpose, for now)

- rsync filter rules (`--exclude`/`--include`/`--filter`); use `-i` (gitignore
  syntax) instead.
- `--delete`, `--link-dest`, `-u`/`--update`, `--files-from`, `--bwlimit`.
- Hardlinks (`-H`), ACLs and xattrs (`-A`/`-X`).
- rsync daemon mode / `rsync://`. pcp speaks its own protocol; it cannot talk
  to an rsync server.
- Rolling-checksum delta transfer (see Resume above).
- Preserving existing partial files from `rsync --partial`; only pcp's own
  `.name.pcp-partial` files are recognised.

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

## TCP data connections (`--tcp`)

ssh caps every stream at a few hundred MB/s of cipher CPU, and its 2 MB
per-channel flow-control window caps a stream at roughly `2 MB / RTT` on long
links (≈7 MB/s at 265 ms). So by default (unless `--no-tcp`) pcp keeps ssh for
authentication and control only and moves the data over separate TCP
connections: the remote opens a listener on a port from `--tcp-ports` (default
47600-47699), and the data connections are plain TCP sockets carrying
AES-256-GCM records keyed by a secret exchanged over the ssh session
(`--tcp-plain` skips the encryption on trusted networks; `--no-tcp` sends data over the ssh connection instead). If the port can't be
reached — a firewall, typically — pcp says so once and falls back to ssh data
connections, so `--tcp` is always safe to pass.

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

Remote→remote (`pcp --tcp hostA:src hostB:dst`) works the same way: the
orchestrator on hostA connects to hostB's listener.

## Defaults chosen for network filesystems

New files are written in place (created with their final mode, no separate
chmod, no rename); existing files are replaced through a partial file and an
atomic rename unless `--inplace`. `--atomic` forces the partial+rename path
for every file (rsync semantics) when readers might open files mid-transfer. When both ends are local, 32 workers are
used. On NFS these choices are the difference between ~300 and ~850 files/s.

## Ignoring paths (`-i`, `--ignore-from`)

pcp has one filter mechanism instead of rsync's include/exclude/filter rules:
every `-i PATTERN` is a line of a virtual `.gitignore` anchored at each source
root, and `--ignore-from FILE` splices in the lines of a file. Patterns from
both are applied in command-line order with gitignore semantics (last match
wins, `!` re-includes), so anything you'd write in a `.gitignore` works here:

```sh
pcp -a -i node_modules -i .git src/ host:dst/   # a name matches at any depth
pcp -a -i '*.o' -i /build src/ host:dst/         # glob; leading / anchors to the root
pcp -a -i 'logs/**' -i '!logs/keep/**' src/ dst/ # re-include a subtree
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
own root. `-n` previews exactly what a real run would send.

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
Hashing is skipped on this path (there's no wire to corrupt it); `-c` and any
existing partial fall back to the streaming path, which keeps hash-based resume.

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
  across continents), and sshd's `MaxStartups` (default 10) randomly rejects
  sessions if too many are being set up at once, so pcp limits in-flight
  connects and retries. For short transfers over long links, `-j 4` may beat
  `-j 16`.
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
| 1 | Fatal: bad arguments, couldn't connect, remote `pcp` missing, connection lost |
