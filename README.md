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
processes), then fsynced, given its metadata, and `rename`d over the target.
The final name is never occupied by an incomplete file. `--inplace` skips the
partial for when there is no room for a second copy.

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

- Every block carries an xxh3 hash checked on receipt; a mismatch is re-sent.
- After a file completes, the source is re-stat'ed. If its size or mtime
  changed during the transfer the file is redone (up to three attempts), then
  reported as an error.
- Destination files appear atomically via rename.
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

Compared with rsync: the atomic rename guarantee is the same (and, unlike
`rsync -P`, still holds for partial files); the change-during-transfer check
is the same idea; deletes and hardlinks aren't implemented, so there is no
ordering question for them.

## Not implemented (on purpose, for now)

- rsync filter rules (`--exclude`/`--include`/`--filter`). A gitignore-style
  `--exclude` may come later.
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
