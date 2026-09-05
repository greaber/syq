# Speed

Start with the defaults. Syq copies files in parallel, splits large files
between workers, and adjusts connection count during the transfer. Over SSH,
it normally sends data through separate encrypted TCP connections.

## Measurements so far

These are development-machine measurements, not a controlled benchmark suite.
Most comparisons are against `cp`, not rsync. Measure your workload with
[syq-bench](https://github.com/greaber/syq-bench).

| Workload | syq | Comparison |
|---|---|---|
| 20,000 small files written to NFS | 28 s | `cp -r`: 72 s |
| 20,000 files removed from NFS, 32 workers | 2.5 s | `rm -rf`: 9.7 s |
| One 8 GB file, same-machine NFS server-side copy | 3.3 GB/s | `cp`: 0.4 GB/s |
| One 4 GiB file, local disk to asynchronous NFS | 9.93 s median | `cp`: 10.94 s median |
| Germany–Japan, 1 Gbit link, 265 ms RTT, TCP | Line rate | |
| Same route using SSH for data | About 110 MB/s with tuning | Fixed eight workers: 44 MB/s |

Methods, additional measurements, and the measured cost of path safety are in
[the performance note](https://github.com/greaber/syq/blob/master/design/performance.md).

## When rsync or cp is faster

- **Tiny jobs:** setup can cost more than the copy. [`syq persist on`](install.md#keep-connections-open) avoids
  repeated logins.
- **One spinning disk:** parallel reads can cause extra seeks. Try
  `--connections 1`.
- **Shifted file contents:** rsync can reuse data after an insertion changes
  byte offsets. Syq's fixed-block resume resends the shifted tail.
- **Storage-limited jobs:** extra network capacity cannot make a full-speed
  disk write faster. Check disk and CPU use at both ends.

## Diagnose a slow copy

```sh
syq cp -vv --stats data --to server --into /backup
```

`-vv` shows helper selection, reachable addresses, the chosen transport, and
initial parallelism. `--stats` shows totals, connection count, and TCP
statistics where available. `SYQ_DEBUG=1` adds engineering timings for a
detailed investigation.

| Symptom | Try |
|---|---|
| Data falls back to SSH | Check [TCP reachability](server-tuning.md#make-tcp-reachable) |
| Many short commands spend time logging in | `syq persist on` |
| A spinning disk is busy but throughput is poor | `--connections 1` |
| CPU is saturated on a fast link | Compare with `--no-compress` |
| A long-distance path suffers loss | A scoped [congestion-control comparison](server-tuning.md#test-congestion-control) |
| You need to leave bandwidth for other users | `--bwlimit RATE` |

Compare the same workload and direction, resetting only a disposable test
destination between runs. Otherwise a second copy may just measure skipping
already copied files.

## How many connections

Without `--connections`, syq adjusts parallelism automatically. Successful
remote copies can remember a useful count for that path; local copies,
including mounted NFS paths, do not use the tuning cache.

`-j N` / `--connections N` fixes the count and disables tuning. Use
`--bwlimit` to cap bandwidth rather than trying to control it indirectly
through worker count. Short copies may finish before tuning has enough data.

## TCP data connections

SSH authenticates and controls remote copies. File data normally uses
encrypted TCP on one port from `47600–47699`; change it with
`--tcp-ports LO-HI`. Syq discovers reachable IPv4 and IPv6 addresses and can
use multiple network interfaces.

If no TCP route is reachable, it reports `data over ssh`. Use `-vv` for
the connection details. **The restricted
remote-to-remote receiver requires encrypted TCP and fails instead.**

`--no-tcp` selects SSH data transport. `--tcp-plain` removes data encryption
and authentication and should be used only on a trusted network. Neither
option works with the restricted receiver.

On Linux, `--tcp-congestion ALGO` chooses an available algorithm for syq's
TCP sockets on both ends, without changing host defaults. Unsupported choices
fail the copy; the restricted receiver refuses this option.

## Local copies and NFS

Same-machine Linux copies can use kernel or NFS server-side copying. When
that is unavailable, syq can still benefit from parallel file operations.
It automatically uses a sequential destination writer for eligible local-disk
to asynchronous-NFS copies; you usually need no special flags.

```sh
syq cp /raid/data --into /mnt/nfs/backup
```

NFS mount tuning, such as `nconnect`, belongs to the host's storage setup.
Benchmark before changing it; server-side copying and ordinary read/write
traffic have different limits.

## Options that change the tradeoff

`--inplace` saves the space for a second file but exposes incomplete updates
to readers and after interruption. Keep the default unless that tradeoff is
necessary. `--no-compress` saves CPU at the cost of potentially sending more
bytes; it does not affect file contents or integrity checks.

Examples use native options. In rsync mode, syq-specific options have a
`--syq-` prefix, such as `--syq-connections` and `--syq-no-tcp`.
See [rsync extensions](rsync-compat.md#syq-extensions).
