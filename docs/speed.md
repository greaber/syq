# Speed

Start with the defaults. Syq copies files in parallel, splits large files
between workers, and adjusts connection count during the transfer. If a TCP
data port is reachable, it sends data through separate encrypted connections.
Otherwise, ordinary copies send their data over SSH. Small copies can stay
on the SSH control connection to avoid extra setup.

## Benchmarks

See the [published syq-bench results](https://greaber.github.io/syq-bench/)
for comparisons with rsync, cp, and other tools, including the workloads,
commands, and measured limitations. Use
[syq-bench on your own machines](https://greaber.github.io/syq-bench/reproduce.html)
to compare settings and track performance over time.

## Quick comparison

The [interactive benchmark](install.md#try-a-benchmark) gives you a small
comparison without installing a benchmark package. After downloading the
script, you can repeat the same choices explicitly:

```sh
bash try-benchmark.sh --yes --mode push --host server --workload both --size medium --rounds 3
bash try-benchmark.sh --yes --mode local --source-dir /data --dest-dir /mnt/nfs --workload small
```

Scratch parents must already exist. For SSH tests, `--dest-dir` is the remote
scratch parent, including when pulling; `--source-dir` is always the local
scratch parent. Budget roughly twice the selected data size locally and one
copy remotely. Sizes are quick (64 MiB and 8 MiB), medium (1 GiB and 32 MiB),
and large (8 GiB and 128 MiB), for the large-file and small-file workloads.

Data comes from a fixed AES-CTR byte stream, making it reproducible and
hard to compress. Every trial has an empty destination. The script rotates
tool order and reports each elapsed time and the mean for each tool. It uses
syq's defaults with permissions preserved, `rsync -rpt`, and local `cp -pR`.
These copy the same regular files and request permissions and modification
times; the tools still differ in compression, integrity checks, and filesystem
optimizations. Syq prints its transfer statistics.

Generation, a small syq helper warm-up, and POSIX `cksum` comparisons are
outside the timer. A failed command or content check stops the comparison.
Caches are not flushed, so this is a cache-friendly test rather than a cold
disk benchmark. Times include process startup and buffered writes, without
waiting for durable storage. Small tests can mostly measure startup costs;
local filesystem cloning can favor cp. Results do not predict every workload,
and syq may be slower. Use the full published benchmark methodology for more
controlled measurements.

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

SSH authenticates and controls remote copies. When reachable, encrypted TCP
carries file data on one port from `47600–47699`; change it with
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

By default, syq builds an updated file beside the old one, then replaces the
old file when the new version is complete. `--inplace` writes directly into
the destination file instead. This uses less disk space, but readers can see
a mixture of old and new contents while the copy runs. If interrupted, that
incomplete version stays at the final filename until you finish the copy.

`--no-compress` saves CPU at the cost of potentially sending more bytes; it
does not affect file contents or integrity checks.

Examples use native options. In rsync mode, syq-specific options have a
`--syq-` prefix, such as `--syq-connections` and `--syq-no-tcp`.
See [rsync extensions](rsync-compat.md#syq-extensions).
