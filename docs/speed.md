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

## Benchmark tuning

`syq cp` and `syq rsync` accept `--tuning-options` for controlled performance
experiments. It appears in `--help-all`, outside the common options. Set one
or both keys in a comma-separated value:

```sh
syq cp large-file --to server --as /scratch/benchmark-copy \
  --connections 1 --tuning-options request-size=1M,pipeline-depth=8 --stats
```

| Key | Default | Accepted values |
|---|---|---|
| `request-size` | Hash block size, normally 4 MiB | 512 bytes through 64 MiB; `K`, `M`, and `G` use powers of 1024 |
| `pipeline-depth` | 4 | 1 through 64 outstanding range requests per endpoint per worker |

Request size controls the maximum payload of an individual range read or write.
It does not change the blocks used to compare file contents, identify partial
files, or resume a copy. `--bwlimit` can lower the effective request size to keep
bursts small. With overrides, `--stats` or `-v` reports the effective request size,
pipeline depth, and hash block size. A final request or a range selected for
repair can be smaller than the effective request size.

Larger requests reduce overhead per byte. Deeper pipelines allow more work to
remain outstanding while replies travel back. Either can help a fast connection
with high latency, but both increase potential buffering; neither guarantees
higher throughput. In-process endpoints handle one request at a time. The
background response queue on each worker connection follows its pipeline depth.

These settings apply to range transfers. Small-file batches and same-machine
whole-file copying can bypass them. Use a large remote file and a fresh,
disposable destination for each comparison, and fix `--connections` (or
`--syq-connections` with `syq rsync`) to isolate the two settings. Leave
`--bwlimit` unset when measuring unrestricted throughput. Include capped runs
when evaluating burst behavior.

Overrides apply to this command, including any remote coordinator. They are
not saved. Copies using overrides neither read nor update the remembered
connection count; connection auto-tuning still runs unless you fix that count.
These are experimental controls whose keys and bounds may change between
releases. The default request size and pipeline depth are not automatically
tuned.

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
