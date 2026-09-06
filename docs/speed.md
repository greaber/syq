# Speed

Start with the defaults. Syq copies files in parallel, splits large files
between workers, and adjusts connection count during the transfer. If a TCP
data port is reachable, it sends data through separate encrypted connections.
Otherwise, ordinary copies send their data over SSH. Small copies can stay
on the SSH control connection to avoid extra setup. When pushing into an
existing directory, syq pipelines destination setup checks to reduce network
round trips. For eligible small-file trees in an empty destination, TCP workers
connect while destination planning finishes. These overlap setup work without
skipping destination checks.

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

The script needs Bash, rsync, OpenSSL and standard Unix utilities locally;
terminal runs also use Perl to keep SSH prompts interruptible. Remote tests
need SSH access and rsync on the other machine. Syq prepares a helper matching
your local build and shows installation progress when one is needed.
Use an SSH config alias for custom ports or IPv6. `--install` installs syq
locally if missing; `--help` lists the choices.

Scratch parents must already exist. For SSH tests, `--dest-dir` is the remote
scratch parent, including when pulling; `--source-dir` is always the local
scratch parent. Budget roughly twice the selected data size locally and one
copy remotely. Sizes are quick (64 MiB and 8 MiB), medium (1 GiB and 32 MiB),
and large (8 GiB and 128 MiB), for the large-file and small-file workloads.

Data comes from a fixed AES-CTR byte stream, making it reproducible and
hard to compress. Every trial has an empty, pre-created destination; interrupted trials are
never resumed. On Ctrl-C the script stops its local workers, moves remote
scratch out of the transfer path, and deletes its temporary data. If SSH
is unavailable, it reports the remote path for later cleanup. The script rotates
tool order and reports speeds in decimal MB/s (1 MB = 1,000,000 bytes):
each trial’s copied bytes divided by its elapsed time, followed by the mean,
minimum and maximum trial speeds. Higher is faster. It uses
syq's defaults with permissions preserved, `rsync -rpt`, and local `cp -pR`.
These copy the same regular files and request permissions and modification
times; the tools still differ in compression, integrity checks, and filesystem
optimizations. Syq prints its transfer statistics.

Generation, a single 14-byte syq setup copy, and POSIX `cksum` comparisons are
outside the timer. The setup copy prepares the helper and exercises transfer
setup; it is labeled separately and shows helper installation messages without a throughput result. A failed command or content check stops the comparison.
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

## Benchmark tuning

`syq cp` and `syq rsync` accept `--tuning-options` for controlled performance
experiments. It appears in `--help-all`, outside the common options. Supply
comma-separated `KEY=VALUE` pairs:

```sh
syq cp large-file --to server --as /scratch/benchmark-copy \
  --connections 1 -v \
  --tuning-options copy-path=ranges,request-size=1M,pipeline-depth=8
```

| Key | Default | Accepted values |
|---|---|---|
| `request-size` | Hash block size, normally 4 MiB | 512 bytes through 64 MiB |
| `pipeline-depth` | 4 | 1 through 64 outstanding range requests per endpoint per worker |
| `copy-path` | `auto` | `auto` or `ranges` |
| `batch-files` | 128 or 512, depending on transport and latency | 1 through 4096 files per worker batch |
| `batch-bytes` | 16 MiB | 512 bytes through 64 MiB per worker batch, including the first file |
| `split-min-size` | 32 MiB, at least two hash blocks | 1 byte through 1 GiB, raised to at least two hash blocks |
| `bw-pacing` | `125ms` when capped | `average`, or an integer interval from `1ms` through `10s`; requires a nonzero `--bwlimit` |

Sizes accept `K`, `M`, and `G`, using powers of 1024. Unknown keys, repeated
keys, and out-of-range values fail the command. Overrides apply to the remote
coordinator too. They are not saved, and these runs neither read nor update
the remembered connection count. Connection auto-tuning still runs unless you
fix `--connections` (`--syq-connections` with `syq rsync`). These are experimental
controls whose keys and bounds may change between releases.

Request size limits the payload of one range read or write. A final request or
a range selected for repair can be smaller. Larger requests reduce overhead
per byte; deeper pipelines allow more work to remain outstanding while replies
travel back. Both increase potential buffering. In-process endpoints handle
one request at a time; the response queue on worker connections follows the
pipeline depth. These settings do not change hash blocks or partial identities.

`copy-path=ranges` makes file contents use range requests, bypassing both
small-file batches and whole-file copying, including local kernel offload.
Matching data can still be skipped or reused. With `auto`, syq chooses the copy
method as usual. Explicit batch controls select worker batching instead of the
native small-copy shortcut. Files larger than the batch byte limit use another
copy path. File and byte limits are ceilings, and the scheduler can choose a
smaller batch to share work among workers. With `--bwlimit`, worker batches
contain at most one file. Batch controls cannot be combined with
`copy-path=ranges`.

For example, compare small-file batches with:

```sh
syq cp --srcs-in small-files --to server --into /scratch/benchmark-small \
  --connections 1 -v --tuning-options batch-files=256,batch-bytes=8M
```

`split-min-size` controls when an idle worker can take part of another worker's
remaining file region. Lower values permit smaller divisions; higher values
avoid small assignments. A division remains aligned to hash blocks. The
scheduler divides a region only when at least twice the effective minimum
remains. This is a work-assignment threshold, separate from request size.

### Average rate and burst patterns

`--bwlimit` budgets logical file-data bytes across the copy's workers, before
compression, encryption, and protocol overhead. It caps a rate, not a total
byte count. The request pacing modes make different trade-offs:

- **Timed pacing**, such as `bw-pacing=125ms`, limits request size to the smaller
  of the configured request size and `max(rate * interval, 512 bytes)`. Workers
  wait for the start of each reserved interval. The first request can start
  immediately, so a short copy can exceed the configured average by that
  initial request. The default `125ms` retains the existing sizing and pacing.
- **Average pacing**, `bw-pacing=average`, leaves request size independent of
  `--bwlimit`. Workers wait for the *end* of each reservation before issuing the
  request, including the first one. A single 2 MiB request at 1 MiB/s therefore
  waits about two seconds before it is issued. Large requests can then travel
  in bursts, while their full byte budgets have already been paid.

For example, to test larger requests under an average rate cap:

```sh
syq cp large-file --to server --as /scratch/benchmark-capped \
  --connections 1 --bwlimit 1M -v \
  --tuning-options copy-path=ranges,request-size=4M,bw-pacing=average
```

Neither mode promises a maximum network burst or uninterrupted service for
other traffic. They pace source requests; helper processing, queues,
compression, and transport buffering affect when bytes actually cross a link.
A deeper pipeline can accumulate more data before forwarding it. A restricted
receiver also enforces its signed rate ceiling independently, including its
existing `max(rate * 125ms, 512 bytes)` request-size ceiling. Both tuning modes
respect that additional ceiling; `-v` shows the effective size. Average pacing
decouples size from rate where this signed receiver constraint does not apply.
Measure both sustained throughput and short-interval traffic when evaluating
capped runs.

### Recording a comparison

With overrides, `-v` reports effective settings, including any reduction in
request size or increase in the split threshold. A final `syq: tuning observed:`
line contains diagnostic JSON with copy-path counts, range request count,
largest requested range, and largest worker batch by file count and content
bytes. These are observations of attempted work, so retries can contribute
more than once. They are experimental diagnostics, separate from completion
records. `--stats` also enables them, but currently bypasses the native
small-copy shortcut; use `-v` to compare that shortcut with other paths.

Use the same reporting options for every comparison, a fresh disposable
destination, and explicit defaults for the baseline, such as
`--tuning-options copy-path=auto`. Record the source data, transport, connection
count, effective settings, elapsed time, CPU use, and peak memory. Check the
exit status and copied contents. Leave `--bwlimit` unset when measuring
unrestricted throughput. Default request size and pipeline depth are not
automatically tuned.

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
