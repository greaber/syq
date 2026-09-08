# Speed

Start with the defaults. Syq copies files in parallel, splits large files
between workers, and adjusts connection count during the transfer. If a TCP
data port is reachable, it sends data through separate encrypted connections.
Otherwise, ordinary copies send their data over SSH. Small copies can stay
on the SSH control connection to avoid extra setup. Larger copies start up to
two workers on the copy's existing SSH connection while the others open
independent connections for parallel throughput. A fixed connection count
reuses it for only one worker. This reuse does not apply to a cross-run
persistent connection or a custom `--rsh` command. Automatic SSH copies into
new or empty directories, or to missing single-file destinations, also limit
their initial worker count to the available files and splittable ranges.
Updates keep their usual count. If a missing file has a resumable partial,
syq restores that count when it discovers the partial: one file can contain
many separate changed regions.
With automatic concurrency, syq divides a single large fresh file over SSH
before copying starts, so workers that connect later can help without waiting for a large enough
remaining range to split. Earlier workers can keep taking work while those
connections start.
When pushing into an
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
bash try-benchmark.sh --yes --mode push --host server --workload both --rounds 3
bash try-benchmark.sh --yes --mode local --source-dir /data --dest-dir /mnt/nfs --workload small
```

The script needs Bash, rsync, OpenSSL and standard Unix utilities locally;
automatic sizing uses Perl with its core JSON::PP module. Terminal runs also
use Perl to keep SSH prompts interruptible. Remote tests
need SSH access and rsync on the other machine. Syq prepares a helper matching
your local build and shows installation progress when one is needed.
Use an SSH config alias for custom ports or IPv6. `--install` installs syq
locally if missing; `--help` lists the choices.

Scratch parents must already exist. For SSH tests, `--dest-dir` is the remote
scratch parent, including when pulling; `--source-dir` is always the local
scratch parent.

By default, the script starts with 64 MiB for the large file and 1,024 files
of 8 KiB for the small-file workload. It makes verified, unscored syq copies
and increases each workload until syq's copying interval reaches about five
seconds. Each increase is between 25% and tenfold, avoiding repeated
near-identical tests when timings fluctuate. Available space at both ends limits
growth, with room reserved for the copies and filesystem overhead; if space
prevents a long enough copy, the script warns and uses the tested size.
There is no fixed total-data or runtime limit. A slow first copy can take longer
than five seconds, and generation and verification also take time.

All tools then copy the same dataset into empty destinations. Three rounds mean
six scored copies per workload over SSH (syq and rsync), or nine locally (also
cp). Choosing both workloads doubles those counts. A faster cp result does not
cause further growth.

Automatic sizing requires syq to report `copying_elapsed_ms` in its automation
results. Older builds can use `--size quick`, `--size medium`, or `--size large`
for fixed workloads: respectively 64 MiB / 1,024 files, 1 GiB / 4,096 files,
and 8 GiB / 16,384 files. Small files remain 8 KiB each. These flags also let
you repeat a fixed-size comparison.

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
optimizations.

Generation, preparation, calibration, and POSIX `cksum` comparisons are
outside the scored timers. Preparation shows helper installation messages without
a throughput result. A failed command or content check stops the comparison.
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
statistics where available. It also reports the copying interval when bytes moved:
the span from first file work to last completed file work across all workers.
This includes per-file checks, finalization and gaps; it may overlap planning
and connection setup. It is not pure network time or a separate phase you can
add to setup time. `SYQ_DEBUG=1` adds engineering timings for a
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
| `copy-path` | `auto` | `auto`, `ranges`, or experimental `streaming` / `auto-streaming` |
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
`copy-path=ranges` or `copy-path=streaming`.

### Streaming and request windows

Syq automatically streams remote ranges larger than one normal request
window (usually 16 MiB). Local ranges and shorter remote ranges use ordinary
requests. Whole-file and small-file shortcuts keep their usual eligibility.
No streaming or pipeline setting is needed for ordinary copies.
The `syq: tuning:` diagnostic describes the selection policy: a pipeline depth
applies only to ordinary ranges, and automatic remote selection also reports
the size above which ranges stream. It does not claim which paths ran; use
the observed range and streaming counters for that.

Streaming sends
checked source blocks and collects destination write replies concurrently,
instead of limiting the number of blocks awaiting replies. It still verifies
block hashes, checks all write errors before completion, and supports resume
and parallel workers on different parts of one large file. It does not add
a disk flush.

For experiments, `copy-path=streaming` forces streaming even for local and
short ranges, bypassing the same copy shortcuts as `copy-path=ranges`.
`copy-path=auto-streaming` keeps the normal whole-file and small-file shortcuts,
but forces streaming for all remaining ranges, including local and short ones.
An explicit `pipeline-depth` uses ordinary requests instead of automatic
streaming, allowing comparisons with the credit-window implementation.

For a controlled comparison, use fresh scratch destinations:

```sh
syq cp data.bin --to host --as /scratch/pipeline.bin --connections 1 -v \
  --tuning-options copy-path=ranges,request-size=1M,pipeline-depth=4
syq cp data.bin --to host --as /scratch/streaming.bin --connections 1 -v \
  --tuning-options copy-path=streaming,request-size=1M
```

Both streaming modes reject `pipeline-depth`. Forced `streaming` also rejects
batch controls; `auto-streaming` allows them, with the usual effect on small
copies. Their data queues remain
bounded, but memory also depends on request size, worker count, compression
and transport buffering. It may be slower on short or CPU-limited copies:
starting/stopping streams and collecting replies add work. Work-stealing can
also discard already-read source data when another worker takes a suffix.
With `--bwlimit`, pacing happens before destination writes; a remote source
can send ahead into bounded buffers. This also applies to automatically selected
streaming, without any tuning override. On pulls, initial incoming traffic can
include the response-reader queue and in-flight frames and socket buffers;
it is not limited to one paced block or one request window. The limit controls
the average accepted copy rate, not a strict source-side burst limit.
Restricted receivers still enforce their signed limits.

### Batch size and splitting

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
other traffic. Ordinary ranges pace source requests, while streamed ranges pace
destination writes after receiving the source block; helper processing, queues,
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
streaming-range and streamed-block counts,
largest requested range, and largest worker batch by file count and content
bytes. These are observations of attempted work, so retries can contribute
more than once. They are experimental diagnostics, separate from completion
records. `--stats` also enables them, but currently bypasses the native
small-copy shortcut; use `-v` to compare that shortcut with other paths.
`SYQ_DEBUG=1` also records path counts without any tuning override, allowing
automatic selection to be inspected without changing the tuning-cache policy.

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
the connection details. This also works for restricted server-to-server
copies: SSH keeps file data on the source-to-destination route. Copies
[authorized through another machine](remote-to-remote.md#start-a-copy-from-the-source-server)
still require direct encrypted TCP and fail if it is unavailable.

`--no-tcp` selects SSH data transport, including for enrolled restricted
receivers. `--tcp-plain` removes data encryption and authentication and should
be used only on a trusted network; restricted receivers refuse it.

On Linux, `--tcp-congestion ALGO` chooses an available algorithm for syq's
TCP sockets on both ends, without changing host defaults. Unsupported choices
fail the copy. Restricted receivers enforce the algorithm signed into the
copy authorization.

## Local copies and NFS

Same-machine Linux copies first try kernel or NFS server-side copying. If
that is unavailable between ext4, XFS, or tmpfs filesystems during a multi-file
copy, syq copies eligible files larger than 64 KiB directly through their open
source and destination files. It runs these file copies in parallel without
sending their contents through local TCP connections. Files up to 64 KiB still
use batches, subject to the hash block, request-size and batch-byte limits.
This local batch ceiling does not reduce the size of ordinary range requests.
This happens automatically, without tuning options. Single-file copies retain parallel range copying when offload
is unavailable.

Syq also uses a sequential destination writer for eligible local-disk to
asynchronous-NFS copies. NFS sources, synchronous destinations, and other
filesystems retain parallel range copying when offload is unavailable.
Checksum comparisons, resumed data, and bandwidth limits keep their usual
range-based behavior.

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
does not affect file contents or integrity checks. Compression applies across
the network, not between syq and its receiver process on the same machine.

Examples use native options. In rsync mode, syq-specific options have a
`--syq-` prefix, such as `--syq-connections` and `--syq-no-tcp`.
See [rsync extensions](rsync-compat.md#syq-extensions).
