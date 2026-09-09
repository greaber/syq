# Speed

Start with the defaults. Syq copies files in parallel and adjusts the connection
count during a transfer. It uses encrypted TCP for data when reachable and SSH
otherwise. Small copies avoid extra connections when setup would cost more
than it saves.

Measure your own workload before changing settings. Network distance, storage,
file sizes, and how much data already exists at the destination all affect speed.

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

The script needs Bash, rsync, OpenSSL, Perl (with JSON::PP), and standard Unix
utilities locally. Remote tests also need SSH access and rsync on the other
machine. Use an SSH config alias for custom ports or IPv6. `--install` installs
syq locally if missing; `--help` lists the choices.

Scratch parents must already exist. `--source-dir` is the local scratch parent;
for SSH tests, `--dest-dir` is the remote one, including when pulling.

Automatic sizing increases throwaway data until a syq copy takes about five
seconds, subject to available space. Setup and verification take additional
time, and there is no fixed total runtime limit. To use a fixed workload:

| Option | Large file | Small files (8 KiB each) |
|---|---|---|
| `--size quick` | 64 MiB | 1,024 |
| `--size medium` | 1 GiB | 4,096 |
| `--size large` | 8 GiB | 16,384 |

Each tool copies the same reproducible, hard-to-compress data into an empty
destination. The script rotates tool order and checks contents after every
trial. It compares syq's defaults with permissions preserved, `rsync -rpt`,
and local `cp -pR`. A failed copy or content check stops the comparison.

Results show mean, minimum, and maximum speed in decimal MB/s; higher is
faster. Timings include process startup and buffered writes, but exclude data
generation, sizing, and verification. Caches are not flushed, and copies do
not wait for durable storage. Small tests can mostly measure startup costs;
filesystem cloning can favor cp. Syq may be slower on your workload.

The script cleans up its test data, including after Ctrl-C. If SSH is unavailable
during cleanup, it reports the remote path to remove later. See the
[published methodology](https://greaber.github.io/syq-bench/) for more controlled
measurements.

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

`-vv` shows the chosen transport and connections. `--stats` adds totals and
available TCP statistics. Its copying interval measures file work, which can
overlap setup; use total elapsed time when comparing complete commands.

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

Use `--tuning-options` for controlled comparisons when the defaults perform
poorly. These experimental controls appear in `--help-all`; their keys and
bounds may change between releases.

`syq cp` and `syq rsync` accept `--tuning-options`. Supply
comma-separated `KEY=VALUE` pairs:

```sh
syq cp large-file --to server --as /scratch/benchmark-copy \
  --connections 1 -v \
  --tuning-options copy-path=ranges,request-size=1M,pipeline-depth=8
```

| Key | Default | Accepted values |
|---|---|---|
| `request-size` | Hash block size (normally 4 MiB) for ordinary requests; at most 2 MiB for streaming | 512 bytes through 64 MiB |
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

Larger requests reduce overhead per byte; deeper pipelines allow more requests
to await replies at once. Both can increase memory use. Neither changes the
hash blocks used for integrity checks and resume.

`copy-path=ranges` disables small-file batches and whole-file shortcuts,
including local kernel copying. Matching data can still be skipped or reused.
`auto` lets syq choose normally.

### Streaming and request windows

Syq automatically streams larger remote ranges (usually above 16 MiB), using
blocks of at most 2 MiB by default. Streaming still checks contents and write
errors and supports resume. No setting is needed for everyday copies.

For comparisons, `copy-path=streaming` forces streaming and disables whole-file
and small-file shortcuts. `copy-path=auto-streaming` keeps those shortcuts and
streams the remaining ranges. Both include local and short ranges.

An explicit `request-size` also sets the streaming block size; bandwidth and
receiver limits may reduce it. An explicit `pipeline-depth` disables automatic
streaming. Neither forced streaming mode accepts `pipeline-depth`.

For a controlled comparison, use fresh scratch destinations:

```sh
syq cp data.bin --to host --as /scratch/pipeline.bin --connections 1 -v \
  --tuning-options copy-path=ranges,request-size=1M,pipeline-depth=4
syq cp data.bin --to host --as /scratch/streaming.bin --connections 1 -v \
  --tuning-options copy-path=streaming,request-size=1M
```

Streaming can be slower on short or CPU-limited copies. Memory use depends on
request size, worker count, compression, and transport buffering. With
`--bwlimit`, a remote source can send ahead of paced destination writes, so the
limit is an average copy rate, not a strict cap on incoming bursts.

### Batch size and splitting

For example, compare small-file batches with:

```sh
syq cp --srcs-in small-files --to server --into /scratch/benchmark-small \
  --connections 1 -v --tuning-options batch-files=256,batch-bytes=8M
```

Explicit batch controls replace the small-copy shortcut with worker batches.
File and byte limits are ceilings; syq may choose smaller batches. Files larger
than the byte limit use another copy method. With `--bwlimit`, each batch
contains at most one file. Batch controls cannot combine with `copy-path=ranges`
or `copy-path=streaming`; `auto-streaming` accepts them.

`split-min-size` sets the smallest file region an idle worker can take from
another worker. Lower values allow finer sharing; higher values avoid small
assignments. Splits align to hash blocks and need at least twice the minimum
remaining size.

### Average rate and burst patterns

`--bwlimit` caps logical file-data bytes per second across workers, before
compression, encryption, and protocol overhead.

- **Timed pacing** (`bw-pacing=125ms`, the default) sends smaller requests at
  regular intervals. The first request can start immediately, so a short copy
  can exceed the average by that initial request.
- **Average pacing** (`bw-pacing=average`) waits for each request's byte budget
  before sending it, including the first. It allows larger requests, which can
  arrive in bursts. A 2 MiB request at 1 MiB/s waits about two seconds.

For example, to test larger requests under an average rate cap:

```sh
syq cp large-file --to server --as /scratch/benchmark-capped \
  --connections 1 --bwlimit 1M -v \
  --tuning-options copy-path=ranges,request-size=4M,bw-pacing=average
```

Neither mode limits the size of every network burst. Streaming, queues, and
transport buffering affect when bytes cross the link. Restricted receivers
also enforce their authorized rate and request-size limits. Measure both
sustained throughput and short-interval traffic when comparing capped runs.

### Recording a comparison

With overrides, `-v` reports effective request sizes and a final
`syq: tuning observed:` diagnostic with copy-method counts and request and batch
sizes. Retries can count more than once. These experimental diagnostics are
separate from [completion records](automation.md).

Use the same reporting options and fresh disposable destinations for each
comparison. Prefer `-v`: `--stats` bypasses the small-copy shortcut and can
change what you measure. Use explicit defaults for the baseline, such as
`--tuning-options copy-path=auto`.

Record the source data, transport, connections, settings, elapsed time, CPU use,
and peak memory. Check exit status and copied contents. Leave `--bwlimit` unset
when measuring unrestricted throughput.

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

Check [source and destination storage placement](server-tuning.md#check-local-storage-placement):
copies within a filesystem that supports cloning can share data extents instead
of physically copying every byte.

Syq uses kernel or NFS server-side copying when available, and otherwise copies
files in parallel. These choices are automatic. Check elapsed time as well as
reported throughput: storage optimizations can avoid moving every logical byte.

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
