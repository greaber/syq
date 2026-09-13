# Speed

Syq copies files in parallel and adjusts its connection count automatically.
Start with the defaults. For repeated remote copies, [keep the connection
open](install.md#keep-connections-open) to avoid logging in each time.

## Quick comparison

Use the quick script to get a sense of performance on your own machines:

```sh
curl --proto '=https' --tlsv1.2 -fLsS -o try-benchmark.sh \
  https://raw.githubusercontent.com/greaber/syq/master/scripts/try-benchmark.sh
bash try-benchmark.sh
```

The default pushes 1,024 files of 8 KiB to an SSH host you choose, comparing syq
with rsync over three rounds. Use `--mode pull` for downloads or `--mode local`
to include cp. `--workload large` selects one 64 MiB file; `--workload both`
runs both workloads. The script checks every copy and cleans up afterward.

Network comparisons first run an untimed syq warm-up so it can learn a useful
connection count. This aims for 60 seconds of copying, using up to four copies
of datasets no larger than 1 GiB each, subject to free space. Slow copies and
preparation can take longer. Use `--warmup off` for a shorter comparison using
the existing learned or default count. Local copies and manual tuning skip
this warm-up.

`--size quick` is the fixed-size default. For longer tests, `--size medium`
uses 1 GiB or 4,096 small files; `--size large` uses 8 GiB or 16,384 files.
`--size auto` grows the test data until a syq copy takes about five seconds or
scratch space limits growth, with no fixed total-data or runtime limit. All
scored tools use the same dataset. Longer tests help reveal sustained
throughput, but neither sizing nor warm-up guarantees tuning has settled.

To try your own syq options, put them after `--`:

```sh
bash try-benchmark.sh --yes --mode pull --host server --tool syq --rounds 1 \
  -- --no-tcp --connections 1 -v
```

These options also apply to setup and warm-up copies. Path, removal, and
output-file options are excluded to keep the test inside its disposable
directories. `-v` shows full commands and scratch paths. Use `--tool rsync`
for a separate rsync comparison, omitting syq options after `--`. See
[tuning options](tuning.md) for experiments, or run
`bash try-benchmark.sh --help` for all script options.

The script needs Bash, rsync, OpenSSL, standard Unix utilities, and Perl's
core JSON::PP module locally. Remote tests need SSH access and rsync on the
other machine; pull warm-ups also need Bash, OpenSSL, dd, and split there.
Scratch parent directories must exist. `--source-dir` selects the local
parent; `--dest-dir` selects the remote parent for both push and pull.

Each scored copy uses an empty destination and preserves permissions and
modification times. Generation, helper preparation, warm-up, and content
checks are untimed. Failed commands or content checks stop the comparison.
SSH connection reuse is disabled for both tools during network tests; syq's
[learned connection counts](tuning.md#remembered-connection-counts) remain
active unless you override tuning. Caches are not flushed, and copies do not
wait for durable storage.

Compare tools using the main table, which includes connection startup in total
command time. Network results show decimal MB/s averaged across trials. Local
results show seconds, because filesystem cloning can avoid moving bytes;
those times do not measure disk bandwidth.

The separate syq timing table helps explain slow results. It divides total time
into the copying interval and time outside it, such as setup and finishing.
The copying interval includes waiting and per-file work, and can overlap
planning and connection setup. Use it to diagnose syq, not to compare against
another tool's total time. If the script flags a short copying interval or
substantial time outside it, try a larger workload to investigate sustained
throughput.

## Benchmarks

The separate [syq-bench project](https://greaber.github.io/syq-bench/) runs more
extensive experiments across workloads, storage systems, and network routes.
Browse its results, or [run its experiments](https://greaber.github.io/syq-bench/reproduce.html)
for a more detailed comparison. The quick script above does not use syq-bench.

<a id="when-rsync-or-cp-is-faster"></a>

## Diagnose a slow copy

```sh
syq cp -vv --stats data --to server --into /backup
```

`-vv` shows the chosen transport and connections; `--stats` adds totals and
available TCP statistics.

| Symptom | Try |
|---|---|
| Data falls back to SSH | Check [TCP reachability](server-tuning.md#make-tcp-reachable) |
| Many short commands spend time logging in | `syq persist on` |
| CPU is saturated on a fast link | Compare with `--no-compress` |
| A long-distance path suffers loss | Investigate [congestion control](server-tuning.md#test-congestion-control) |

Compare the same workload and direction using empty test destinations.
A second copy into the same destination may just measure skipping existing files.

## TCP data connections

SSH authenticates remote copies. When reachable, encrypted TCP carries file
data on a port in `47600–47699`; otherwise copies use SSH on the same route.
See [server setup](server-tuning.md#make-tcp-reachable) for firewall settings.
Copies [authorized through another machine](remote-to-remote.md#start-a-copy-from-the-source-server)
require direct encrypted TCP.

Use `--no-tcp` to select SSH data transport or `--tcp-ports LO-HI` to choose a
port range. On Linux, `--tcp-congestion ALGO` selects an available congestion
control algorithm. `--tcp-plain` disables data encryption and authentication;
use it only on a trusted network. Restricted receivers refuse it.

## Local copies and NFS

For local copies, syq uses the filesystem's copy optimizations automatically
when it can. On filesystems that support cloning, this can avoid physically
copying every byte. You can also copy to or from a mounted NFS directory using
its local path. See [storage placement](server-tuning.md#check-local-storage-placement)
for how the source and destination filesystems affect performance.

## Limit bandwidth

Use `--bwlimit` to leave bandwidth for other work:

```sh
syq cp data --to server --into /backup --bwlimit 10M
```

This limits file data to 10 MiB/s across the copy's workers. It controls the
average copy rate; buffering and protocol overhead can cause network bursts.

<a id="options-that-change-the-tradeoff"></a>

## Compression and in-place writes

`--no-compress` can help when compression costs more CPU time than it saves in
network traffic. `--inplace` saves temporary disk space, but exposes incomplete
updates to readers. Read [in-place writes](reference.md#in-place-writes) before
using it.

<a id="how-many-connections"></a>
<a id="benchmark-tuning"></a>
<a id="streaming-and-request-windows"></a>
<a id="batch-size-and-splitting"></a>
<a id="average-rate-and-burst-patterns"></a>
<a id="recording-a-comparison"></a>

## Investigate tuning

Manual connection counts and other [tuning options](tuning.md) are for
troubleshooting and development. Normal copies should not need them.
