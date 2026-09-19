# Speed

Syq copies files in parallel and adjusts its connection count automatically.
Start with the defaults. To avoid logging in for every remote copy, see
[Keep connections open](install.md#keep-connections-open).

## Quick comparison

Use the quick script to get a sense of performance on your own machines:

```sh
curl --proto '=https' --tlsv1.2 -fLsS -o try-benchmark.sh \
  https://raw.githubusercontent.com/greaber/syq/master/scripts/try-benchmark.sh
bash try-benchmark.sh
```

By default, the script copies 1,024 files of 8 KiB to an SSH host you choose,
comparing syq with rsync over three rounds. It creates disposable test data,
checks every copy, and cleans up afterward. Use `--mode pull` for downloads or
`--mode local` to include cp.

Network tests first warm up syq's connection tuning. This targets about a minute
of copying, but setup and slow transfers can take longer. It uses up to four
copies of datasets no larger than 1 GiB each, subject to free space. Use
`--warmup off` for a shorter comparison.

Compare tools using the main table: it includes connection startup in total
command time. Network results show average MB/s; local results show seconds,
since filesystem cloning may avoid moving the bytes. The separate syq timing
table helps diagnose setup costs; its copying-only rate is not comparable with
another tool's total-time rate.

Run `bash try-benchmark.sh --help` for workload sizes, dependencies, scratch
directories, and custom syq options. If trials are too short to measure sustained
speed, choose a larger workload.

### What the comparison measures

Each timed copy uses the same data and an empty destination, preserving
permissions and modification times. Generation, helper preparation, warm-up,
and content checks are untimed. Failed copies or content checks stop the test.

Network tests disable SSH connection reuse for both tools. Syq's learned
connection counts remain active unless you override tuning; warm-up does not
guarantee that tuning has settled. Caches are not flushed, and copies do not
wait for durable storage. Local cloning times therefore do not measure disk
bandwidth.

## Benchmarks

The separate [syq-bench project](https://greaber.github.io/syq-bench/) runs more
extensive experiments across workloads, storage systems, and network routes.
Browse its results, or [run its experiments](https://greaber.github.io/syq-bench/reproduce.html)
for a more detailed comparison. The quick script above does not use syq-bench.

<figure class="benchmark-example">
<table>
<caption>Published example: Germany → US East Coast</caption>
<thead><tr><th scope="col">Tool</th><th scope="col">Average speed</th></tr></thead>
<tbody>
<tr><th scope="row">syq</th><td>159.9 MB/s</td></tr>
<tr><th scope="row">syq over SSH</th><td>88.3 MB/s</td></tr>
<tr><th scope="row">rsync</th><td>18.3 MB/s</td></tr>
</tbody>
</table>
<figcaption>One 1.07 GB file, held in memory at both ends; three runs per tool.
From the separate <a href="https://greaber.github.io/syq-bench/all-results.html#public-wan-forward">syq-bench project</a>,
measured on September 13, 2026 (<a href="https://greaber.github.io/syq-bench/data/release-060-public-wan-forward.json">raw results</a>).
Your results will depend on your machines and connection.</figcaption>
</figure>

<a id="when-rsync-or-cp-is-faster"></a>

## Diagnose a slow copy

```sh
syq cp -vv --stats data --to server --into /backup
```

`-vv` shows the chosen transport and connections; `--stats` adds totals and
available TCP statistics, worker wait fractions, endpoint operations and bytes,
and process CPU. These wait fractions
help locate delays; they are not proof of their cause. Add `--results run.ndjson`
to inspect how worker waits, endpoint operations, CPU and TCP backpressure change
over time. Remote evidence includes its age. See the
[`progress`](automation.md#progress) record for interpretation and limitations.

| Symptom | Try |
|---|---|
| Data falls back to SSH | Check [Make TCP reachable](server-tuning.md#make-tcp-reachable) |
| Many short commands spend time logging in | `syq persist on` |
| CPU is saturated on a fast link | Compare with `--no-compress` |
| A long-distance path suffers loss | Investigate [Test congestion control](server-tuning.md#test-congestion-control) |

Compare the same workload and direction using empty test destinations.
A second copy into the same destination may just measure skipping existing files.

## TCP data connections

SSH authenticates remote copies. When reachable, encrypted TCP carries file
data on a port in `47600–47699`; otherwise copies use SSH on the same route.
See [Make TCP reachable](server-tuning.md#make-tcp-reachable) for firewall settings.
To [Run the copy from a server](remote-to-remote.md#run-the-copy-from-a-server)
with your laptop’s approval, direct encrypted TCP must be reachable.

Use `--no-tcp` to select SSH data transport or `--tcp-ports LO-HI` to choose a
port range. On Linux, `--tcp-congestion ALGO` selects an available congestion
control algorithm. `--tcp-plain` disables data encryption and authentication;
use it only on a trusted network. Restricted receivers refuse it.

## Local copies and NFS

For local copies, syq uses the filesystem's copy optimizations automatically
when it can. On filesystems that support cloning, this can avoid physically
copying every byte. You can also copy to or from a mounted NFS directory using
its local path. See [Check local storage placement](server-tuning.md#check-local-storage-placement)
for how the source and destination filesystems affect performance.

Reported bytes count the file's size even when cloning avoids physical I/O,
so the displayed rate can exceed disk throughput.

## Limit bandwidth

Use `--resource-limits bandwidth=RATE` to leave bandwidth for other work:

```sh
syq cp data --to server --into /backup --resource-limits bandwidth=10M
```

This limits file data to 10 MiB/s across the copy's workers. It controls the
average copy rate; buffering and protocol overhead can cause network bursts.
See [Resource limits](resource-limits.md) for all units and supported routes.

<a id="options-that-change-the-tradeoff"></a>

## Compression and in-place writes

`--no-compress` can help when compression costs more CPU time than it saves
in network traffic; see [Transport compression](reference.md#transport-compression). `--inplace` saves temporary
disk space, but exposes incomplete updates to readers. Read
[in-place writes](reference.md#in-place-writes) before using it.

<a id="how-many-connections"></a>
<a id="benchmark-tuning"></a>
<a id="streaming-and-request-windows"></a>
<a id="batch-size-and-splitting"></a>
<a id="average-rate-and-burst-patterns"></a>
<a id="recording-a-comparison"></a>

## Investigate tuning

Manual connection counts and other [tuning options](tuning.md) are for
troubleshooting and development. Normal copies should not need them.
