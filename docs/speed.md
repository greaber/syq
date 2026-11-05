# Speed

Syq copies files in parallel and adjusts its number of connections
automatically, so start with the defaults. This page shows how to measure syq
on your machines and find out why a copy is slow. To avoid logging in for every
remote copy, see [Keep connections open](persistence.md).

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

Network tests first spend about a minute warming up syq's connection tuning;
use `--warmup off` for a shorter comparison. Run `bash try-benchmark.sh --help`
for workload sizes, dependencies, and custom syq options. If trials are too
short to measure sustained speed, choose a larger workload.

<a id="what-the-comparison-measures"></a>

The script prints a comparison table and, below it, a syq timing breakdown.
Use the comparison table to compare tools: it times each whole command,
including connection startup, copying into an empty destination. Network
results show average MB/s; local results show seconds, because filesystem
cloning can avoid moving the bytes at all. The timing breakdown leaves setup
out of its copying rate, so don't compare that rate with another tool's.

Network tests turn off SSH connection reuse for both tools. The script doesn't
flush caches or wait for data to reach the disk, so local times don't measure
disk bandwidth.

## Benchmarks

The separate [syq-bench project](https://greaber.github.io/syq-bench/) runs more
extensive experiments across workloads, storage systems, and network routes.
Browse its results, or [run its experiments](https://greaber.github.io/syq-bench/reproduce.html)
for a more detailed comparison.

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
<figcaption>One 1.07 GB file, held in memory at both ends, over a route with about
108 ms round-trip time; three runs per tool. The syq row sends data over
encrypted TCP; syq over SSH sends it through SSH instead. Measured with syq 0.6.0
and rsync 3.4.1 on September 13, 2026, by the separate
<a href="https://greaber.github.io/syq-bench/all-results.html#public-wan-forward">syq-bench project</a>
(<a href="https://greaber.github.io/syq-bench/data/release-060-public-wan-forward.json">raw results</a>).
Your results will depend on your machines and connection.</figcaption>
</figure>

<a id="when-rsync-or-cp-is-faster"></a>

## Diagnose a slow copy

```sh
syq cp -vv --stats data --to server --into /backup
```

`-vv` shows whether the data travels over TCP or SSH and the connections syq
opens. `--stats` adds totals, TCP statistics, how syq's parallel workers spent
their time, and CPU time. These help locate a delay but don't prove its cause.
To see how they change during the copy, add `--results run.ndjson` and see
[performance measurements](performance-measurements.md).

| Symptom | Try |
|---|---|
| Data falls back to SSH | Check [Make TCP reachable](server-tuning.md#make-tcp-reachable) |
| Many short commands spend time logging in | `syq persist on` |
| CPU is saturated on a fast link | Compare with `--no-compress` |
| A long-distance path suffers loss | Investigate [Test congestion control](server-tuning.md#test-congestion-control) |

Compare the same workload and direction using empty test destinations.
A second copy into the same destination may just measure skipping existing files.

## Local copies and NFS

For local copies, syq uses the filesystem's own copy features when it can. On
filesystems that support cloning, the copy can share data instead of writing
every byte, so the displayed rate can exceed the disk's speed. A mounted NFS
directory works like any local path.

<a id="tcp-data-connections"></a>
<a id="limit-bandwidth"></a>
<a id="options-that-change-the-tradeoff"></a>
<a id="compression-and-in-place-writes"></a>
<a id="compression"></a>
<a id="how-many-connections"></a>
<a id="benchmark-tuning"></a>
<a id="streaming-and-request-windows"></a>
<a id="batch-size-and-splitting"></a>
<a id="average-rate-and-burst-patterns"></a>
<a id="recording-a-comparison"></a>
<a id="investigate-tuning"></a>

## Other options

Remote copies send file data over encrypted TCP on a port in `47600–47699`
when the server's port is reachable, and through SSH otherwise; see
[Make TCP reachable](server-tuning.md#make-tcp-reachable). `--no-tcp` uses SSH
without trying TCP, `--tcp-ports LO-HI` chooses another port range, and on
Linux `--tcp-congestion ALGO` selects a congestion control algorithm.
`--no-tcp-encryption` turns off encryption and authentication of the data; use
it only on a trusted network.

`--resource-limits bandwidth=RATE` leaves bandwidth for other work; see
[Resource limits](resource-limits.md). Manual connection counts and other
[tuning options](tuning.md) are for troubleshooting; most copies don't need
them.
