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

Choose an SSH copy to compare syq with rsync, or a local copy to include cp.
The script creates test data, checks the copied contents, and cleans up afterward.
Use `bash try-benchmark.sh --help` for options.

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

On macOS, eligible files larger than 64 KiB use APFS cloning within the same
volume. The reported logical byte rate can exceed physical disk throughput.
Small files stay batched. See [copy files](reference.md#copy-files) for cloning
eligibility and fallbacks.

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
