# Performance tuning

Syq adjusts performance automatically. Use these controls to investigate copies
where the defaults perform poorly. They appear in `--help-all` and are
experimental; their keys and bounds may change between releases.

`--performance-tuning workers=N` fixes the number of filesystem copy-worker
slots instead of adjusting it automatically. Workers process files or ranges;
several workers can share a large file. Remote workers use data channels, SSH
channels can share a TCP socket, and local workers need no network connection.
Idle slots do no work, and shortcuts can finish a copy using fewer workers.
This is not a limit on total sockets, file descriptors, CPU or memory.

Both `syq cp` and `syq rsync` use this spelling. Leave it unset for everyday
copies. S3 uses separate [object, part and request controls](object-storage.md#parallelism).
Use `--resource-limits bandwidth=RATE` to leave bandwidth for other work.

## Remembered connection counts

Remote copies start from the last learned count for the same host route,
direction and transport, or from 8 workers over SSH and 16 over TCP. The cache
normally lives at `~/.cache/syq/tuning.json` (`XDG_CACHE_HOME` can change its
parent, and `SYQ_TUNING_CACHE` names another file or, when empty, turns the
cache off). The quick benchmark uses this cache, even though it disables SSH
connection persistence. Its temporary file paths do not change the cache key.

Short copies may finish before syq can learn a better count. Only successful
copies that compare enough connection counts without changing transport update
the cache; failed or interrupted copies leave it unchanged. The benchmark's
[untimed warm-up](speed.md#quick-comparison) gives learning more time before
scoring, but does not guarantee that tuning has settled.

`--performance-tuning workers=N` disables automatic adjustment and cache use. Supplying
`--performance-tuning` or `--resource-limits` bypasses reading and updating learned counts, but live
auto-tuning continues unless you also set `workers`. Use `-vv` to see
when syq starts from a remembered count.

## Transfer controls

`syq cp` and `syq rsync` accept `--performance-tuning`. Supply
comma-separated `KEY=VALUE` pairs:

```sh
syq cp large-file --to server --as /scratch/benchmark-copy \
  --performance-tuning workers=1 -v \
  --performance-tuning copy-path=ranges,request-size=1M,pipeline-depth=8
```

| Key | Default | Accepted values |
|---|---|---|
| `comparison-block-size` | 4 MiB | 64 KiB through 64 MiB; filesystem copies only |
| `request-size` | Hash block size (normally 4 MiB) for ordinary requests; at most 2 MiB for streaming | 512 bytes through 64 MiB |
| `pipeline-depth` | 4 | 1 through 64 outstanding range requests per endpoint per worker |
| `copy-path` | `auto` | `auto`, `ranges`, or experimental `streaming` / `auto-streaming` |
| `batch-files` | 128 or 512, depending on transport and latency | 1 through 4096 files per worker batch |
| `batch-bytes` | 16 MiB | 512 bytes through 64 MiB per worker batch, including the first file |
| `split-min-size` | 32 MiB, at least two hash blocks | 1 byte through 1 GiB, raised to at least two hash blocks |
| `bw-pacing` | `125ms` when capped | `average`, or an integer interval from `1ms` through `10s`; requires a nonzero `--resource-limits bandwidth=RATE` |

Sizes accept `K`, `M`, and `G`, using powers of 1024. Unknown keys, repeated
keys, and out-of-range values fail the command. Overrides apply to the remote
coordinator too and are not saved.

Larger requests reduce overhead per byte; deeper pipelines allow more requests
to await replies at once. Both can increase memory use. Neither changes the
hash blocks used for integrity checks and resume.

`copy-path=ranges` disables small-file batches and whole-file shortcuts,
including local kernel copying and APFS cloning. Matching data can still be
skipped or reused.
`auto` lets syq choose normally.

### Scattered edits in existing files

For existing remote copies with scattered small edits, try smaller comparison
blocks while keeping larger transfer requests:

```sh
syq cp --srcs-in source --to host --into destination \
  --performance-tuning comparison-block-size=64K,request-size=4M
```

The default comparison block is 4 MiB; one changed byte makes that whole block
need copying. Smaller blocks can reduce the data sent, but require more hashes
and requests. Keep `request-size=4M`: request size otherwise defaults to the
comparison block, so setting only `comparison-block-size=64K` also shrinks
requests and lowers the automatic streaming threshold to 256 KiB.

Comparison and resume also limit how small these blocks can be for a large
file: the hashes must fit in one response. At 64 KiB, the file must be smaller
than 130 GiB; exceeding that limit fails the comparison rather than falling
back to a full copy. Increase `comparison-block-size` for larger files. Doubling
it doubles the size limit; increasing `request-size` does not change this limit.

Syq fills available request windows with changed ranges from the same file,
leaving queued work for other workers. This can help on high-latency links,
though the result depends on the edits and connection. Both endpoints still
read the full file to compare it. By default, syq builds the updated file beside
the destination and then replaces it. It copies and checks reused destination
bytes before applying changes, skipping final-file blocks already known to
differ. With `--inplace`, changes are written directly to the destination instead.

A later copy can reuse matching bytes from an interrupted copy even if you
change the comparison block size; syq checks them using the new size.
`-B` / `--block-size` are available only in `syq rsync`; native commands use
`--performance-tuning comparison-block-size=SIZE`. Do not combine the two
controls in `syq rsync`.

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

To test the amount of outstanding large-file work over SSH, keep the worker
count and copy method fixed, then vary only the request window:

```sh
bash try-benchmark.sh --yes --mode pull --host server --workload large \
  --tool syq --rounds 1 --size quick -- --no-tcp --performance-tuning workers=1 -v \
  --performance-tuning copy-path=ranges,request-size=1M,pipeline-depth=4
```

Repeat with `pipeline-depth=8` and `16`. With 1 MiB requests, these allow up to
4, 8 and 16 MiB of outstanding range requests per endpoint per worker. They
do not resize TCP or SSH flow-control windows. Compare separately with a run
omitting `--performance-tuning`: long remote ranges normally stream, and an explicit
pipeline depth disables that behavior. The ordinary defaults already allow
4 MiB × 4 requests; a larger application request window may not help.
Use a larger fixed size if the timing notes show the test is too short.

For the small-file workload, vary `batch-files` and `batch-bytes` instead,
such as `--performance-tuning batch-files=512,batch-bytes=4M`. Those are batch
ceilings, and the scheduler may choose smaller batches. `pipeline-depth` does
not multiply small-file batches. After testing these controls, vary
`workers` separately to assess parallelism and its startup cost.

For a direct comparison without the benchmark script, use fresh scratch destinations:

```sh
syq cp data.bin --to host --as /scratch/pipeline.bin --performance-tuning workers=1 -v \
  --performance-tuning copy-path=ranges,request-size=1M,pipeline-depth=4
syq cp data.bin --to host --as /scratch/streaming.bin --performance-tuning workers=1 -v \
  --performance-tuning copy-path=streaming,request-size=1M
```

Streaming can be slower on short or CPU-limited copies. Memory use depends on
request size, worker count, compression, and transport buffering. With
`--resource-limits bandwidth=RATE`, a remote source can send ahead of paced destination writes, so the
limit is an average copy rate, not a strict cap on incoming bursts.

### Batch size and splitting

For macOS local copies, files above the batching limit can use APFS cloning.
The limit is the smallest of the hash block size (normally 4 MiB for `syq cp`),
`batch-bytes`, and the effective `request-size`. Changing these limits changes
which files can be cloned; `syq rsync --block-size` changes the hash block size.

For example, compare small-file batches with:

```sh
syq cp --srcs-in small-files --to server --into /scratch/benchmark-small \
  --performance-tuning workers=1 -v --performance-tuning batch-files=256,batch-bytes=8M
```

Explicit batch controls replace the small-copy shortcut with worker batches.
File and byte limits are ceilings; syq may choose smaller batches. Files larger
than the byte limit use another copy method. With `--resource-limits bandwidth=RATE`, each batch
contains at most one file. Batch controls cannot combine with `copy-path=ranges`
or `copy-path=streaming`; `auto-streaming` accepts them.

Remote new-file copies can batch files up to the smaller of `request-size` and
`batch-bytes`; by default, `request-size` equals the comparison block size.
Increasing these limits can make larger files use whole-file copies held in
memory, which restart from the beginning if interrupted.

`split-min-size` sets the smallest file region an idle worker can take from
another worker. Lower values allow finer sharing; higher values avoid small
assignments. Splits align to hash blocks and need at least twice the minimum
remaining size.

### Average rate and burst patterns

`--resource-limits bandwidth=RATE` caps logical file-data bytes per second across workers, before
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
  --performance-tuning workers=1 --resource-limits bandwidth=1M -v \
  --performance-tuning copy-path=ranges,request-size=4M,bw-pacing=average
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
`--performance-tuning copy-path=auto`.

Record the source data, transport, connections, settings, elapsed time, CPU use,
and peak memory. Check exit status and copied contents. Leave `--resource-limits bandwidth=RATE` unset
when measuring unrestricted throughput.
