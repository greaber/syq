# Tuning options

Syq adjusts performance automatically. These controls are for developers and
for investigating copies where the defaults perform poorly. These experimental controls appear in `--help-all`; their keys and
bounds may change between releases.

`--connections N` (or `-j N`) fixes the connection count and disables automatic
adjustment. In `syq rsync`, use `--syq-connections N`. Use the same count when
comparing other tuning settings. Leave it unset for everyday copies.

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
including local kernel copying and APFS cloning. Matching data can still be
skipped or reused.
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

For macOS local copies, files above the batching limit can use APFS cloning.
The limit is the smallest of the hash block size (normally 4 MiB for `syq cp`),
`batch-bytes`, and the effective `request-size`. Changing these limits changes
which files can be cloned; `syq rsync --block-size` changes the hash block size.

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

