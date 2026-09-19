# Performance tuning

`--performance-tuning` overrides syq's automatic choices. To keep automatic
choices within a ceiling, use [resource limits](resource-limits.md) instead.
Leave performance tuning unset for everyday copies. These experimental controls
are available in `syq cp` and `syq rsync`; `syq rm` and `syq clean-partials` accept
only `workers` for filesystem removal.

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
| `workers` | Automatic | 1 through 65536 filesystem workers; route-specific receiver limits also apply |
| `comparison-block-size` | 4 MiB | 64 KiB through 64 MiB; filesystem copies only |
| `request-size` | Hash block size (normally 4 MiB) for ordinary requests; at most 2 MiB for streaming | 512 bytes through 64 MiB |
| `pipeline-depth` | 4 | 1 through 64 outstanding range requests per endpoint per worker |
| `copy-path` | `auto` | `auto`, `ranges`, or experimental `streaming` / `auto-streaming` |
| `batch-files` | Up to 2048, sharing queued files across active workers | 1 through 4096 files per worker batch |
| `batch-bytes` | 16 MiB | 512 bytes through 64 MiB per worker batch, including the first file |
| `split-min-size` | 32 MiB, at least two hash blocks | 1 byte through 1 GiB, raised to at least two hash blocks |
| `bw-pacing` | `125ms` when capped | `average`, or an integer interval from `1ms` through `10s`; requires a nonzero `--resource-limits bandwidth=RATE` |

Sizes accept `K`, `M`, and `G`, using powers of 1024. Unknown keys, repeated
keys, and out-of-range values fail the command. Overrides apply to the remote
coordinator too and are not saved.

## S3 copies

Use these keys for `syq cp` with S3 endpoints.

| Key | Default | Accepted values / meaning |
|---|---|---|
| `s3-max-concurrent-requests` | Automatic | 1–65536 simultaneous data requests across objects; excludes metadata requests and idle sockets |
| `s3-max-concurrent-objects` | Automatic | 1–65536 objects in progress, including preparation and finalization |
| `s3-max-concurrent-parts-per-object` | Automatic | 1–1024 simultaneous parts or ranges per object |
| `s3-part-size` | Automatic | 5 MiB–5 GiB per upload part or download range |
| `s3-retries` | `10` | 0–100 retries for transient failures and throttling; 0 disables retries |

The concurrency limits are nested. For example:

```sh
syq cp data --to s3://backups --into archive \
  --performance-tuning s3-max-concurrent-objects=4,s3-max-concurrent-parts-per-object=8,s3-max-concurrent-requests=16
```

This allows four objects in progress and up to eight parts per object, with at
most sixteen simultaneous data requests across them. These performance-tuning
values fix the available slots and disable automatic adjustment of each
specified count; unused slots can remain idle. To let syq
choose counts within these ceilings instead, pass the same keys through
`--resource-limits`. A count cannot be specified in both groups.

Part size grows when needed to stay within 10,000 upload parts. For server-side
copies, an explicit part size also selects the multipart threshold, capped at
5 GiB. Without an explicit part limit, server-side copies can use the shared
request budget's full tuning range.

See [S3 parallelism](object-storage.md#s3-options) for memory use and buffering
limits. S3 tuning is not saved between runs.

<a id="s3-streams"></a>

## Remembered connection counts

Remote copies start from the last learned count for the same route, direction,
and transport, or from 8 workers over SSH and 16 over TCP. Successful copies
update the cache after comparing enough worker counts. Short copies may finish
before syq learns a better count.

The cache is `~/.cache/syq/tuning.json`; `XDG_CACHE_HOME` changes its parent.
`SYQ_TUNING_CACHE` names another file, or disables the cache when empty.
Supplying `--performance-tuning` bypasses the cache. With
`--resource-limits workers=N`, syq starts from the remembered count or the
ceiling, whichever is lower, and leaves the cache unchanged. A bandwidth limit
alone still reads and updates it.
Live tuning continues unless you fix `workers`. Use `-vv` to see the starting count.

## Filesystem tuning examples

Use disposable destinations when comparing settings. Larger requests and deeper
pipelines can increase memory use. `copy-path=ranges` disables small-file batches
and whole-file shortcuts, including local kernel copying and APFS cloning.

### Scattered edits in existing files

Smaller comparison blocks can reduce the data sent for scattered edits, at the
cost of more hashes and requests:

```sh
syq cp --srcs-in source --to host --into destination \
  --performance-tuning comparison-block-size=64K,request-size=4M
```

Set `request-size` too: it otherwise follows the comparison block size.
At 64 KiB, files must be smaller than 130 GiB or comparison fails. Increase
`comparison-block-size` for larger files; doubling it doubles that limit.
Both endpoints still read the full file to compare it.

In `syq rsync`, `-B` / `--block-size` selects the comparison block size.
Do not combine it with `comparison-block-size`.

### Streaming and request windows

Syq normally streams remote ranges above 16 MiB, with blocks of at most 2 MiB.
`copy-path=streaming` forces streaming and disables whole-file and small-file
shortcuts. `copy-path=auto-streaming` keeps those shortcuts and streams the
remaining ranges.

An explicit `request-size` also sets the streaming block size; bandwidth and
receiver limits may reduce it. Setting `pipeline-depth` disables automatic
streaming and cannot combine with either forced streaming mode.

To compare pipeline depths, hold the worker count and request size fixed:

```sh
syq cp data.bin --to host --as /scratch/pipeline.bin --performance-tuning workers=1 -v \
  --performance-tuning copy-path=ranges,request-size=1M,pipeline-depth=4
```

Repeat with `pipeline-depth=8` and `16`, using a fresh destination each time.
These allow up to 4, 8, and 16 MiB of outstanding requests per endpoint per worker.
Compare with the defaults too; larger windows may add memory use without improving speed.

### Batch size and splitting

Tune small-file batches with `batch-files` and `batch-bytes`:

```sh
syq cp --srcs-in small-files --to server --into /scratch/benchmark-small \
  --performance-tuning workers=1,batch-files=256,batch-bytes=8M -v
```

Explicit batch settings replace the small-copy shortcut with worker batches.
With a bandwidth cap, each batch contains at most one file. Batch controls
cannot combine with `copy-path=ranges` or `copy-path=streaming`;
`auto-streaming` accepts them.

Remote new-file copies can batch files up to the smaller of `request-size` and
`batch-bytes`. Larger limits allow more data to be held in memory; interrupted
whole-file copies restart from the beginning. On macOS, files above the batching
limit can use APFS cloning. That limit is the smallest of the comparison block
size, `batch-bytes`, and `request-size`.

`split-min-size` controls how small a region an idle worker can take from another
worker. Lower values allow finer sharing; higher values reduce assignments.
Splits align to comparison blocks and need twice the minimum remaining size.

### Average rate and burst patterns

With a [bandwidth cap](resource-limits.md), `bw-pacing` controls when data is sent:

- `125ms` (default): send smaller requests at regular intervals. The first
  request starts immediately, so short copies can exceed the average rate.
- `average`: wait for each request's byte budget before sending it. A 2 MiB
  request at 1 MiB/s waits about two seconds, then can arrive in a burst.

Streaming and transport buffering can also produce bursts. Restricted receivers
apply their authorized rate and request-size limits.

### Recording a comparison

Use the same reporting options and fresh destinations for each run.
Prefer `-v`; `--stats` can change which copy optimizations run.
With overrides, `-v` reports effective settings and a final
`syq: tuning observed:` diagnostic. Check elapsed time, exit status, and copied
contents. See [Speed](speed.md#quick-comparison) for the benchmark script.
