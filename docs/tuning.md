# Performance tuning

`--performance-tuning` overrides syq's automatic choices. To keep automatic
choices within a ceiling, use [resource limits](resource-limits.md) instead.
Leave performance tuning unset for everyday copies: these experimental
controls are for troubleshooting and controlled benchmarks. Their keys, values,
and behavior may change or be removed between releases without deprecation,
so pin the syq version when a script depends on them.

`syq cp` and `syq rsync` accept the keys below. For removal, `syq rm` accepts
`workers` for filesystems or `s3-requests` for S3, and `syq clean-partials`
accepts `workers`.

## Transfer controls

Supply comma-separated `KEY=VALUE` pairs:

```sh
syq cp large-file --to server --as /scratch/benchmark-copy \
  --performance-tuning workers=1 -v \
  --performance-tuning copy-path=ranges,request-size=1M,pipeline-depth=8
```

<a id="average-rate-and-burst-patterns"></a>

| Key | Default | Accepted values |
|---|---|---|
| `workers` | Automatic | 1 through 65536 filesystem workers, fewer when there is less work |
| `comparison-block-size` | 4 MiB; 64 KiB for replaced files up to 64 MiB | 64 KiB through 64 MiB; filesystem copies only |
| `request-size` | Automatic, normally up to 4 MiB; at most 2 MiB for streaming | 512 bytes through 64 MiB |
| `pipeline-depth` | 4 | 1 through 64 outstanding range requests per endpoint per worker |
| `copy-path` | `auto` | `auto` takes shortcuts where they apply, such as local clones and small-file batches, and streams long remote ranges; `ranges` copies every file in range requests without those shortcuts; experimental `streaming` streams every range without the shortcuts; experimental `auto-streaming` keeps the shortcuts and streams every other range |
| `batch-files` | Up to 2048 | 1 through 4096 files per worker batch |
| `batch-bytes` | 16 MiB | 512 bytes through 64 MiB per worker batch |
| `split-min-size` | 32 MiB | 1 byte through 1 GiB: the smallest part of a file an idle worker can take over from another |
| `bw-pacing` | `125ms` | Requires a nonzero `--resource-limits bandwidth=RATE`. Chooses how local, descriptor, and receiver-approved copies pace file data: an integer interval from `1ms` through `10s` sends smaller requests at that spacing, and `average` waits for each request's byte budget, so data can arrive in bursts. Ordinary SSH and TCP copies ignore it; S3 copies reject it |

Sizes accept `K`, `M`, and `G`, using powers of 1024. Unknown keys, repeated
keys, and out-of-range values fail the command. Explicit request, block,
pipeline, split, and batch settings also turn off the matching automatic
adjustments during the copy, which keeps comparisons controlled. Batch
controls cannot combine with
`copy-path=ranges` or `streaming`, and `pipeline-depth` cannot combine with
either streaming mode. Overrides also apply when a server coordinates the copy,
and are not saved.

## S3 copies

Use these keys for `syq cp` with S3 endpoints:

| Key | Default | Accepted values / meaning |
|---|---|---|
| `s3-requests` | Automatic | 1–65536 simultaneous data requests across objects; excludes metadata requests and idle sockets |
| `s3-objects` | Automatic | 1–65536 objects in progress, including preparation and finalization |
| `s3-parts-per-object` | Automatic | 1–1024 simultaneous parts or ranges per object |
| `s3-part-size` | 16 MiB for uploads, 8 MiB for downloads, 256 MiB for copies between buckets; adjusted for some providers and fast links | 5 MiB–5 GiB per upload part or download range. Larger parts take fewer requests; smaller ones let one object use more requests at once and resend less after a failure |

The concurrency limits are nested. For example:

```sh
syq cp data --to s3://backups --into archive \
  --performance-tuning s3-objects=4,s3-parts-per-object=8,s3-requests=16
```

This allows four objects in progress and up to eight parts per object, with at
most sixteen simultaneous data requests across them. Each count you set here is
fixed, and unused slots can remain idle. To let syq choose counts within these
ceilings instead, pass the same keys through `--resource-limits`; a count
cannot be specified in both. Part size grows when needed to stay within
S3's limit of 10,000 parts per upload.

<a id="s3-streams"></a>

For S3 streams, see [Descriptor copies](object-storage.md#descriptor-copies).
`--s3-retries` sets how many times each request is retried; see
[Retries](object-storage.md#retries).

## Deletion

`syq rm`, `syq clean-partials`, and pruning after a copy adjust their
concurrency automatically while they run. For `rm` and `clean-partials`,
`--performance-tuning workers=N` fixes the filesystem worker count. For S3
removal, `s3-requests=N` fixes the request count; in a copy, the S3 request
setting also applies to S3 pruning. Filesystem pruning tunes its own workers.

## Remembered connection counts

Syq remembers useful starting worker counts from successful filesystem copies
of the same kind and keeps adjusting as the next copy runs.

`--performance-tuning workers=N` bypasses the remembered count, and
`--resource-limits workers=N` caps it. Set `SYQ_TUNING_CACHE` to an empty value
to turn off history and remembered counts.

## Inspect tuning history

Filesystem copies record a local timeline of their tuning decisions. The
history contains opaque endpoint, filesystem, and network-address identifiers,
the UTC date, copy settings, numerical progress, and tuning decisions. It does
not contain filenames, command lines, file contents, or Wi-Fi names, and
nothing is uploaded. Timing and sizes still reveal activity; this is
performance history, not anonymous data or a complete audit trail.

```sh
syq tuning-cache list
syq tuning-cache show 42
syq tuning-cache show 42 --html > tuning-42.html
syq tuning-cache export 42 > tuning-42.ndjson
syq tuning-cache clear
```

Open the HTML file in a browser to plot worker counts and byte progress and
inspect the evidence for each decision. `export` without an ID exports all
retained transfers as NDJSON. These diagnostic records may change between
versions; they are separate from the [automation results](automation.md)
contract. Clearing history also resets remembered starting counts.

S3 copies do not record timelines. When a server coordinates a copy, the
history is on that server; run the inspection commands there.

See [Environment](environment.md#other-variables) for the history file's
location and size.

## Filesystem tuning examples

<a id="recording-a-comparison"></a>

Use disposable destinations when comparing settings, and restore the same
initial destination before each run. With overrides, `-v` reports the effective
settings and a final `syq: tuning observed:` line. See
[Quick comparison](speed.md#quick-comparison) for a benchmark script.

### Compare block reuse with full replacement

To measure what [block reuse](reference.md#choose-a-transfer-strategy) costs
and saves, compare the two strategies without copy shortcuts, keeping worker
counts, request sizes, and cache preparation identical:

```sh
syq cp --srcs-in source --into destination \
  --performance-tuning copy-path=ranges --transfer-strategy aligned-block
syq cp --srcs-in source --into destination \
  --performance-tuning copy-path=ranges --transfer-strategy whole-file
```

Block reuse saves network traffic, but the destination still writes a complete
new file unless its filesystem supports reflinks. Comparison can use up to
64 MiB of memory per worker.

### Scattered edits in existing files

Smaller comparison blocks can reduce the data sent for scattered edits, at the
cost of more hashes and requests:

```sh
syq cp --srcs-in source --to host --into destination \
  --performance-tuning comparison-block-size=64K,request-size=4M
```

Set `request-size` too: it otherwise follows the comparison block size.
Both endpoints still read the full file to compare it. In `syq rsync`,
`-B` / `--block-size` selects the comparison block size; do not combine it
with `comparison-block-size`.

<a id="streaming-and-request-windows"></a>

### Pipeline depth

To compare pipeline depths, hold the worker count and request size fixed:

```sh
syq cp data.bin --to host --as /scratch/pipeline.bin --performance-tuning workers=1 -v \
  --performance-tuning copy-path=ranges,request-size=1M,pipeline-depth=4
```

Repeat with `pipeline-depth=8` and `16`, and compare with the defaults too;
larger windows may add memory use without improving speed.

### Batch size and splitting

Tune small-file batches with `batch-files` and `batch-bytes`:

```sh
syq cp --srcs-in small-files --to server --into /scratch/benchmark-small \
  --performance-tuning workers=1,batch-files=256,batch-bytes=8M -v
```

Larger batches hold more data in memory, and an interrupted batch restarts its
files from the beginning. Lower `split-min-size` values let idle workers share
large files more finely; higher values mean fewer handoffs.
