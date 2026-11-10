# Performance tuning

`--performance-tuning` overrides syq's automatic choices for troubleshooting
and controlled benchmarks; leave it unset for everyday copies. To keep the
automatic choices under a ceiling instead, use
[resource limits](resource-limits.md). These experimental keys can change or
disappear between releases without deprecation.

`syq cp` and `syq rsync` accept the keys below; for `syq rm` and
`syq clean-partials`, see [Deletion](#deletion).

## Transfer controls

Supply comma-separated `KEY=VALUE` pairs:

```sh
syq cp large-file --to server --as /scratch/benchmark-copy -v \
  --performance-tuning workers=1,copy-path=ranges,request-size=1M,pipeline-depth=8
```

| Key | Default | Accepted values |
|---|---|---|
| `workers` | Automatic | 1 through 65536 filesystem workers, fewer when there is less work |
| `comparison-block-size` | 4 MiB; 64 KiB for replaced files up to 64 MiB; automatic for larger files between machines (see [Scattered edits](#scattered-edits-in-existing-files)) | 64 KiB through 64 MiB; filesystem copies only. Comparison can use up to 64 MiB of memory per worker |
| `request-size` | Automatic, normally up to 4 MiB; at most 2 MiB for streaming | 512 bytes through 64 MiB |
| `pipeline-depth` | 4; automatic when comparing replaced files over 64 MiB | 1 through 64 outstanding range requests per endpoint per worker |
| `copy-path` | `auto` | `auto`, `ranges`, `streaming`, `auto-streaming`; see below |
| `batch-files` | Up to 2048 | 1 through 4096 files per worker batch |
| `batch-bytes` | 16 MiB | 512 bytes through 64 MiB per worker batch |
| `split-min-size` | 32 MiB | 1 byte through 1 GiB: the smallest part of a file an idle worker can take over from another |
| `bw-pacing` | `125ms` | An integer interval from `1ms` through `10s`, or `average`; see below |

<a id="streaming-and-request-windows"></a>

`copy-path=auto` takes shortcuts where they apply, such as local clones and
small-file batches, and streams long remote ranges. `ranges` copies every file
in range requests without those shortcuts. The experimental `streaming`
streams every range without shortcuts, and `auto-streaming` keeps the
shortcuts and streams all other ranges.

<a id="average-rate-and-burst-patterns"></a>

`bw-pacing` needs a nonzero `--resource-limits bandwidth=RATE` and applies to
local and descriptor copies; SSH and TCP copies ignore it, and S3 copies
reject it. An interval sends smaller requests that far apart, while `average`
waits for each request's byte budget, so data can arrive in bursts.

Sizes accept `K`, `M`, and `G`, using powers of 1024. Setting a request, block,
pipeline, split, or batch value also stops syq from adjusting it during the
copy, which keeps comparisons controlled.

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
most sixteen simultaneous data requests across them. Each count you set is
fixed, and unused slots can stay idle; to let syq choose counts under these
ceilings, pass the same keys to `--resource-limits` instead. Part size grows
when needed to stay within S3's limit of 10,000 parts per upload. For retries,
see [`--s3-retries`](object-storage.md#retries).

<a id="s3-streams"></a>

For S3 streams, see [Descriptor copies](object-storage.md#descriptor-copies).

## Deletion

Removal and pruning adjust their concurrency automatically. To fix it, use
`--performance-tuning workers=N` with `syq rm` and `syq clean-partials`, or
`s3-requests=N` for S3 removal; in a copy, `s3-requests` also applies to S3
pruning. Filesystem pruning always tunes its own workers.

## Remembered connection counts

Syq starts each filesystem copy from the number of workers, and so of
connections, that worked for earlier copies of the same kind, then keeps
adjusting. `--performance-tuning workers=N`
bypasses the remembered count, and `--resource-limits workers=N` caps it. To
turn off both the history and remembered counts, set `SYQ_TUNING_CACHE` to an
empty value.

## Inspect tuning history

To see why syq chose its worker counts, inspect the local timeline that each
filesystem copy records:

```sh
syq tuning-cache list
syq tuning-cache show 42
syq tuning-cache show 42 --html > tuning-42.html
syq tuning-cache export 42 > tuning-42.ndjson
syq tuning-cache clear
```

The HTML file plots worker counts and progress with the evidence for each
decision, and `export` without an ID exports every recorded transfer. These
records can change between versions and are not part of the
[automation results](automation.md) contract. Clearing history also resets
remembered counts. When a server coordinates a copy, the history is on that
server; S3 copies record none.

The history holds opaque endpoint, filesystem, and network-address
identifiers, the UTC date, copy settings, progress numbers, and tuning
decisions, but no filenames, command lines, file contents, or Wi-Fi names, and
nothing is uploaded. Timing and sizes still reveal activity, so it isn't
anonymous. See [Environment](environment.md#other-variables) for the file's
location and size.

## Filesystem tuning examples

<a id="recording-a-comparison"></a>

Compare settings on disposable destinations, restoring the same starting
destination before each run. With overrides, `-v` reports the settings in
effect. See [Quick comparison](speed.md#quick-comparison) for a benchmark
script.

### Compare block reuse with full replacement

To measure what [block reuse](reference.md#choose-a-transfer-strategy) costs
and saves, run the same copy with `--transfer-strategy aligned-block` and with
`whole-file`, adding `--performance-tuning copy-path=ranges` to both so that
copy shortcuts don't hide the difference. Block reuse saves network traffic,
but the destination still writes a complete new file unless its filesystem
supports reflinks.

### Scattered edits in existing files

Smaller comparison blocks send less data around scattered edits, and larger
ones need fewer requests. For a replaced file over 64 MiB copied between
machines, syq adjusts the block size as the copy runs, between 64 KiB and
4 MiB, or at most 256 KiB when copying from a server to this machine. To
compare with one fixed size instead, for example to see what block size costs
on your link:

```sh
syq cp --srcs-in source --to host --into destination \
  --performance-tuning comparison-block-size=64K,request-size=4M
```

Set `request-size` too, since it otherwise follows the comparison block size.
In `syq rsync`, `-B` / `--block-size` sets the comparison block size. Setting
`request-size`, `pipeline-depth` or `split-min-size` also fixes the block:
4 MiB unless you set another, or `request-size` if that is smaller.

### Batch size and splitting

Tune small-file batches with `batch-files` and `batch-bytes`:

```sh
syq cp --srcs-in small-files --to server --into /scratch/benchmark-small \
  --performance-tuning workers=1,batch-files=256,batch-bytes=8M -v
```

Larger batches hold more data in memory, and an interrupted batch restarts its
files from the beginning. Lower `split-min-size` values let idle workers share
large files more finely; higher values mean fewer handoffs.
