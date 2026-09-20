# Performance tuning

`--performance-tuning` overrides syq's automatic choices. To keep automatic
choices within a ceiling, use [resource limits](resource-limits.md) instead.
Leave performance tuning unset for everyday copies. These experimental controls
are available in `syq cp` and `syq rsync`; `syq rm` and `syq clean-partials` accept
only `workers` for filesystem removal.

Performance-tuning keys, accepted values, and behavior may change or be removed
between releases without deprecation. Pin the syq version when a script depends
on these overrides.

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

For S3 streams, see [Descriptor copies](object-storage.md#descriptor-copies)
for buffering and upload-size limits. S3 tuning is not saved between runs.

<a id="s3-streams"></a>

## Remembered connection counts

Syq first looks for a previous successful, measured worker count for the same
source and destination filesystems, direction, transport, and copy settings.
This also works for local copies. Filesystem identities are best-effort hints
reported by the operating system; syq uses the selected roots and marks a run
as mixed if planning observes other filesystems. Unknown or mixed filesystems
can use a route-level hint for remote copies. SSH, encrypted TCP, and plaintext
TCP histories are separate. Destination hints come from existing filesystem
inspection responses; some restricted routes and copies onto existing individual
files do not provide them. Local copies without both filesystem hints use the
normal starting count.

Without a matching history result, remote copies can use the older connection
cache, then fall back to 8 workers over SSH or 16 over TCP. Local copies start
with 32 workers, or 16 when at most two CPUs are available. Startup can reduce
these counts when there is little parallel work. Live tuning continues unless
you fix `workers`.

Supplying `--performance-tuning` bypasses remembered counts and does not publish
a new recommendation. With `--resource-limits workers=N`, syq clamps the starting
count and leaves recommendations unchanged. Bandwidth-limited runs have separate
history matches. Only successful runs with a completed worker-count comparison
can supply a recommendation; a short run's ending count is not treated as an
optimum. A change of data transport during the copy also prevents publication.

The older cache remains at `~/.cache/syq/tuning.json`, in its existing format.
`SYQ_TUNING_CACHE` names another file; an empty value disables both this cache
and the history below. `XDG_CACHE_HOME` changes their parent directory.

## Inspect tuning history

Filesystem copies record a local timeline by default, including short and failed
copies. The history contains opaque endpoint and filesystem identifiers, the
UTC date, copy settings, numerical progress, worker readiness, and tuning
decisions. It does not contain filenames, command lines, file contents, or
Wi-Fi names, and nothing is uploaded. Timing and sizes still reveal activity;
this is performance history, not anonymous data or a complete audit trail.

```sh
syq tuning list
syq tuning show 42
syq tuning show 42 --html > tuning-42.html
syq tuning export 42 > tuning-42.ndjson
syq tuning clear
```

Open the HTML file in a browser to plot worker counts and byte progress, then
select a decision to inspect its evidence. It is a standalone file with no
external scripts. `export` without an ID exports all retained transfers as
NDJSON. These diagnostic records are versioned, but their event details may
evolve; they are separate from the [automation results](automation.md) contract.

Samples include their duration, byte and file progress, worker counts, and
whether the tuner used them. Copies completed by a single control request
record that copy path without a tuning timeline. Warm-up, insufficient remaining work, and partial
final intervals are labeled explicitly. The tuning score adds a credit for
completed files, so it is distinct from byte throughput. A requested count may
still be connecting; activation and acceptance are separate events. Decisions
include the baseline, scores, thresholds, and policy state used at the time.
The remaining-work gate records its scan status, work available, and required
measurement duration in activity units. Repeated waiting states are recorded
when the reason changes.

Descriptor and pipe copies also record their tuning decisions, but do not use
filesystem history to choose their starting count. S3 copies do not currently
record these timelines. For remote-coordinated copies, history belongs to the
machine running the coordinator; run the inspection commands there.

The default file is `~/.cache/syq/tuning.history-v1.sqlite`. When
`SYQ_TUNING_CACHE` selects another file, the history uses that name with its
extension replaced by `.history-v1.sqlite`. `SYQ_TUNING_HISTORY` selects an
independent history file; an empty value disables history and its startup hints
while leaving the older cache available. New database files are private to the
user. SQLite may create adjacent `-wal` and `-shm` files while in use.

`SYQ_TUNING_HISTORY_SIZE` sets a retention target, default `1G`, minimum `16M`.
There is no age expiry for completed transfers. When over budget, completion
removes up to 100 oldest eligible records with their whole timelines. The
current transfer and recently active incomplete records are preserved; disk use
can temporarily exceed the target, and freed pages are reused or reclaimed
incrementally. Increase the target before collecting a large investigation.

Recording is buffered and best effort. Copies still proceed when history cannot
be written. An interrupted process can leave an incomplete timeline; prolonged
write contention can lose events, reported in the history when it becomes
writable again. Clearing history also removes its startup hints; it leaves the
older connection-count cache intact.

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

Syq normally streams remote ranges larger than four ordinary requests
(16 MiB with default settings), with stream blocks of at most 2 MiB. The
threshold follows the effective request size, including bandwidth limits.
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
contents. See [Quick comparison](speed.md#quick-comparison) for the benchmark script.
