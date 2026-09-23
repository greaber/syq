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

Use these keys for `syq cp` with S3 endpoints. `workers` applies only to
filesystem copies; use `s3-requests` for the shared S3 data-request count.

| Key | Default | Accepted values / meaning |
|---|---|---|
| `s3-requests` | Automatic | 1–65536 simultaneous data requests across objects; excludes metadata requests and idle sockets |
| `s3-objects` | Automatic | 1–65536 objects in progress, including preparation and finalization |
| `s3-parts-per-object` | Automatic | 1–1024 simultaneous parts or ranges per object |
| `s3-part-size` | Automatic | 5 MiB–5 GiB per upload part or download range |
| `s3-retries` | `10` | 0–100 retries for transient failures and throttling; 0 disables retries |

The concurrency limits are nested. For example:

```sh
syq cp data --to s3://backups --into archive \
  --performance-tuning s3-objects=4,s3-parts-per-object=8,s3-requests=16
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

Large unfiltered prefix copies, current-object removals, and destination scans
for pruning can list subtrees concurrently. Discovery may use extra LIST
requests; selectors still name literal keys and prefixes. For copies,
`--performance-tuning s3-parts-per-object=N` also caps unfiltered
discovery; setting `N=1` keeps flat pagination. If a policy denies discovery, these operations retry with flat
pagination at the original prefix.

<a id="s3-streams"></a>

## Remembered connection counts

Syq chooses starting worker counts from measurements recorded by successful
filesystem copies, then continues adjusting while copying. It matches history
to the route, filesystems, transport, and copy settings when available. Starting
choices are computed when a copy begins; earlier saved recommendations are not
used. Short copies can contribute measurements without completing a tuning
comparison. A starting choice is not a fixed limit or a promise of the best
speed for a different workload. Startup learning reads per-worker measurement totals recorded during each copy;
the detailed timeline remains available for inspection. Histories without those
totals do not determine starting counts. Startup inference requires measurements
at two or more worker counts. Capped runs can contribute those comparisons:
improvement at the highest tested count supports starting at least that high,
without treating the cap as evidence against more workers. Fixed-count runs do
not provide comparisons for startup learning.

On macOS and Linux, remote-copy hints also distinguish local networks using
available default-router hardware addresses, without requesting Wi-Fi location
permission. These are hints about the network around the machine running syq;
they cannot detect changes upstream of a phone hotspot. Linux currently reads
IPv4 routers; macOS also reads IPv6 routers. If the network cannot be identified,
syq uses its existing route and filesystem matches. Hints without network
context remain available for that fallback; a known network starts its own
history. Local-copy hints are unchanged. A change of transport or observed
network context during a copy prevents reusing its measurements for the initial path.

`--performance-tuning` bypasses automatic starting choices.
`--resource-limits workers=N` caps the starting count and subsequent exploration.

The older `~/.cache/syq/tuning.json` file is left untouched for older binaries;
its saved counts are no longer read or updated. `SYQ_TUNING_CACHE` still sets
the base path for history; an empty value disables history and learning.
`XDG_CACHE_HOME` changes the default parent directory.

Syq can keep idle connections ready for later tuning changes. These connections
and their helper processes still use resources, so the active worker count is
not a count of open connections.

## Inspect tuning history

Filesystem copies record a local timeline by default, including short and failed
copies. The history contains opaque endpoint and filesystem identifiers, the
UTC date, copy settings, numerical progress, worker readiness, and tuning
decisions. It does not contain filenames, command lines, file contents, or
Wi-Fi names, and nothing is uploaded. Timing and sizes still reveal activity;
this is performance history, not anonymous data or a complete audit trail.

TCP preflight events record opaque candidate-address identifiers, reported link
speeds (`null` when unknown), reachability (`null` when the probe had not finished
at selection time), and selection. Selected addresses are eligible for data
connections; they may not all carry data. Reported speeds are interface hints,
not measured throughput. These observations do not change startup-hint reuse.

```sh
syq tuning-cache list
syq tuning-cache show 42
syq tuning-cache show 42 --html > tuning-42.html
syq tuning-cache export 42 > tuning-42.ndjson
syq tuning-cache clear
```

Open the HTML file in a browser to plot worker counts and byte progress, then
select a decision to inspect its evidence. It is a standalone file with no
external scripts. `export` without an ID exports all retained transfers as
NDJSON. These diagnostic records are versioned, but their event details may
evolve; they are separate from the [automation results](automation.md) contract.

The timeline distinguishes requested workers from workers ready to copy, and
shows which measurements informed each decision. Copies completed by a single
control request record that copy path without a tuning timeline.

Descriptor and pipe copies also record their tuning decisions, but do not use
filesystem history to choose their starting count. S3 copies do not currently
record these timelines. For remote-coordinated copies, history belongs to the
machine running the coordinator; run the inspection commands there.

The default file is `~/.cache/syq/tuning.history-v1.sqlite`. When
`SYQ_TUNING_CACHE` selects another file, the history uses that name with its
extension replaced by `.history-v1.sqlite`. `SYQ_TUNING_HISTORY` selects an
independent history file; an empty value disables history and learning. New database files are private to the
user. SQLite may create adjacent `-wal` and `-shm` files while in use.

`SYQ_TUNING_HISTORY_SIZE` sets how much history to keep, default `128M`, minimum
`16M`. History may be removed when this size target is exceeded.

Recording is best effort: an interrupted transfer or a storage error can leave
gaps in the history. Copies still proceed when history cannot be saved.
Clearing history removes the measurements used for startup choices; it leaves
the older connection-count cache intact.

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
