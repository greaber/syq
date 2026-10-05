# Performance tuning

`--performance-tuning` overrides syq's automatic choices. To keep automatic
choices within a ceiling, use [resource limits](resource-limits.md) instead.
Leave performance tuning unset for everyday copies. These experimental controls
are available in `syq cp` and `syq rsync`. For removal, `syq rm` accepts
`workers` for filesystems or `s3-requests` for S3; `syq clean-partials` accepts
`workers`.

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
| `comparison-block-size` | 4 MiB; 64 KiB for replaced files up to 64 MiB | 64 KiB through 64 MiB; filesystem copies only |
| `request-size` | Automatic remote requests up to the hash block size (normally 4 MiB); at most 2 MiB for streaming | 512 bytes through 64 MiB |
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

Each request has its own retry allowance. Retries wait longer each time, with
randomized delays to spread out concurrent retries. Requests keep their
concurrency slots while waiting, so throttling slows new work too. With the
default budget a single request can keep retrying for a minute or more. If 8
requests in a row fail after all their retries, each with no connection, a
timeout, or a server error or throttling response, `syq cp` and `syq rm` stop
instead of trying the remaining objects; rerun the command once the service is
available.

For bulk deletion, syq retries only keys with temporary errors, up to
`s3-retries` times during pruning or 10 times with `syq rm`. This count is
separate from retries of the batch request itself.

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

## Deletion

`syq rm`, `syq clean-partials`, and pruning after a copy adjust deletion
concurrency using completed entries per second. Filesystem deletion runs on
the machine holding the target filesystem. S3 deletion adjusts concurrent
requests while keeping supported batch requests. These measurements are
separate from copying file contents and are not saved between runs. When a
higher deletion count brings no clear throughput gain, syq returns to the
previous count. It keeps a lower count when that improves throughput, such as
when excess workers contend for the same filesystem locks.

For `rm` and `clean-partials`, `--performance-tuning workers=N` fixes the
filesystem worker count. For S3 removal, `--performance-tuning s3-requests=N`
fixes the request count. For copies, the S3 request override and ceiling also
apply during S3 pruning.
Filesystem copy-worker settings apply to copying; filesystem pruning tunes its
own workers. Filesystem deletion finishes children before removing their parent
directories.

<a id="s3-streams"></a>

## Remembered connection counts

Syq remembers useful starting worker counts from successful filesystem copies
and continues adjusting as the next copy runs. History is matched to the route,
filesystems, transport, and copy settings when that information is available.
A remembered count is a starting point, not a fixed limit or a promise of the
best speed for a different workload.

On macOS and Linux, remote-copy hints also distinguish local networks using
available default-router hardware addresses, without requesting Wi-Fi location
permission. These are hints about the network around the machine running syq;
they cannot detect changes upstream of a phone hotspot. Linux currently reads
IPv4 routers; macOS also reads IPv6 routers. If the network cannot be identified,
syq uses its existing route and filesystem matches. Hints without network
context remain available for that fallback; a known network starts its own
history. Local-copy hints are unchanged. A change of transport or observed
network context during a copy prevents saving a new hint for its initial path.

`--performance-tuning` bypasses automatic starting choices.
`--resource-limits workers=N` caps the starting count and subsequent exploration.

`SYQ_TUNING_CACHE` sets the base path for history; an empty value disables
history and remembered starts. An absolute `XDG_CACHE_HOME` changes the default
parent directory.

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
independent history file; an empty value disables history and remembered starts.
New database files are private to the user. SQLite may create adjacent `-wal`
and `-shm` files while in use.

`SYQ_TUNING_HISTORY_SIZE` sets how much history to keep, default `10M`, minimum
`10M`. History may be removed when this size target is exceeded.

Recording is best effort: an interrupted transfer or a storage error can leave
gaps in the history. Copies still proceed when history cannot be saved.
Clearing history resets remembered starting counts.

## Filesystem tuning examples

Use disposable destinations when comparing settings. Larger requests and deeper
pipelines can increase memory use. `copy-path=ranges` disables small-file batches
and whole-file shortcuts, including local kernel copying and APFS cloning.

### Compare block reuse with full replacement

Choose `--transfer-strategy=aligned-block` or `whole-file` to compare block reuse
with full replacement. See [transfer strategies](reference.md#choose-a-transfer-strategy)
for defaults and interactions.

```sh
syq cp --srcs-in source --into destination \
  --transfer-strategy aligned-block
```

Size/time quick checks still skip completed files. Explicit `--hash` (or rsync
`--checksum`) still compares contents even when reuse is disabled; if copying
is required, the final destination contributes no reusable blocks. Expected
hashes, payload checks and publication-recovery checks stay in effect. Partial-file resume remains enabled
in every mode: matching bytes from interrupted copies can still be reused,
even with `whole-file`. The setting controls reuse of the final destination, not partials.

With block reuse enabled, a replaced file of up to 64 MiB is compared before
any of its contents are sent, together with other files. (The default
strategy compares only files whose destination has the same size.) The receiving side
hashes the file it would replace in 64 KiB blocks, the sending side reads the
source once and sends only the blocks that differ, and the receiving side
builds the new file from those and its own matching blocks, which must be
unchanged since they were hashed. A file whose contents already match is kept, and only
its metadata is updated. Comparing a batch of files costs about one round trip,
however many files it holds.

Explicit `--hash` comparisons of files up to 64 MiB use the same batches;
without block reuse, they only decide whether a file is unchanged, and a file
that differs is then copied whole. Same-machine copies without block reuse,
larger files and `--inplace` updates are compared one file at a time, in
comparison blocks of 4 MiB by default. For
those, a difference near the end can add almost a full extra read of both
files before copying. An output already being written by the current run
resumes before that probe. Leftover partials from earlier runs do not bypass
checking whether the completed file already matches, and a file with leftover
partials takes this path so that it can resume from them.

Changed files still use atomic replacement unless `--inplace` is selected.
Reflinks can reduce replacement writes on supporting filesystems; otherwise the
replacement must include every byte, including matching blocks. Comparison can
use up to 64 MiB of destination buffers per worker (up to 32 MiB at default
request settings), in addition to source payload buffers. Increasing the worker
count increases this memory cost.

This setting does not select a sequential writer. To isolate comparison and
reuse costs while keeping range transfers, compare
`--performance-tuning=copy-path=ranges --transfer-strategy=aligned-block`
with `--performance-tuning=copy-path=ranges --transfer-strategy=whole-file`.
Restore the same initial destination before each run and keep worker counts,
request sizes and cache preparation identical. Leave `--inplace` unchanged too:
normal staging must populate a new file, whereas in-place updates can leave
matching destination ranges untouched.

### Scattered edits in existing files

Smaller comparison blocks can reduce the data sent for scattered edits, at the
cost of more hashes and requests:

```sh
syq cp --srcs-in source --to host --into destination \
  --performance-tuning comparison-block-size=64K,request-size=4M
```

Set `request-size` too: it otherwise follows the comparison block size.
Both endpoints still read the full file to compare it. Most staged updates and
partial resume compare bounded windows; their hash memory does not grow with
file size. Bandwidth-limited pulls and relays compare before requesting source
data, so matching blocks do not consume the bandwidth budget. These copies and
explicit whole-file comparisons (protected-existing-file policies, in-place
reuse, and `--hash` other than for same-machine copies without block reuse,
which compare in bounded windows) have a hash-response limit: at 64 KiB, files
must be smaller than 130 GiB. Increasing `comparison-block-size` increases that
limit proportionally.
A smaller effective request size, including
bandwidth pacing, also reduces staged comparison granularity.

In `syq rsync`, `-B` / `--block-size` selects the comparison block size.
Do not combine it with `comparison-block-size`.

### Streaming and request windows

Syq normally streams remote ranges larger than four ordinary requests
(16 MiB with default settings), with stream blocks of at most 2 MiB. The
threshold follows the request-size ceiling, including logical-byte bandwidth
limits, rather than the smaller requests chosen during a copy.
`copy-path=streaming` forces streaming and disables whole-file and small-file
shortcuts. `copy-path=auto-streaming` keeps those shortcuts and streams the
remaining ranges.

Ordinary remote requests adapt to each worker's observed completion times.
Slow workers issue smaller requests and allow idle workers to take smaller
unread parts of their files, including while checking connection delay. A new
worker starts with the size suggested by the work it takes over, then adapts to
its own connection. Workers with measurements already use their own size.
Connection-delay checks help requests grow again when competing traffic changes
the delay. A worker skips periodic checks while it reaches the request-size
ceiling without any slow replies; after a slow reply, checks remain enabled.
Already-issued requests must still finish or fail. Local requests, streaming
blocks, and comparison blocks keep their existing sizes. Explicit
`request-size`, `comparison-block-size`, `--block-size`, `pipeline-depth`, or
`split-min-size` settings disable ordinary request adaptation for controlled
comparisons.

Staged block reuse and partial resume use bounded comparison requests in every
copy-path mode, including `streaming`.

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

By default, workers adjust the size of small-file request groups to their own
observed completion times. Slow workers issue smaller groups, leaving unread
files available to others. Workers occasionally recheck connection delay after
slow replies and on connections whose latency allowance exceeds 250 ms. The
first periodic check waits 30 seconds; a large drop in the group budget can
trigger an earlier check. These checks briefly pause new requests on that worker
and help it recover when competing traffic changes the delay. Default source
read-ahead also allows for the group's expected completion time, at least
250 ms, before treating a source reply as stalled. A group still contains whole
files: one slow file can exceed the estimate, and requests already sent must
finish or fail.
Explicit `batch-files`, `batch-bytes`, `request-size`, or `pipeline-depth` settings
disable this adjustment for controlled comparisons.

Explicit batch settings replace the small-copy shortcut with worker batches.
With logical-byte bandwidth pacing, each batch contains at most one file.
Ordinary SSH and TCP copies keep multi-file batches while pacing compressed
transport bytes. Batch controls
cannot combine with `copy-path=ranges` or `copy-path=streaming`;
`auto-streaming` accepts them.

Remote copies batch new files up to the smaller of `request-size` and
`batch-bytes`; on Linux, same-machine copies without `--hash` or a bandwidth cap
batch files up to 64 KiB. Larger limits allow more data to be held in memory;
interrupted whole-file copies restart from the beginning. A file that already exists at the destination joins a batch when syq
replaces it without reading it first, as same-machine copies do by default.
With block reuse or `--hash`, replaced files of up to 64 MiB are compared in
batches as described above, except `--hash` comparisons in same-machine copies
without block reuse. Those, larger files with block reuse or `--hash`, files
protected by an `--if-exists` policy, and preserved hard links are handled one
at a time. On macOS, files above the batching
limit can use APFS cloning. That limit is the smallest of the comparison block
size, `batch-bytes`, and `request-size`.

`split-min-size` controls how small a region an idle worker can take from another
worker. Lower values allow finer sharing; higher values reduce assignments.
Splits normally align to comparison blocks and need twice the minimum remaining
size. With automatic ordinary remote requests, slow workers can share smaller
unread regions without changing comparison blocks.

Capped SSH and TCP copies tune from continuous transport-byte activity so waiting for a
large batch acknowledgment does not look like an idle link. Completion counters
still report acknowledged file data. Saved starting counts require the same
bandwidth limit and compression setting; a capped plateau does not select the
starting count for an uncapped copy. Transport-byte history is also kept separate
from older logical-byte-cap history.

Small-file copies can continue exploring worker counts after files have been
assigned to batches, while unread work can still be shared with other workers.
Requests already in flight do not count as work an additional worker can take.
After reducing the count, measurements wait for retiring workers to finish
their outstanding requests, including streamed and compared file data.
A long copy alone does not guarantee a saved starting count: that requires
sufficient usable measurements at more than one worker count.

### Average rate and burst patterns

Ordinary SSH and TCP copies pace compressed bytes at the sender without
changing copy request sizes or batching. `bw-pacing` does not change that pacing;
syq prints a notice if you explicitly set it for these copies.
For the other routes listed in [Resource limits](resource-limits.md), `bw-pacing`
controls logical-byte pacing:

- `125ms` (default): send smaller requests at regular intervals. The first
  request starts immediately, so short copies can exceed the average rate.
- `average`: wait for each request's byte budget before sending it. A 2 MiB
  request at 1 MiB/s waits about two seconds, then can arrive in a burst.

Streaming and transport buffering can also produce bursts. Restricted receivers
apply their authorized rate and request-size limits.

### Recording a comparison

Use the same reporting options and fresh destinations for each run.
`--stats` adds counters without changing the transfer route.
With overrides, `-v` reports effective settings and a final
`syq: tuning observed:` diagnostic. Check elapsed time, exit status, and copied
contents. See [Quick comparison](speed.md#quick-comparison) for the benchmark script.
