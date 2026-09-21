# Performance measurements

Use these measurements to investigate a slow copy. For a starting command and
common symptoms, see [Diagnose a slow copy](speed.md#diagnose-a-slow-copy).
The measurements appear in [automation progress records](automation.md#progress);
use the terminal result for the copy's outcome and totals.

With `--stats` (or debug logging), `progress` records can include an `activity`
object, exposed as `ProgressEvent.activity` in Python. `--results` alone does
not collect it. Accept missing activity data: collection can be unavailable
or lose its remote connection while the copy continues.

| Activity field | Meaning |
|---|---|
| `elapsed_ms` | Time since the preceding coordinator sample |
| `workers` | Counts at sampling time and fractions of observed worker time |
| `endpoints` | Local operations or the latest reports from remote connections |
| `processes` | User and system CPU deltas in nanoseconds, once per process |
| `summary` | The same cumulative worker, endpoint and CPU summary printed by `--stats`, with observed seconds beside the fractions; idle actors are omitted |

## Worker time

Worker `fractions` divide each state's accumulated duration by `observed_ns`,
including waits still in progress. They sum to one when activity was observed;
an empty object means none was observed. `cumulative_fractions` uses all observed
worker time since collection began. Both exclude tuner parking; `parked_ns` and
`cumulative_parked_ns` report that time separately in nanoseconds. These are
fractions of worker time, not command elapsed time. `observed` includes retired
workers; `active` excludes retired workers and workers `parked` by connection tuning. `awaiting_work`
counts workers waiting for a scheduler job. Compare this with `scan_done` to
investigate insufficient work supply.

`source_request` and `source_response` cover sending a request and awaiting its
response. `destination_send` and `destination_ack` cover sending writes and waiting
for replies; synchronous local work can occur inside these calls. `pacing` covers
bandwidth-limit waits. `other_work` is remaining worker activity. A source-response
wait alone cannot distinguish storage, CPU, transport or downstream backpressure.

## Endpoint operations

Endpoint `actors` separate filesystem operations, server communication and Linux
read-ahead helpers. `cumulative_actors` reports the same measurements since the
connection subscribed, including when its latest sample has not advanced. Labels
include worker IDs to distinguish connections. Their fractions use each actor's
own observed time; do not add fractions across actors or to worker fractions.

`source_read` measures demand-read syscalls, including reads used to hash existing destination data; `hashing` measures
content hashing; `destination_write` measures write syscalls. `filesystem_copy`
keeps a combined measurement where filesystem copy operations do not separate reads
and writes. `handling` covers remaining filesystem request work. Server
`request_wait` covers its request queue and `response_send` covers serialization
and writing replies. Server idleness does not by itself prove a transport limit.

`prefetch_advice` measures Linux read-ahead advice calls; its `bytes` are requested
bytes, not bytes physically read. `prefetch_fence` measures waiting for outstanding
advice before releasing or shrinking a range. Read and write byte counters count
completed operations; filesystem-copy bytes are logical bytes and may include
cloning or offload.

## Process CPU

`cpu` is the interval delta; `cumulative_cpu` is the delta since collection began
for that process. Process identities apply only to this run. Helper `helper_cpu`
is part of its process CPU, so do not count it twice. Live Linux helper CPU uses
kernel clock ticks; short intervals can report zero.

## Sample timing

Remote reports arrive at response boundaries and on connection retirement.
`sample_age_ms` measures time since receipt, so network delivery delay is additional
and clocks on different hosts need not agree. `state_at_sample` is the state at that
report. When no newer report arrives, endpoint `elapsed_ms` is null and `actors` is
empty; process CPU deltas are null too. A blocked remote call can therefore leave
stale evidence. Endpoint intervals can span several coordinator intervals. The
first remote CPU sample establishes a baseline and has no delta.

## TCP counters

`tcp` and `tcp_delta` describe the coordinator end of a TCP socket; `peer_tcp` and
`peer_tcp_delta` describe the remote end at its reported sample. The raw counters
include RTT and retransmissions; deltas include receive-window-limited and
send-buffer-limited durations. Local counters are sampled by the progress ticker;
the final reading is retained after retirement. Null means unavailable, whereas
zero is a measurement. See the [schema](https://github.com/greaber/syq/blob/master/schemas/automation.schema.json) for the
complete field definitions.

