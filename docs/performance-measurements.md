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
| `sample_duration_ms` | Length of the diagnostic sampling window, measured between coordinator samples |
| `workers` | Counts at sampling time and fractions of observed worker time |
| `endpoints` | Local operations or the latest reports from remote connections |
| `processes` | User and system CPU deltas in nanoseconds, once per process |
| `summary` | The same cumulative worker, endpoint and CPU summary printed by `--stats`, with observed seconds beside the fractions; idle actors are omitted |

## Worker time

Worker `fractions` divide each state's accumulated duration by `observed_ns`,
including waits still in progress, and sum to one when activity was observed;
an empty object means none was. `cumulative_fractions` covers all worker time
since collection began. These are fractions of worker time, not command elapsed
time. Both exclude time that connection tuning keeps workers parked, which
`parked_ns` and `cumulative_parked_ns` report separately. `observed` counts
retired workers too; `active` excludes retired and parked workers.
`awaiting_work` counts workers waiting for a job; compare it with `scan_done`
to see whether scanning supplies work fast enough.

`source_request` and `source_response` cover sending a request and awaiting its
response. `destination_send` and `destination_ack` cover sending writes and
waiting for replies. `pacing` covers bandwidth-limit waits that count file
data; ordinary SSH and TCP copies wait inside transport writes instead, which
shows up in `destination_send` on pushes and `source_response` on pulls.
`other_work` is remaining worker activity. A source-response wait alone cannot
distinguish storage, CPU, transport, or downstream backpressure.

## Endpoint operations

Endpoint `actors` separate filesystem operations, server communication, and
Linux read-ahead. `cumulative_actors` reports the same measurements since the
connection subscribed. Labels include worker IDs to distinguish connections.
Fractions use each actor's own observed time; do not add them across actors or
to worker fractions.

`source_read` measures read calls, including reads of existing destination
data for hashing; `hashing` measures content hashing; `destination_write`
measures writes. `filesystem_copy` combines reads and writes where the
filesystem's copy operation does not separate them. `handling` covers
remaining filesystem request work. Server `request_wait` covers its request
queue and `response_send` covers writing replies; an idle server does not by
itself prove a transport limit. `prefetch_advice` measures read-ahead requests,
whose `bytes` were requested rather than read, and `prefetch_fence` measures
waiting for them. Byte counters count completed operations; filesystem-copy
bytes are logical and may include cloning.

## Process CPU

`cpu` is the interval delta; `cumulative_cpu` is the delta since collection began
for that process. Process identities apply only to this run. A helper's
`helper_cpu` is part of its process CPU, so do not count it twice. Short
intervals can report zero for Linux helpers.

## Sample timing

Remote reports arrive with responses and when a connection retires, so they
can be older than the coordinator's sample. `sample_age_ms` measures time since
the report arrived, so network delay comes on top, and host clocks need not
agree.
`state_at_sample` is the state at that report. When no newer report has
arrived, endpoint `sample_duration_ms` and process CPU deltas are null and
`actors` is empty. The first remote CPU sample has no delta.

## TCP counters

`tcp` and `tcp_delta` describe the coordinator end of a TCP socket; `peer_tcp` and
`peer_tcp_delta` describe the remote end at its reported sample. The raw counters
include RTT and retransmissions; deltas include receive-window-limited and
send-buffer-limited durations. Null means unavailable, whereas zero is a
measurement. See the [schema](https://github.com/greaber/syq/blob/master/schemas/automation.schema.json) for the
complete field definitions.

