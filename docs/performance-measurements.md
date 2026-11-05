# Performance measurements

If a copy is slower than you expect, add `--stats` to see where its time went.
The measurements locate a delay; they don't prove its cause. For common fixes,
see [Diagnose a slow copy](speed.md#diagnose-a-slow-copy).

## Read the summary

This summary, shortened to one of two workers, comes from comparing two local
directories with `--hash`:

```text
Observed worker time: source request 77%, destination ack 20%, awaiting work 1%, destination send 1% (0.122884s observed; 2 workers; parking excluded: 0.000s; wait states, not proven causes)
  source worker 0 (process 2829cc7c…; sample age 0ms):
    filesystem: hashing 55%, source read 33%, handling 12% (0.048946s observed); source read 176160768 bytes
  destination worker 0:local receiver (tcp 127.0.0.1:47600) (process 0aff957a…; sample age 0ms):
    filesystem: hashing 46%, source read 45%, handling 9% (0.057586s observed); source read 176160768 bytes
    server: request wait 81%, response send 19% (0.003825s observed)
  Process 0aff957a… CPU: user 0.059s, system 0.050s
  Process 2829cc7c… (coordinator) CPU: user 0.061s, system 0.038s
```

### Worker time

Syq copies with several workers, each with its own connections to the source
and destination. The first line splits their combined time between these
states:

| State | The worker is |
|---|---|
| `awaiting_work` | Waiting for its next file or part of a file |
| `source_request` | Sending a request to the source |
| `source_response` | Waiting for the source's reply |
| `destination_send` | Sending data or requests to the destination |
| `destination_ack` | Waiting for the destination's reply |
| `pacing` | Waiting for the bandwidth limit |
| `other_work` | Doing its own processing |

A large share tells you which side to look at, not why it was slow:
`source_response` can mean slow storage or CPU at the source, a slow network,
or a slow destination. A large `awaiting_work` share means workers ran out of
work; if scanning was still running (`scan_done` false in progress records),
it isn't finding files fast enough. A local source has no process of its
own, so its file work counts as `source_request` and `source_response`, as in
the example. On SSH and TCP copies, waits for a
[bandwidth limit](resource-limits.md#bandwidth) count as `destination_send` or
`source_response` rather than `pacing`.

### Endpoint operations

The indented groups show what each worker's source or destination did, in up
to three parts:

| Part | Operation | Meaning |
|---|---|---|
| `filesystem` | `source_read` | Reading file data, including an existing destination file being compared |
| | `hashing` | Hashing contents, excluding the reads |
| | `destination_write` | Writing file data |
| | `filesystem_copy` | A filesystem copy call; its bytes are logical and can include cloned data |
| | `prefetch_fence` | Waiting for read-ahead to finish |
| | `handling` | The rest of the work on each request |
| `server` | `request_wait` | Waiting for the next request |
| | `response_send` | Writing replies |
| `prefetch` | `prefetch_advice` | Asking Linux to read ahead; its bytes were requested, not read |

Percentages are shares of each part's own time, so don't compare them across
parts or with worker time. A `filesystem` part that was busy for most of the
elapsed time points to that side's storage or hashing. A `server` that mostly
waits for requests was idle, but that alone doesn't show a network limit.

### Process CPU

The last lines give the CPU time of the coordinator (the syq process running
the copy), of the `local receiver` that writes a local destination, and of each
remote process. CPU time divided by elapsed time is the number of cores in use;
if that is near the machine's core count, compare with `--no-compress`.

The `tcp` lines in the `--stats` totals combine all TCP data connections.
Retransmissions point to packet loss; see
[Test congestion control](server-tuning.md#test-congestion-control).
Window-limited time shows whether the receiver or the sender's socket buffer
held data back.

## Activity fields

To follow the measurements during a copy, also write
[automation results](automation.md#progress): with `--stats`, each `progress`
record carries an `activity` object (`ProgressEvent.activity` in Python),
except in S3 copies. Fields starting with `cumulative_` cover the copy so far;
the others cover the time since the previous sample. Expect gaps: a remote
process can stop reporting while the copy continues.

| Field | Meaning |
|---|---|
| `sample_duration_ms` | Time since the previous sample |
| `workers` | Worker counts and time shares |
| `endpoints` | One entry for each worker's source or destination |
| `processes` | One entry for each syq process |
| `summary` | The summary `--stats` prints, for the copy so far; idle parts are left out |

### Workers

| Field | Meaning |
|---|---|
| `observed` | Workers started so far, including finished ones |
| `active` | Workers that have not finished and are not paused |
| `awaiting_work`, `parked` | Workers waiting for work, or paused while syq adjusts their number, at the sample |
| `observed_ns` | Combined worker time, excluding pauses |
| `fractions`, `cumulative_fractions` | Each [state](#worker-time)'s share of worker time; empty when there was no activity |
| `parked_ns`, `cumulative_parked_ns` | Paused worker time |

### Endpoints

| Field | Meaning |
|---|---|
| `label` | The side and worker, as in the summary |
| `process` | The reporting process, as in `processes`; null before its first report |
| `sample_age_ms` | Time since the report arrived; null before the first report |
| `sample_duration_ms` | Time the report covers; null when no new report has arrived |
| `actors`, `cumulative_actors` | One entry for each [part](#endpoint-operations); `actors` is empty when no new report has arrived |
| `tcp`, `tcp_delta`, `peer_tcp`, `peer_tcp_delta` | [TCP counters](#tcp-counters) |

Each part has a `role` (`filesystem`, `server`, or `prefetch`), the operation
in progress at the report as `state_at_sample` (or `inactive`), its time in
operations as `observed_ns`, each operation's share of that time in
`fractions`, and the bytes of completed operations in `bytes`. `helper_cpu` is
the Linux `prefetch` thread's CPU time, already counted in its process, and
null for other parts.

### Processes

| Field | Meaning |
|---|---|
| `process` | An identifier that is meaningful only within this run |
| `local` | True for the coordinator |
| `sample_age_ms`, `sample_duration_ms` | As for endpoints |
| `cpu`, `cumulative_cpu` | `user_ns` and `system_ns`; `cpu` is null for another process's first report or when no newer one has arrived |

Each process appears once, even when it serves several connections.

### TCP counters

For a TCP data connection, `tcp` and `peer_tcp` hold the kernel's counters,
such as round-trip time and retransmissions, for the coordinator's end and the
other end; `tcp_delta` and `peer_tcp_delta` hold their changes since the
previous sample. The
[schema](https://github.com/greaber/syq/blob/master/schemas/automation.schema.json)
lists them. Other connections report null, as does a counter the system doesn't
provide; zero is a measurement.
