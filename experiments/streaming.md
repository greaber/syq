# Experimental range streaming

2026-09-06. This opt-in experiment compares continuous checked block streaming
with the existing request/ack credit window. `copy-path=auto` remains the
default. `--tuning-options copy-path=streaming` selects the experiment and
bypasses small-file/whole-file shortcuts, just as `copy-path=ranges` does.
Neither performance superiority nor a default change is assumed.

`copy-path=auto-streaming` keeps the same eligibility rules for native small
copies, worker batches, and whole-file copies as `auto`, and selects streaming
only when the scheduler reaches range transfer. This isolates the streaming
mechanism from bypassing unrelated optimizations. It rejects pipeline depth
but permits explicit batch controls. No default or automatic selection policy
changes, no new wire messages, and no persistent state changes are involved.

## Protocol and scheduling

An authenticated source worker receives one bounded-block `ReadStream` command
for its current interval. It emits ordinary checked `Block` frames, without
waiting for per-block read requests. Its existing bounded response queue and
transport backpressure limit read-ahead. The scheduler advances its claimed
position only as the coordinator accepts blocks, so idle workers may still
steal the suffix. `StopReadStream` cancels unused read-ahead, and the client
drains through `ReadStreamDone` before another operation. A split through a
frame validates the whole frame's hash before truncating/re-hashing its prefix.
In-process sources produce one block per receive, without preloading a range.

Writes use unchanged `WriteRange` requests, with unchanged destination
authorization, hashing and error checks. A separate reply collector consumes
all completions and retains only their count and first error, not a growing
reply list. `WriteStreamFence` / `WriteStreamDone` is an ordered, non-writing
fence. The authenticated server returns it even after grant expiration or
revocation, so rejected writes cannot strand the collector. Completion
requires every write reply and that fence. It does not flush disk.
Both endpoints are drained on an operation error before connection reuse.

The initial experiment adds a reply-drain thread per remote destination range.
It can lose on short/CPU-bound work through startup, synchronization, source
stream start/stop round trips, and read-ahead discarded after work-stealing.
Frame sizes, worker counts, transport buffers and receiver queues still affect
memory/performance. This is not unlimited buffering or a universal saturation
guarantee. The default four-frame read-ahead queue remains bounded. Pipeline
depth is rejected with streaming because it no longer controls block credits.

Bandwidth pacing charges each accepted block before its destination write.
A remote source can already have read/sent ahead into bounded buffers, so this
is not a strict source-side traffic/burst limit. The shared average limiter and
restricted destination's signed limits still apply. Finalize, source rechecks,
publication and resume identities are unchanged.

## Compatibility boundary

Baseline: released v0.4.0 (f4aee996), whose protocol and resume definitions
match this task's base 7d5062d. New request/response variants are appended; no
existing frame tags or payload layouts change. The source stream is protected
by the existing build-identity preamble before any frames are decoded. Both
old-to-new and new-to-old build mismatches fail explicitly; managed helpers
select/upload the matching executable. A manually selected old helper must be
updated, and an old coordinator rejects the new tuning value. Default copies
never issue stream commands.

There is no new persisted state, grant/receipt field, resume grid, enrollment
format, updater setting or automation schema. Tuning remains raw CLI in SDKs
and is forwarded to remote coordinators through its existing string field.
Experiments bypass the remembered connection-count cache. Old/new commands
sharing a host retain their separate build-identified helpers and compatible
resume state. Diagnostic JSON adds attempted streaming-range/block counts;
those are not completion or wire-byte measurements.

## Comparing

Use the same candidate binary, explicit worker count, data, transport, cache
policy and request size. Compare `copy-path=ranges,pipeline-depth=4` with
`copy-path=streaming`. Inspect `-v` diagnostics and verify complete contents.
Keep copies short with an external deadline. Measure whole-copy time as well
as sustained throughput, memory and CPU; include short files, multiworker
large files, delayed links, interruption/resume and receiver failures. Store
measured numbers as result data, not assumed improvements in this document.
