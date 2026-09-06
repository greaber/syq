# Experimental range streaming

2026-09-06. The current candidate makes streaming automatic for remote ranges
larger than one ordinary request window (normally four 4 MiB blocks). Local
ranges and shorter remote ranges retain ordinary requests: local operations
have no network credit latency, and short ranges fit in the existing window
without waiting to refill it. This selection is based on the work remaining,
not a provider, measured RTT threshold, or user-supplied budget. It is a
candidate under measurement, not a universal performance guarantee.

Whole-file, native small-copy and batching eligibility remain unchanged.
An explicit pipeline depth or `copy-path=ranges` retains ordinary requests
for diagnostic comparisons. `copy-path=streaming` still forces streaming
and bypasses small-file/whole-file shortcuts, just as `copy-path=ranges` does.

`copy-path=auto-streaming` keeps the same eligibility rules for native small
copies, worker batches, and whole-file copies as `auto`, and selects streaming
only when the scheduler reaches range transfer. This isolates the streaming
mechanism from bypassing unrelated optimizations. It rejects pipeline depth
but permits explicit batch controls. Unlike `auto`, this diagnostic selector
also streams short and local ranges, allowing the automatic exclusions to be
tested independently.

## Protocol and scheduling

An authenticated source worker receives one bounded-block `ReadStream` command
for its current interval. It emits ordinary checked `Block` frames, without
waiting for per-block read requests. Its existing bounded response queue and
transport backpressure limit read-ahead. The scheduler advances its claimed
position only as the coordinator accepts blocks, so idle workers may still
steal the suffix. Before each consumer block the worker checks its assigned
end and sends a one-way `ShrinkReadStream` if it decreased. This is a
block-boundary observation, not an immediate scheduler callback: a blocked
receive or destination write can delay it. The scheduler never does network
I/O, and unchanged boundaries require no messages or acknowledgements.

The source processes reductions before its next read and never starts another
block at or beyond the new end. It preserves the original frame boundaries,
so the final block may straddle the new limit. Already queued/in-flight blocks
can also arrive; this is not a zero-waste guarantee. Limits may only decrease,
including to zero or behind the current source offset. At the reduced end,
the source still waits for `StopReadStream`, consuming any late reductions.
No reduction produces a response or can leak past the stop fence.

`StopReadStream` cancels unused read-ahead, and the client sends it and
drains through `ReadStreamDone` before another operation. On natural completion
or a read error, the source emits Done immediately after its last data/error
frame, then consumes late shrinks and Stop before accepting another operation.
This avoids waiting an extra round trip for an already-finished read. Stop
and subsequent commands remain ordered on the same connection; there is
exactly one Done, including on early cancellation. A split through a
frame validates the whole frame's hash before truncating/re-hashing its prefix.
Exhausting a reduced limit also emits Done before waiting for Stop, including
when a late shrink moves the end behind read-ahead's current offset. The source
still consumes all late controls through Stop before the next operation.
In-process sources produce one block per receive, without preloading a range.

Writes use unchanged `WriteRange` requests, with unchanged destination
authorization, hashing and error checks. A separate reply collector consumes
all completions and retains only their count and first error, not a growing
reply list. `WriteStreamFence` / `WriteStreamDone` is an ordered, non-writing
fence. The authenticated server returns it even after grant expiration or
revocation, so rejected writes cannot strand the collector. Completion
requires every write reply and that fence. It does not flush disk.
The destination fence is sent before draining the source, allowing their
independent remote round trips to overlap. Both endpoints are drained and the
write collector is joined even after a fence-send or source error, before
connection reuse. Both completion boundaries must succeed.

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
updated, and an old coordinator rejects the new tuning value. The automatic
candidate can issue stream commands, but only after the same identity check.
The subsequent v0.4.1 baseline retains these pre-streaming wire definitions.

There is no new persisted state, grant/receipt field, resume grid, enrollment
format, updater setting or automation schema. Tuning remains raw CLI in SDKs
and is forwarded to remote coordinators through its existing string field.
Experiments bypass the remembered connection-count cache. Old/new commands
sharing a host retain their separate build-identified helpers and compatible
resume state. Diagnostic JSON adds attempted streaming-range/block counts;
those are not completion or wire-byte measurements.

`stream_discarded_bytes` counts received source block payload discarded after
work-stealing or cancellation, including drained read-ahead and trimmed frame
suffixes. It excludes transport framing/retransmissions; failed drains may
leave this count incomplete. It diagnoses redundant payload, not network
utilization or peak buffering.
`stream_shrink_requests` counts successfully sent limit reductions, not source
acknowledgements or bytes saved. The shrink experiment adds one appended
request variant; existing frame layouts and all persisted state stay unchanged.

## Comparing

Use the same candidate binary, explicit worker count, data, transport, cache
policy and request size. Compare `copy-path=ranges,pipeline-depth=4` with
`copy-path=streaming`. Inspect `-v` diagnostics and verify complete contents.
Keep copies short with an external deadline. Measure whole-copy time as well
as sustained throughput, memory and CPU; include short files, multiworker
large files, delayed links, interruption/resume and receiver failures. Store
measured numbers as result data, not assumed improvements in this document.

## macOS handoff

The implementation is pushed to `greaber/syq`, branch `experimental-streaming`.
The automatic candidate is commit `6d0c1efa20583a8972446087f55ea1365eb3ae2c`,
including early completion of exhausted reads. It selects streaming without
tuning flags while keeping the local/short-range exclusions described above.
Linux correctness and performance checks exist; this revision has not yet
been validated on a Mac. The earlier opt-in checkpoint `34cadda` remains in
history for reproducing the first early-shrink measurements.

Read `AGENTS.md` first. From your existing syq coordination checkout, preserve
any changes and create a separate task worktree (choose unused names):

```sh
git status --short
git worktree list
git fetch origin experimental-streaming
git worktree add -b mac-streaming .worktrees/mac-streaming \
  6d0c1efa20583a8972446087f55ea1365eb3ae2c
ln -s ../../current-plans .worktrees/mac-streaming/current-plans
cd .worktrees/mac-streaming
cargo build --locked --release
./target/release/syq --build-identity
```

Do not set `SYQ_RELEASE_BUILD`. A clean build should identify itself as
`v0.4.1+dev.6d0c1efa2058`. Use the built executable explicitly, not the installed
release on `PATH`. Run the Rust baseline and focused streaming integration
tests from `AGENTS.md`; `cargo test --test local streaming` selects the latter.
Debug test timings are not performance measurements.

For a Mac-to-Linux test, also build this exact commit in a private checkout on
the user-authorized Linux endpoint. A Mac executable cannot be uploaded and
run as its Linux helper. Both native builds must print the same
`--build-identity`; their executable file hashes will differ across platforms.
Select the matching Linux executable with `--syq-path /absolute/path/to/syq`
in native copy mode, or `--rsync-path /absolute/path/to/syq` in rsync mode.
Do not replace a normal remote installation or bypass build-identity checks.
See [cross-platform development](../docs/development.md#another-platform).

First compare normal copies against a separately built master baseline,
without tuning or connection-count overrides. Record the baseline commit too;
the current Linux comparison uses `79a126a`. Each baseline/candidate must use
its own matching remote helper.

For diagnosis, compare these settings using the same candidate and workload:

| Comparison | `--tuning-options` value |
|---|---|
| Ordinary pipeline | `copy-path=auto,request-size=4M,pipeline-depth=4` |
| Automatic candidate | Omit `--tuning-options` |
| Streaming every remaining range | `copy-path=auto-streaming,request-size=4M` |
| Deeper ordinary pipeline | `copy-path=auto,request-size=4M,pipeline-depth=16` |

Also try fixed connection counts of 1 and 8 (`--connections` in native copy mode,
`--syq-connections` in rsync mode). Keep compression settings equal; the Linux
screening comparisons used `--no-compress`. Use `-v --stats` and `SYQ_DEBUG=1`
to retain actual transport evidence, copy-path counters, discarded source
payload and shrink-notification counts. A local whole-file or small-batch path
can legitimately report zero streaming ranges under `auto-streaming`.

Start with a generated large file and a small-file tree, then test remote push
and pull when a named endpoint is available. Separately compare
`copy-path=ranges` against `auto` to investigate local parallel-range gains;
those are not gains provided by streaming itself. `copy-path=streaming` forces
ranges and disables unrelated fast paths, so it is not the hybrid candidate.

Use fresh, empty, task-owned destinations; check free space before generation;
verify every complete copy outside the timer; remove only generated scratch.
Use three interleaved repeats and a 25-second per-copy deadline, reducing the
fixture size if necessary. Terminate the whole owned process group on a cap
and check for surviving local/remote workers. Do not assume GNU `timeout`, GNU
`time`, `/proc`, or the private Linux experiment adapters exist on macOS.
Record cache policy and filesystem behavior (including possible APFS cloning),
and never apply a global cache purge or add a final disk flush to these timings.

The syq-bench run data and host-specific Linux adapters remain gitignored on
the original machine; they are not distributed by this branch. No credentials
or infrastructure identifiers are needed in git. The implementation and this
handoff are sufficient to run fresh comparisons using the laptop's harness or
a small bounded driver. Keep new environment-specific configs and measurements
in ignored artifacts, and report exact revisions, verification, transport,
throughput and any unavailable controls alongside the results.
