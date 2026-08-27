# SYQ resume and checkpoint design

**Status:** implemented. README.md is the user-facing contract.

## Goals

SYQ needs to recover efficiently at two different scales:

1. An interrupted large file should reuse bytes already present at the
   destination.
2. An explicitly identified, unusually large job should be able to remember
   completed files when repeatedly reaching its unfinished frontier would be
   prohibitively expensive.

Ordinary invocations must not leave a persistent history or make their result
depend on hidden state from earlier SYQ commands. The second optimization is
therefore opt-in through `--checkpoint FILE`.

## Atomic publication and per-file resume

Unless `--inplace` was explicit, every regular file is written to the
deterministic destination-side name `.<name>.syq-partial`, given its final
metadata, and atomically renamed over the requested pathname. Small files are
still pipelined as whole-file protocol requests, but the receiver stages and
renames each one before acknowledging it. SYQ does not `fsync` by default;
`--fsync` separately requests crash durability for the file and directory.

If a range transfer is interrupted, the partial itself is the per-file state.
A normal rerun finds it, hashes it and the current source at fixed
`--block-size` offsets, and transmits only mismatching blocks. SYQ never needs a
local record to trust those bytes. A stale partial is content-safe because
every reused block is compared with the current source. Pipelined small files
are cheap enough to overwrite wholesale on retry; they avoid the extra partial
probe while retaining the same atomic publication boundary.

`--inplace` deliberately removes the staging boundary. It can save space and
work for a changed large file, but readers may observe mixed contents and an
interruption leaves the final pathname unfinished.

## Explicit whole-job checkpoint

`--checkpoint FILE` names state chosen and owned by the user. A missing file is
created mode 0600; an existing one resumes the same logical copy. The path is
on the coordinating machine. For direct or detached remote-to-remote copies,
the coordinator is the source host; `--relay` keeps it on the invoking host.

The checkpoint is append-only JSONL:

```json
{"type":"header","format":1,"job_identity":"..."}
{"type":"complete","path_b64":"YS9maWxl","size":123,"mtime_sec":1700000000,"mtime_nsec":42,"mode":33188,"uid":1000,"gid":1000,"basis":"transferred"}
```

Paths are base64 because Unix paths need not be UTF-8. The header identifies
canonical source roots, trailing-slash mappings, destination, endpoints, and
content/metadata-affecting options. Reusing a checkpoint for a different job
is rejected. An advisory exclusive lock rejects simultaneous use of one
checkpoint file.

The latest completion record for a destination-relative path wins. A record
contains the source size, nanosecond mtime, mode, owner, and group observed
when the destination became complete. Mode/owner/group participate in matching
only when the command requests that metadata; size and mtime always do.

## Recording completion

A regular file is recorded only after one of these outcomes:

- its staged or in-place transfer finalized successfully and the post-transfer
  source stat confirmed that the source fingerprint was stable;
- block comparison found the existing final file content-identical and its
  metadata repair succeeded; or
- the ordinary destination quick check matched and any requested metadata
  repair succeeded.

An unfinished file is never recorded. Its destination partial remains the
only state. A crash before a completion record is flushed causes a safe false
negative: the next attempt repeats a destination check. Records are flushed
after 256 additions or about one second; `--fsync` also syncs those flushes.
Malformed or crash-torn records are ignored.

## Using and retiring a checkpoint

The source is scanned on every attempt. For each regular file, SYQ first claims
its destination mapping (so checkpoint skipping cannot hide source collisions),
then looks up its destination-relative path. A matching source fingerprint is
counted complete without a destination stat. A missing or mismatching record
uses the ordinary destination quick check, partial probe, block comparison, and
transfer path.

The checkpoint is retained after interruption or any copy error. After a clean
copy it is closed and removed: completed jobs do not become hidden history. If
the destination root no longer exists at startup, an old checkpoint is reset
because none of its destination claims can still be valid. SYQ validates that
the user-selected path contains this job's checkpoint before resetting it; it
never silently replaces an unrelated file. A dry run may read state to preview
the corresponding retry but does not create, append, reset, or remove it.

`-c` and `--verify-only` conflict with `--checkpoint`: those modes explicitly
ask to inspect destination contents, while a checkpoint exists to bypass that
inspection.

## Explicit trust boundary

A checkpoint record is a historical assertion. A matching record intentionally
wins over current destination reality: if another process deletes, replaces,
or modifies that destination path between attempts, the retry skips it. This is
why checkpointing is opt-in and why ordinary SYQ runs keep no automatic
journal.

The source fingerprint detects ordinary source changes between attempts but is
not a content hash. Deliberately changing content while preserving size and
nanosecond mtime can evade it, like the normal size-and-mtime quick check.

Power-loss durability is promised only with `--fsync`. Without it, a
destination may acknowledge a completed write and later lose it while a
checkpoint record survives.

## Metadata cost

The planner already batch-stats final destination paths and the receiver stats
those paths in parallel. A non-in-place file needing the general transfer path
performs one additional lookup for its deterministic partial sidecar; the
pipelined new-small-file path and `--inplace` avoid even that lookup. The worker
carries the planner's final-file metadata and its chosen final/partial basis
forward; it does not re-stat the final path or re-probe merely to rediscover
that choice.

The checkpoint's main win is therefore eliminating actual destination metadata
lookups for previously completed files, not eliminating one wire round trip per
file. It is most useful for a fast/local source and a slow or repeatedly
disconnected destination where rechecking an ever-growing completed prefix can
prevent the job from reaching new work.

## Removed automatic state

An earlier implementation kept a job-keyed journal under
`$XDG_STATE_HOME/syq` for every copy and placed a session marker in the
destination. That made ordinary results depend on invisible history, consumed
coordinator storage without an explicit request, required a writable state
directory, and introduced marker lifecycle and concurrency semantics unlike
rsync. Both the automatic journal and destination marker were removed. There
is no `--no-resume`: partial-file reuse remains automatic and the only
historical whole-job state is the explicitly named checkpoint.
