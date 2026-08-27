# PCP interrupted-transfer resume design

**Status:** proposed design, not yet implemented.

## Purpose

PCP already avoids retransmitting most completed data. A repeated archive copy
skips files whose size and modification time match, and an incomplete large
file can be resumed by comparing the source with its `.pcp-partial` file in
blocks.

The remaining cost is planning: resuming or rerunning a tree with millions of
small files still requires destination metadata requests for the entire tree.
On NFS, those `stat` operations can take longer than the useful transfer.

This design adds two deliberately separate pieces of state:

1. a **destination marker on the destination filesystem**, visible through
   every host that mounts that filesystem, which warns other PCP jobs that the
   destination is owned by an incomplete transfer; and
2. a **persistent local completion journal**, keyed by the logical copy job,
   which lets interrupted resumes and later completed reruns avoid destination
   metadata requests for files PCP previously completed successfully.

The design is not a distributed transaction or lease system. It provides the
largest ordinary-use benefits with one atomic marker creation and an
append-only local record.

## Operating assumptions

Version 1 relies on these assumptions:

- The source is not intentionally modified while a copy is running.
- The destination is not independently modified or deleted outside PCP.
- A transfer is normally resumed from the same coordinating machine and user.
- Common failures are Ctrl-C, a lost connection, or a crashed PCP process.
- Two identical resume attempts may rarely overlap; with an unchanged source,
  they intend to write the same content.
- Power-loss durability is promised only when the existing `--fsync` option is
  used.

PCP retains its existing post-transfer source re-stat. The journal's source
fingerprints catch ordinary changes between attempts, but do not claim to
detect content changed while size and nanosecond mtime were deliberately
preserved.

## Explicit non-goals

Version 1 does not attempt to guarantee correct fast resume when:

- source files change during a running copy;
- completed destination files are deleted or modified outside PCP;
- two matching resume processes start at almost exactly the same time;
- independent jobs run concurrently under the same destination marker scope,
  even when their intended payload paths do not overlap;
- a session is automatically adopted by a different coordinating machine; or
- a destination acknowledges a non-`--fsync` write and subsequently loses it
  during a machine or storage-system power failure.

It also does not add held advisory locks, leases, fencing tokens, PID/boot-ID
liveness records, a remote per-file manifest, or a distributed coordinator.

Users who want destination verification must use `-c`, `--verify-only`, or a
future explicit destination-recheck option. Those modes must bypass
journal-based destination skipping.

## Identities

### Job identity and job key

A **job identity** describes a repeatable logical copy. It contains:

- the source endpoint and normalized source root or roots;
- trailing-slash "copy contents" semantics for every source;
- the destination endpoint and normalized destination mapping;
- content- and metadata-affecting options; and
- the state format version.

Content-affecting options include recursive traversal, symlink handling,
archive and metadata flags, devices and special files, `--inplace`, and
`--atomic`. Worker count, progress display, verbosity, TCP selection, and
compression are operational and do not create a different job.

The **job key** is a stable cryptographic hash of the encoded job identity. It
names the local journal, so rerunning the same job can find its state without a
destination marker or remembered session ID.

Existing local paths should be canonicalized. For a nonexistent final
component, canonicalize the nearest existing parent and normalize the
remaining components lexically. Remote endpoints should perform equivalent
normalization themselves where possible.

The job key is for finding local state, not for locating the destination
marker. A marker's physical location must remain the same when the same NFS
directory is mounted under different absolute paths on different machines.

### Session identity

A **session** is one destination ownership interval, including any interrupted
attempts that resume it. It has a random 128-bit session ID. The ID is an
identity, not a secret.

A new invocation after a previously successful copy starts a new session, but
reuses the persistent job journal's completion records.

## State locations

State is never written into the source tree. Sources may be read-only, may be
single files, and may be reused for several destinations.

### Local journal

Use:

```text
$XDG_STATE_HOME/pcp/transfers/<job-key>.jsonl
```

with this fallback when `XDG_STATE_HOME` is unset:

```text
$HOME/.local/state/pcp/transfers/<job-key>.jsonl
```

The directory is mode `0700` and journal files are mode `0600`. `/tmp` is not
suitable because the state must survive reboot-time and periodic cleanup.

"Local" means local to the process running the orchestrator. For an ordinary
push that is the invoking machine; for direct or detached remote-to-remote
operation it is normally the source machine where PCP moved the orchestrator.

The journal remains after successful sessions. It may be compacted, but is not
deleted merely because the destination marker was removed.

### Destination marker

The marker must live **on the destination filesystem**, not in the destination
host's home or XDG state directory. This is the cross-machine interlock: if j2,
j3, j4, and j5 mount the same NFS directory, each host must observe the same
marker through that mount.

For a directory destination scope, use a reserved destination-relative path:

```text
<destination-root>/.pcp-transfer-session.json
```

If the destination directory does not exist yet, PCP may create the empty root
first, then must create the marker before creating any payload beneath it.
Racing processes may both create or observe the empty root; exclusive marker
creation chooses the sole session owner.

For an exact single-file destination, use a reserved sidecar in its parent:

```text
<destination-parent>/.<destination-name>.pcp-transfer-session.json
```

The marker name is relative to the destination object rather than hashed from
its host-local absolute path. Consequently, different mount prefixes still
reach the same physical marker.

The reserved marker path is internal PCP metadata. PCP must never transfer a
source entry onto it, include it in destination comparisons, or expose it as a
user payload path. If a requested mapping collides with the reserved name, PCP
must stop with a clear error rather than overwrite either object.

Creating and removing a marker inside a directory changes that directory's
mtime. When metadata preservation is requested, PCP must reapply the intended
destination-root metadata after removing the marker; otherwise marker cleanup
would spoil an otherwise correct archive copy.

Creating the marker requires write permission on the destination directory or,
for an exact file destination, its parent. That is consistent with the ability
to create or replace the requested destination.

## Destination marker format

An illustrative marker is:

```json
{
  "format": 1,
  "session_id": "80e00c95b8ff4d108e125bc8d29166fd",
  "job_identity": "sha256:...",
  "source_identity": "sha256:...",
  "options_identity": "sha256:...",
  "created_at": "2026-08-27T15:00:00Z",
  "coordinator_host": "workstation-a"
}
```

The marker contains no per-file state and is not periodically rewritten. Its
existence means that the destination may be incomplete. Its session ID lets
the owning coordinator distinguish a resume from an unrelated transfer.

The marker is created with exclusive-create semantics (`O_CREAT|O_EXCL`, Rust
`create_new`, or the endpoint equivalent). PCP must not implement marker
ownership as a separate check followed by an ordinary overwrite.

The marker is a persistent claim, not a held advisory lock. A crashed process
leaves it behind intentionally so another machine cannot treat the incomplete
destination as fresh.

One marker claims the entire destination scope. Two jobs targeting the same
destination root are therefore serialized even if one intends to populate `A/`
and the other `B/`: the second job sees a different identity and aborts. Jobs
that name `A/` and `B/` themselves as separate destination roots have separate
marker scopes and may run independently. Version 1 chooses this conservative
root-level policy instead of trying to prove that two mappings cannot overlap.

## Local journal format

The local journal is append-only JSON Lines. Rewriting a large JSON array for
every completion would be expensive and fragile under interruption.

Illustrative records are:

```json
{"type":"header","format":1,"job_identity":"sha256:..."}
{"type":"session_start","session_id":"80e00c95b8ff4d108e125bc8d29166fd","started_at":"2026-08-27T15:00:00Z"}
{"type":"complete","path_b64":"YS9maWxlMQ==","kind":"file","size":1234,"mtime_sec":1700000000,"mtime_nsec":123456789,"basis":"transferred"}
{"type":"complete","path_b64":"Yi9maWxlMg==","kind":"file","size":9876,"mtime_sec":1700000001,"mtime_nsec":987654321,"basis":"quick-check"}
{"type":"session_complete","session_id":"80e00c95b8ff4d108e125bc8d29166fd","completed_at":"2026-08-27T15:30:00Z","root_meta":{"mode":493,"uid":1000,"gid":1000,"mtime_sec":1700000002,"mtime_nsec":0}}
{"type":"cleanup_complete","session_id":"80e00c95b8ff4d108e125bc8d29166fd","completed_at":"2026-08-27T15:30:01Z"}
```

Paths are encoded without assuming UTF-8; base64 is sufficient for JSON.
Completion records persist across sessions. The latest valid completion record
for a destination-relative path wins.

`session_complete` means that all payload and ordinary metadata work succeeded
and the session may release its marker. It also retains the destination-root
metadata needed for idempotent post-marker cleanup. `cleanup_complete` means
the matching marker is absent and the root metadata has been restored after
marker removal.

A malformed or unterminated final line is treated as a crash-truncated tail and
ignored. A malformed interior record means the journal is corrupt; PCP must
abort fast resume rather than guess.

The implementation may later replace JSONL with a compact binary or indexed
format without changing these semantics.

## Starting a new session

Before payload operations, PCP determines the effective destination scope and
the corresponding marker location.

When no marker exists and the local journal is absent or its latest session has
`cleanup_complete`:

1. Normalize and validate the job identity.
2. Open or create the job-keyed local journal and validate its header.
3. Generate a random 128-bit session ID.
4. Create the destination marker atomically with exclusive-create semantics.
5. If another process won creation, read its marker and restart the
   existing-marker decision flow.
6. Append and flush `session_start` to the local journal.
7. If the journal update fails, reread the marker, remove it only if its session
   ID is still ours, and abort before payload operations.
8. Begin the ordinary source scan and transfer.

If the latest local session has `session_complete` but not
`cleanup_complete`, PCP first finishes the idempotent cleanup described below.
This applies whether its marker remains or was already removed before a crash.
Only after recording `cleanup_complete` may it enter the new-session flow.

If an incomplete local session exists but its destination marker is missing,
PCP should abort by default. The marker may have been removed manually or the
destination may have been replaced. An explicit reset/recovery operation can
start a new session while retaining safe completion records; v1 should not
silently guess.

## Resuming an interrupted session

When a destination marker exists:

1. Read and validate its format.
2. Locate the local journal directly from the current job key.
3. Validate the complete job identity stored in the journal and marker.
4. If the matching session already has a durable `session_complete`, reread and
   conditionally remove its stale marker, restore the recorded destination-root
   metadata, append `cleanup_complete`, and then restart the new-session flow.
5. Otherwise, confirm that the journal's latest incomplete `session_start` has
   the same session ID as the marker.
6. If all identities match, resume using the existing completion records and
   `.pcp-partial` files.
7. If the journal is missing, the session IDs differ, or any identity differs,
   abort. The marker belongs to another machine/job or local recovery state has
   been lost.

Version 1 does not inspect PID, boot ID, or process start time. Therefore, two
identical commands on the same coordinator can both recognize the same session
and overlap. This narrow race is accepted: with an unchanged source they write
the same intended content. The destination marker still prevents unrelated
jobs and other machines without the matching journal from proceeding.

Automatic cross-machine adoption is not part of v1. A machine that sees an
incomplete destination marker but lacks the matching local journal must stop;
it must not silently create a fresh transfer over that destination.

## Recording file completion

A regular file becomes journal-complete only after:

1. the destination acknowledges its write or finalize operation; and
2. PCP's existing source re-stat confirms that source kind, size, mtime
   seconds, and mtime nanoseconds did not change during the copy.

The completion record stores that source fingerprint. No extra source hash is
required on the ordinary fast path.

A file found complete through a real destination quick check may also be
recorded with `basis: "quick-check"`. Later sessions can then avoid repeating
that destination metadata request.

The first implementation may journal only regular files. Directories,
symlinks, and special files can continue through the existing planner; regular
small files provide the primary NFS metadata benefit.

## Using persistent completion records

The source must still be scanned on every invocation so PCP can discover new,
removed, changed, and unfinished source entries. For every scanned regular
file in a normal copy:

1. Look up its latest completion record by destination-relative path.
2. Compare current source kind, size, and nanosecond mtime with the record.
3. If they match, count the file complete without issuing a destination `stat`.
4. Otherwise, ignore the record and use PCP's existing destination probe,
   quick check, partial hashing, and transfer path.

This applies both to an interrupted resume and to a later invocation after a
successful session. A completed rerun therefore performs a source scan and
local journal lookups, but avoids most NFS destination metadata requests.

Files without completion records retain existing behavior. An unfinished
large `.pcp-partial` remains authoritative and is compared block by block.

Journal trust must be bypassed when the user explicitly requests destination
inspection:

- `-c` must perform its destination block comparison;
- `--verify-only` must inspect and hash the destination; and
- a future `--recheck-destination` or `--ignore-journal` option should force
  the ordinary destination metadata path without deleting the journal.

Without such a mode, externally deleted or modified destination files may be
skipped because the persistent journal records their earlier success. This is
an explicit speed-versus-external-change tradeoff, not a verification claim.

`--dry-run` must not create a marker, journal, or destination directory.
`--verify-only` should read an existing marker and report that the destination
may be incomplete, but it does not need to claim the destination with a new
marker because it performs no writes. Neither mode may turn read-only planning
into persistent state changes.

## Journal buffering and crash behavior

Completion records may be buffered and flushed in batches by count or time.
They do not require an `fsync` after every file.

The ordering rule is strict: PCP never generates a completion record before
destination success and source revalidation. Therefore:

- A crash after the destination succeeds but before the journal record is
  flushed causes a safe false negative: the next attempt performs an
  unnecessary destination check or retransmission.
- A present completion record represents a destination success acknowledged
  under this design's operating assumptions.
- A truncated final record is ignored and likewise causes only repeated work.

When `--fsync` is used, destination success retains the stronger durability
meaning already provided by that option. Local journal loss can reduce resume
speed or require recovery, but must never make PCP record a file before the
destination acknowledged it.

## Successful completion and cleanup

Only after all payload work and deferred child-directory metadata finish
without errors should PCP:

1. flush pending file-completion records;
2. append `session_complete`, including the root metadata needed for cleanup,
   and sync the journal before releasing the destination marker;
3. reread the destination marker and confirm its session ID still matches;
4. remove that marker;
5. reapply the requested destination-root metadata, because marker removal
   changed the root directory's mtime;
6. append and flush `cleanup_complete`; and
7. retain the job-keyed local journal for later reruns.

The ordering makes both cleanup crash windows automatic. A crash after durable
`session_complete` but before marker removal leaves a completed session with a
stale marker; the next invocation conditionally removes it and finishes
cleanup. A crash after marker removal but before root-metadata restoration or
`cleanup_complete` leaves a completed session with no marker; the next
invocation restores the recorded root metadata and finishes cleanup. Neither
case is mistaken for an incomplete payload or requires manual reset.

If PCP exits due to interruption or a transfer error before cleanup begins, the
marker and journal remain. If conditional marker removal fails after
`session_complete`, PCP reports the cleanup failure and leaves the marker in
place; the next invocation recognizes the matching completed session and
retries cleanup safely.

Marker removal must never delete destination payload or `.pcp-partial` files.

## Missing, stale, or abandoned state

If the destination marker exists but the matching local journal does not, PCP
must abort with a diagnostic containing the session ID, coordinator host,
destination, and marker path. This is what protects a shared NFS destination
when a different host encounters another host's interrupted copy.

A later explicit recovery command may support:

- **adopt:** inspect the destination using existing stats and partial hashing,
  create a matching local journal, and continue the marked session; or
- **reset:** conditionally remove the marker after confirmation and start a new
  session.

Neither is required for the first implementation. Reset never removes payload
or partial files; the next session can reuse safe partials through existing
block comparison.

If a persistent completed journal exists but the destination marker is absent,
normal reruns may trust its matching completion records under the operating
assumptions. Users who may have changed the destination must select a
destination-rechecking mode.

## Large in-place files

The journal improves recovery for explicit `--inplace` transfers: an
interrupted file has no completion record and must re-enter the existing
probe/block-resume path.

It does **not** make in-place writes equivalent to partial-plus-rename. A
concurrent reader can still observe mixed content, and an interrupted update
has already modified the previous destination. Therefore this design does not
change PCP's default for large files: partial-plus-rename remains the default,
while `--inplace` stays an explicit space/behavior tradeoff.

## Journal size and compaction

JSONL is intentionally simple for v1, but a record per file is large. A tree of
millions of files can produce a journal hundreds of megabytes long.

After a clean session, PCP may compact the local journal atomically to:

- one validated header;
- the latest completion record for each destination-relative path; and
- the most recent `session_complete` and `cleanup_complete` records.

Compaction reduces replay of superseded records but not the one-record-per-file
floor. If multi-million-file datasets are normal, a compact binary/indexed
format should follow. Parsing local sequential state is still expected to be
substantially cheaper than millions of NFS metadata round trips.

## Failure cases intentionally accepted

### Simultaneous matching resumes

Two matching processes can observe the same marker and local session before
either makes progress. Both may proceed. Eliminating this completely requires
a local lock or a distributed compare-and-swap/lease mechanism. Version 1
accepts the race rather than adding lock lifecycle and stale-lock handling.

### Independent jobs sharing one destination root

A single marker serializes the whole destination scope. Two different jobs
cannot concurrently populate disjoint names under the same destination root;
the second aborts on the first job's marker. Users who need independent
concurrency should name non-overlapping subdirectories as separate destination
roots. Version 1 does not implement per-subtree ownership or overlap analysis.

### Remote work briefly outliving the coordinator

After the coordinator dies, a destination server may still be finishing an
in-flight operation before noticing the closed connection. An immediate resume
can briefly overlap that work. With an unchanged source, both attempts write
the same intended content. Version 1 adds no lease or fencing protocol for this
narrow window.

### External destination changes

Normal fast reruns do not stat journal-complete destination files. An external
deletion or modification can therefore remain unnoticed. `-c`,
`--verify-only`, and the future forced-recheck mode must bypass this shortcut.

## Expected benefit

For archive copies, PCP already avoids resending bytes for completed files.
The journal improves planning and restart latency.

The benefit is asymmetric because the journal removes destination metadata
requests, not the required source scan. A push from a fast local source to a
slow NFS destination is the primary win. A pull from NFS to a fast local
destination still pays for the expensive NFS source scan, so its improvement
is usually modest. For NFS-to-NFS copies, the journal removes most repeated
destination-side work but cannot remove the source-side scan.

For a large small-file tree on shared NFS, a resume or completed rerun should
require:

- one source scan;
- local completion-record lookups for known files;
- destination probes only for unrecorded or source-changed files; and
- existing block comparison for incomplete partials.

The destination marker independently ensures that every machine mounting the
same destination sees that another session may have left it incomplete.

## Implementation sequence

1. Define job identity, job key, session ID, and marker-location rules.
2. Add marker create/read/conditional-remove operations on the destination
   filesystem.
3. Implement persistent job-keyed JSONL journal parsing and truncated-tail
   handling.
4. Append completion records after destination success and source
   revalidation.
5. Integrate journal lookups before destination `StatMany` planning for normal
   copies.
6. Explicitly bypass journal skipping for `-c` and `--verify-only`.
7. Durably append `session_complete`, remove only the matching marker, restore
   root metadata, append `cleanup_complete`, and retain the journal.
8. Add optional atomic compaction after clean sessions.
9. Test shared-NFS visibility through two mount aliases, interrupted resume,
   completed rerun, both cleanup crash windows, marker mismatch, missing
   journal, truncated journal, reserved-path collision, root-scope
   serialization, and simultaneous marker creation.
10. Benchmark cold planning, interrupted resume, and completed rerun on a
    representative multi-million-file NFS tree.
