# PCP interrupted-transfer resume design

**Status:** proposed design, not yet implemented.

## Purpose

PCP already resumes without retransmitting most data. On a repeated archive
copy, files whose size and modification time match are skipped. For an
incomplete large file, PCP hashes the source and `.pcp-partial` file in blocks
and sends only the blocks that differ.

That design is data-efficient, but resuming a tree with many small files still
requires scanning the source and issuing destination metadata requests for the
whole tree. On NFS, those destination `stat` operations can dominate the time
before useful work resumes.

This design adds:

1. a persistent destination-side session marker, which prevents an unrelated
   PCP command from accidentally using the same destination; and
2. a local append-only journal of files known to have completed, which lets a
   repeated invocation avoid destination metadata requests for those files.

The design deliberately targets the common case: a transfer is interrupted
and the same user reruns the same command from the same coordinating machine.
It is not intended to be a distributed transaction system.

## Operating assumptions

Version 1 relies on the following assumptions:

- The source is not intentionally changed during or between attempts.
- The destination is not independently changed by another tool or user.
- A transfer is normally resumed by the same user on the same coordinating
  machine.
- The common failures are Ctrl-C, a lost connection, or a crashed PCP process.
- It is acceptable for an extremely narrow simultaneous-resume race to remain.
- Power-loss durability is promised only when the existing `--fsync` option is
  used.

PCP should continue its existing post-transfer source re-stat. The assumptions
above mean that PCP does not need a remote per-file completion manifest,
distributed leases, fencing tokens, or full destination verification during a
normal resume.

## Explicit non-goals

The first implementation will not attempt to guarantee correct resume when:

- source files are modified while the copy is running;
- completed destination files are deleted or modified outside PCP;
- two resume attempts start at almost exactly the same time;
- a session is moved automatically to a different coordinating machine;
- the same filesystem destination is reached through different remote hosts,
  users, mount namespaces, or aliases that normalize to different endpoint
  identities; or
- a destination acknowledges a non-`--fsync` write and subsequently loses it
  in a machine or storage-system power failure.

Users who need to check for external destination changes can use the existing
quick comparison, `-c`, or `--verify-only`. Those checks should remain separate
from the fast ordinary-resume path.

## Terminology

### Session

A **session** is the logical transfer across all of its interrupted attempts.
It has a randomly generated 128-bit session ID. The session ID is an identity,
not a secret or authentication credential.

### Attempt

An **attempt** is one running PCP process participating in a session. Each
attempt records its coordinator host, boot identity, PID, and process start
time in the local journal.

### Remote marker

The **remote marker** is a small persistent JSON document on the destination
endpoint. Its existence claims the normalized destination for one session.

The marker is created atomically, but PCP does not hold an advisory lock on it.

### Local journal

The **local journal** is an append-only JSON Lines file on the machine running
the orchestrator. It contains the session header, attempt records, and
completion records.

For a push, that is normally the invoking machine. For direct or detached
remote-to-remote operation, it is the source machine where the PCP
orchestrator actually runs.

## State locations

State must not be written into the source directory. The source may be
read-only, may be a single file, and may itself be copied recursively. Keeping
PCP state there would also create naming and multi-destination conflicts.

### Local journal location

Use:

```text
$XDG_STATE_HOME/pcp/transfers/<session-id>.jsonl
```

with this fallback when `XDG_STATE_HOME` is unset:

```text
$HOME/.local/state/pcp/transfers/<session-id>.jsonl
```

The directory should be mode `0700` and journal files should be mode `0600`.
`/tmp` is not suitable because the journal must survive reboot-time or periodic
temporary-file cleanup.

### Remote marker location

The destination endpoint should keep markers in its per-user PCP state
directory, keyed by a stable hash of the normalized destination identity:

```text
$XDG_STATE_HOME/pcp/destinations/<destination-key>/session.json
```

with the analogous `$HOME/.local/state` fallback.

Keeping the marker outside the copied tree prevents it from colliding with a
source file or being included in the transfer. It also avoids requiring write
access to the source directory.

This v1 location coordinates jobs that use the same destination endpoint and
user. It does not attempt to recognize that two different remote hosts happen
to mount the same underlying NFS directory.

No global dictionary from destinations to nonces is required. The remote
marker is found from the destination key and supplies the session ID; that ID
directly names the local journal.

## Normalized transfer identity

The session header and remote marker must contain enough information to reject
using a journal for a different path mapping. At minimum, record:

- the source endpoint and normalized source root or roots;
- whether each source uses trailing-slash "copy contents" semantics;
- the destination endpoint and normalized destination root;
- the effective content and metadata options;
- the state format version; and
- the PCP session ID.

Content-affecting options include recursive traversal, symlink handling,
archive/metadata flags, devices and special files, `--inplace`, and `--atomic`.
Operational options such as progress display, verbosity, worker count, TCP
selection, and compression do not need to be identical for a resume.

Existing paths should be canonicalized by the endpoint. A nonexistent final
component should be normalized lexically relative to the canonical nearest
existing parent. The normalized identity is stored in the marker as well as
hashed into the destination key, so an accidental hash collision or
normalization bug can be detected before resuming.

## Remote marker format

An illustrative marker is:

```json
{
  "format": 1,
  "session_id": "80e00c95b8ff4d108e125bc8d29166fd",
  "source_identity": "sha256:...",
  "destination_identity": "sha256:...",
  "options_identity": "sha256:...",
  "created_at": "2026-08-27T15:00:00Z",
  "coordinator_host": "workstation-a"
}
```

The marker is small and rewritten only if the marker format itself must be
upgraded. Per-file completion is not written remotely.

## Local journal format

The journal is JSON Lines rather than one JSON array. Rewriting a large JSON
document for every completed file would be increasingly expensive and would
make interruption recovery more fragile.

Illustrative records are:

```json
{"type":"header","format":1,"session_id":"80e00c95b8ff4d108e125bc8d29166fd","source_identity":"sha256:...","destination_identity":"sha256:...","options_identity":"sha256:..."}
{"type":"attempt","host":"workstation-a","boot_id":"...","pid":12345,"process_start":987654321,"started_at":"2026-08-27T15:00:00Z"}
{"type":"complete","path_b64":"YS9maWxlMQ==","kind":"file","size":1234,"mtime_sec":1700000000,"mtime_nsec":123456789,"basis":"transferred"}
{"type":"complete","path_b64":"Yi9maWxlMg==","kind":"file","size":9876,"mtime_sec":1700000001,"mtime_nsec":987654321,"basis":"quick-check"}
```

Paths must be encoded without assuming UTF-8; base64 is sufficient for the JSON
format. The implementation may use a compact binary journal later without
changing the session semantics.

The latest valid completion record for a path wins. This permits a file to be
reprocessed and recorded again without editing earlier journal contents.

A malformed or unterminated final line is treated as a crash-truncated tail and
ignored. A malformed interior record indicates journal corruption and should
abort fast resume rather than guessing.

## Creating a new session

For a destination with no marker:

1. Normalize the source, destination, and semantic options.
2. Generate a random 128-bit session ID.
3. Create the remote marker with exclusive-create semantics
   (`O_CREAT|O_EXCL`, Rust `create_new`, or the endpoint equivalent).
4. If exclusive creation reports that the marker already exists, do not
   overwrite it. Read the winner and restart the existing-marker decision flow.
5. Create the local journal named by the session ID and write its header and
   first attempt record.
6. If local journal creation fails, remove the remote marker only after
   rereading it and confirming that it still contains this session ID. Then
   abort without starting file operations.
7. Begin the ordinary scan and transfer.

Atomic remote creation is the only required interlock. PCP does not perform a
separate check-then-write sequence, because two new jobs could otherwise both
observe an absent marker and proceed.

## Resuming an existing session

When a remote marker exists:

1. Read and validate the marker format and destination identity.
2. Use its session ID to locate the local journal.
3. If no matching local journal exists, abort with a clear diagnostic. Automatic
   cross-machine adoption is outside the first implementation.
4. Validate the journal header against the current source, destination, and
   semantic options. A mismatch aborts rather than silently starting a
   different mapping in the same session.
5. Read the most recent attempt record.
6. If it names this coordinator host and boot, and the recorded PID still has
   the same process start time, report that the transfer is already running and
   abort.
7. Otherwise append a new attempt record and proceed with resume.

The boot ID and process start time prevent a reused PID from being mistaken for
the old PCP process. The process information is an ordinary-use liveness check,
not an atomic lock. Two resume processes that execute the dead-process check at
the same instant can both proceed; this race is accepted by the v1 assumptions.

## Recording completion

A regular file becomes journal-complete only after:

1. the destination reports that its write/finalize operation succeeded; and
2. PCP's existing source re-stat confirms that the source size and modification
   time did not change during the copy.

The completion record contains the source kind, size, mtime seconds, and mtime
nanoseconds observed by that successful attempt. No additional source hashing
is required for the normal journal path.

A file that was found complete through the ordinary destination quick check may
also be recorded with `basis: "quick-check"`. Doing so lets later attempts
avoid repeating the same destination metadata request.

The first implementation may journal only regular files. Directories,
symlinks, and special files can continue through the current planner; regular
small files provide the primary NFS metadata benefit.

## Using completion records

The source still must be scanned on resume so PCP can discover new and
unfinished files. For every scanned regular file:

1. Look up its latest journal completion record by destination-relative path.
2. Compare the current source kind, size, and nanosecond mtime with the record.
3. If they match, count the file as complete without issuing a destination
   `stat` and without retransferring it.
4. If they do not match, ignore the record and send the file through PCP's
   existing destination probe, quick-check, partial hashing, and transfer flow.

This inexpensive source fingerprint check catches common accidental source
changes. It does not claim to detect content changed while size and mtime were
deliberately preserved; changing the source is outside the v1 contract.

Files with no completion record use the existing PCP behavior. In particular,
an existing `.pcp-partial` remains the authoritative state for an unfinished
large file and is compared block-by-block.

## Journal buffering and crash behavior

Completion records may be buffered and flushed in batches by count or time.
They do not require an `fsync` after every file.

The ordering rule is important: a completion record is never generated before
destination success and source revalidation. Therefore:

- If PCP crashes after the remote file completes but before its journal record
  is flushed, the next attempt performs an unnecessary destination check or
  retransmission. This is safe.
- If the journal record is present, it represents a destination success already
  acknowledged during this session under the operating assumptions.
- A truncated last journal line is ignored, producing the same safe false
  negative.

When `--fsync` is selected, destination success retains the stronger durability
meaning already provided by that option. The local journal itself still need
not be synchronously updated per file because loss of a completion record only
causes repeated work.

## Completion and cleanup

Only after the entire transfer, including deferred directory metadata, finishes
without errors should PCP:

1. flush the local journal;
2. reread the remote marker and confirm that its session ID matches;
3. remove the remote marker; and
4. remove the local journal, or optionally retain it briefly as a diagnostic
   completed-session record.

If PCP exits because of interruption or any transfer error, both marker and
journal remain so the command can be resumed.

## Missing or abandoned local state

If the remote marker exists but its local journal has been lost, PCP cannot use
the fast journal path and should abort by default. The diagnostic should report
the session ID, coordinator host, normalized destination, and marker location.

A later explicit recovery command may support either:

- **adopt:** rebuild local knowledge using PCP's existing destination stats and
  partial-file hashing, then create a replacement journal for the same session;
  or
- **reset:** remove the marker after confirmation and begin a new session.

Neither operation is needed for the initial common-case implementation. Manual
reset must never delete destination data or `.pcp-partial` files; a new session
can safely reuse those partials through the existing block comparison.

## Failure cases intentionally accepted

### Simultaneous resume race

Two processes can read the same dead attempt record before either appends its
new attempt record. Both may then run. Avoiding this completely requires an
atomic local lock or compare-and-swap mechanism. The first implementation
accepts this unlikely race rather than adding lock lifecycle and filesystem
compatibility complexity.

### Remote work briefly outliving the coordinator

After the coordinating process dies, a remote server may still be finishing an
in-flight filesystem operation before it notices the closed connection. An
immediate resume can briefly overlap that operation. With an unchanged source,
the old and new attempts write the same intended content. The first design does
not add a remote lease or fencing system for this narrow window.

### External destination changes

A journal-complete file is not statted during fast resume. If another tool
deletes or modifies it, fast resume can leave the destination incomplete or
stale. Users requiring that guarantee must run with a verification workflow.
This trade-off is what removes the destination metadata round trips that the
journal is intended to avoid.

## Expected benefit

For archive copies, the current implementation already avoids sending bytes for
completed files. The journal's main benefit is therefore faster planning and
restart, not lower byte counts.

For a large small-file tree on NFS, a resume should require:

- one source scan;
- local journal lookups for known-complete files;
- destination probes only for files absent from the journal or whose source
  fingerprint changed; and
- the existing block comparison for incomplete partials.

This preserves PCP's current self-validating partial-file resume while removing
most repeated destination metadata latency in the common interrupted-transfer
case.

## Implementation sequence

1. Define normalization and session identity types.
2. Add destination marker create/read/remove protocol operations.
3. Implement local state-directory discovery and JSONL journal parsing.
4. Record attempt identity and ordinary liveness diagnostics.
5. Append completion records after destination success and source revalidation.
6. Integrate journal lookups before destination `StatMany` planning.
7. Remove marker and journal only after completely successful transfers.
8. Add interruption, truncated-journal, live-PID, identity-mismatch, and
   simultaneous-new-session tests.
9. Benchmark cold resume versus journal resume on a representative NFS
   small-file tree.

