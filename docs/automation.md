# Automation results

Native `cp` and `rm` can write structured outcomes alongside human output:

```sh
syq cp --srcs-in project --into backup --results copy.ndjson
syq rm old-output --results removal.ndjson
```

Each line is a JSON record. **Require a final `result` record before trusting
completion.** EOF without one means the outcome is unknown, even if no error
record appeared.

This page describes stream semantics. The
[JSON Schema](https://github.com/greaber/syq/blob/master/schemas/automation.schema.json)
lists precise field shapes;
[example streams](https://github.com/greaber/syq/tree/master/tests/fixtures/automation)
show complete runs. Mapping manifests are a [different format](mappings.md#the-format).

## The channel

`--results FILE` creates a fresh regular file and refuses an existing one.
Use a new name for each run and keep it outside trees being copied or removed.
`--results-fd N` uses an already opened writable descriptor above 2:

```sh
syq cp project --into backup --results-fd 3 3>copy.ndjson
```

Use a descriptor for pipes or other non-regular sinks. Named results paths
follow the normal native symlink rules; `--follow` permits traversal.
Human stdout and stderr are not part of this contract.

Results are written on the invoking machine, including for remote removal.
For direct restricted remote-to-remote copies, they are derived from the
verified destination receipt and marked `provenance: "receiver_attested"`.
Those records arrive after receipt verification. Otherwise remote-to-remote
results require `--coordinate-at local`, which relays data through your
machine. Remote-to-remote `--dry-run --results` and `--verify-only --results`
also require that local route.

`--results` supports native `cp` (including pruning) and `rm`. It cannot be
combined with `--detach`. The restricted receiver supports copy changes,
including capped pruning, but not native removal.

Records arrive in `seq` order; error and terminal records are flushed
immediately. If writing the stream fails, syq warns where possible and stops
writing it. Filesystem work can continue, leaving an incomplete stream.

Argument errors exit 2 without a stream. Failure to open the results sink
exits 1 without a stream. Once opened, completed runs and fatal setup failures
emit a terminal record if the sink remains writable. Crashes and interruptions
can leave it missing.

## Consumer rules

- Check the terminal record and process exit code; a mismatch is a protocol
  error. Use terminal totals, not progress or a count of operation records.
- Build [mapping retries](mappings.md#machine-readable-results) only after
  terminal `success` or `partial`. Other statuses can leave entries unresolved.
- Ignore unknown record types and optional fields within a supported schema
  version.
- Reject unknown `schema`, `schema_version`, terminal `status`, or path
  `encoding` values.
- Treat human `message` text as display only; parse structured fields.

`--progress-json` is a separate progress display whose format may change.
Use `--results` when you need a stable consumer contract.

## Record envelope

Every record carries:

| Field | Value |
|---|---|
| `schema` | `"syq.automation"` |
| `schema_version` | `1` |
| `seq` | Integer starting at 0, strictly increasing |
| `type` | Record type |

Paths are tagged: `{"encoding":"utf-8","value":"docs/a.txt"}`, or
`encoding: "base64"` with standard base64 of raw filename bytes. Byte and
count fields are non-negative integers within the `u64` range.

## Record types

### `run`

Always first. Identifies the invocation with `run_id`, `started_at` (Unix
seconds), `syq_version`, `mode` (`cp` or `rm`), `dry_run`, and `endpoints`.
Endpoints identify role, local/SSH kind, and SSH host/user; they omit
credentials, ports, and raw command arguments.

Copy runs also carry `prune` and `mapping`. Compare-only runs add optional
`verify_only: true`; absence means false. Removal has one source endpoint
regardless of selector count and omits those copy fields.

With `--verify-only`, differences and inspection failures produce `error`
records and a nonzero terminal status. Matching regular files count as
`files_unchanged` and `bytes_unchanged`; transfer and creation totals remain
zero. Successful comparisons do not emit copy operations. Progress bytes
measure comparison work, not bytes written. As with dry runs, use
`--coordinate-at local` for JSON comparison results between two remote hosts;
a receiver receipt cannot attest the source's comparison claims.

### `progress`

Sampled telemetry, approximately once per second, for displays rather than
accounting. It includes bytes, files, exclusions, scan state, and elapsed time.
Removal has zero byte and unchanged/excluded counts; its file counts reflect
outcomes received so far. The terminal record owns final totals.

### `trace`

One intended copy change in a dry run. Includes action, destination, source
for mapping entries, kind and bytes where applicable, plus a `reason`:
`destination_missing`, `type_differs`, `content_differs`, `metadata_differs`,
or `destination_only`.

A trace cannot be matched by identity to a later live operation: the filesystem
may change between runs.

### `operation_result`

An outcome for a completed copy change or a failed mapping entry.

| Field | Meaning |
|---|---|
| `action` | `transfer_file`, `create_directory`, `create_symlink`, `create_special`, or `delete`; attested streams also use `set_metadata` and `observe_hash` |
| `dst` | Path relative to the destination container |
| `src` | Mapping source path, where available; absent for ordinary copies and deletions |
| `kind` | `file`, `dir`, `symlink`, or `special`, when known |
| `disposition` | `succeeded`, `failed`, `blocked`; attested streams also use `incomplete` and `observed` |
| `bytes`, `attempts` | Optional transfer information |
| `retryable` | On failures: `yes`, `no`, or `unknown` |
| `class`, `os_kind`, `message` | Error details where available |
| `provenance`, `scope`, `code` | Attested origin, signed destination-scope index, and receiver outcome code |

In attested records, `dst` is relative to the destination area identified by
`scope`. An attested `set_metadata` omits `kind`.

Unchanged and excluded entries have totals only. Ordinary live streams do not
emit per-operation records for metadata-only updates, though dry runs emit
`metadata_differs` traces. Failed implicit parent creation can lack `src` and
is non-retryable. Do not construct a retry source from its destination name.

### Removal records

| Type | Meaning |
|---|---|
| `selection_result` | One explicit selector resolved or found missing |
| `removal_trace` | One entry that a dry run would remove |
| `removal_result` | One finished removal or inspection failure |

`selection_result` uses a zero-based `selector` index, the original `path`,
`status` (`resolved` or `missing`), and `kind` when resolved. Missing selectors
succeed. Overlapping or duplicate selectors keep separate indexes. If a later
selector cannot resolve, earlier selection records may precede the fatal
error and terminal record.

`removal_trace` includes selector, path, kind, and
`disposition: "would_remove"`. Directories follow their descendants.

`removal_result` includes selector, path, kind when known, attempts, and
`disposition`: `removed`, `already_absent`, or `failed`. Already absent is
success. Failures include error details and retryability where available,
and also produce a counted `error` record. Dry-run inspection failures can
produce failed removal results, but never successful removal results.

### `error`

One per counted error. `message` is display text; `class` and `os_kind` are
provided where known. Classes are `io`, `transport`, `conflict`, `integrity`,
`safety_limit`, `usage`, and `internal`.

OS kinds are `not_found`, `permission_denied`, `already_exists`,
`invalid_input`, `no_space`, `quota_exceeded`, `read_only`, and `other`.
They preserve OS error meaning across hosts without requiring matching errno
numbers. Receiver refusals use `class: "safety_limit"` with provenance and
the receiver's `code`.

### `final_state`

Attested streams only: the destination's final observation of a path the
transfer could have changed. Includes `scope`, `dst`, and an `object`:
absent, an observation failure, or present with kind, size, applicable
metadata, and symlink target. With `--receiver-receipt digests`, regular
files also have a BLAKE3 digest.

Object kinds distinguish directories, files, symlinks, FIFOs, sockets,
character/block devices, and other objects. Metadata fields are `mode`, `uid`,
`gid`, `mtime`, `mtime_nsec`, and `rdev`. Consult the schema for exact shapes.
This observes destination state; it does not attest source completeness.

### `result`

Exactly one terminal record, always last when the stream completes. Common
fields are `status`, `exit_code`, `dry_run`, `errors`, and `elapsed_ms`.

Copy totals include transferred/unchanged/excluded files, created directories,
symlinks and specials, transferred/unchanged bytes, and on pruning runs
`deletions_planned`, `deletions_completed`, and `deletions_blocked`. A fatal
failure reports what finished before it stopped. Dry-run totals describe
planned work, not committed changes.

Attested terminals add `receipt_status` (`clean`, `failed`, or `incomplete`),
provenance, and receipt counts. They can attest only what the receiver saw:

- Unchanged and excluded totals are zero, not a claim that every source entry
  changed.
- Only `deletions_completed` appears; planned and blocked deletion totals are
  omitted.
- `errors` counts attested error records for failed/incomplete operations,
  refusals, and failed or partial final-state observations.

Removal terminals have `mode: "rm"` and totals for selectors, resolved and
missing selectors, planned/removed/already-absent entries, and failed entries.
Live removal leaves `entries_planned` zero. Dry removal leaves
`entries_removed` and `entries_already_absent` zero, but inspection failures
may increase `entries_failed`.

The human summary uses the same terminal totals.

## Exit codes

| Code | Terminal status | Meaning |
|---|---|---|
| `0` | `success` | Requested operation succeeded |
| `1` | `failed` / `aborted` | Fatal failure or abort |
| `2` | No stream | Invalid arguments |
| `23` | `partial` | Per-entry failures; independent work finished |
| `25` | `refused` | A safety cap refused deletions |

Removal terminals use only `success`, `partial`, or `failed`. A results-sink
startup error also exits 1 without a stream.

## Compatibility

Within a schema version, required fields keep their types and meanings;
existing types, actions, dispositions, statuses, classes, and reasons are not
renamed or reused. New record types and optional fields may be added. Human
messages may change at any time.
