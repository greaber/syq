# Automation interface v1

The native mutating commands expose one machine-readable results contract:

```sh
syq cp ... --results=- --quiet
syq cp-prune ... --results=run.ndjson
syq rm ... --results=run.ndjson
```

`--results` is newline-delimited JSON (NDJSON). It is independent of human
stdout/stderr and of `--progress-json`. Use `--quiet` when writing results to
stdout so stdout contains only records. `syq map` already owns stdout as its
mapping stream and does not accept `--results`.

Version 1 deliberately uses the same record types for live and dry runs. A
consumer can switch `--dry-run` without changing its decoder: operation
records have `disposition: "planned"` in a dry run and `"succeeded"` or
`"failed"` in a live run, while terminal aggregates separate planned and
completed work.

## Stream invariants

Every record contains:

- `schema: "syq.automation"` and `schema_version: 1`;
- one nonempty `run_id`, unchanged throughout the stream;
- `seq`, beginning at zero and increasing by exactly one; and
- nonnegative `elapsed_ms`, measured from creation of the results writer.

A normally completed stream begins with exactly one `run` record and ends
with exactly one `result` record. Nothing follows `result`. Consumers must
also reap syq and require the `result.exit_code` to equal the process status.
EOF without a terminal result is incomplete even when the process exited zero;
this detects crashes, kills, output failures, and incompatible executables.

CLI or connection failures that happen before the results writer can start do
not produce a stream. The process status and stderr remain authoritative for
that case.

For a direct remote-to-remote copy, use `--results=-`; named results files are
refused because the copy orchestrator runs on the source host. The stdout
stream is forwarded to the invoking host and is what the Python client uses.

Within schema version 1, producers may add fields to existing records.
Consumers must ignore fields they do not use. New record types, required
fields, enum values, or changed meanings require another schema version.

## Paths

Paths are lossless tagged objects:

```json
{"encoding":"utf-8","value":"dir/file","display":"dir/file"}
{"encoding":"base64","value":"cmF3Lf8=","display":"raw-�"}
```

`value` is either Unicode text or standard padded base64 of the raw Unix path
bytes. `display` is diagnostic only and must never be used to reconstruct a
path. Copy operation paths are relative to the destination placement root.
Removal paths use the endpoint-resolved spelling reported by `syq rm`.

## Records

### `run`

The first record adds:

- `syq_version`;
- `mode`: `cp`, `cp-prune`, or `rm`;
- `dry_run`: whether mutations were suppressed; and
- `mapping`: whether `cp` consumed a mapping manifest.

### `operation_result`

An operation record contains `action`, `dst`, `kind`, and `disposition`.
Depending on the operation it may also contain `src`, `bytes`, `attempts`,
`retryable` (`yes`, `no`, or `unknown`), and `message`.

Version 1 reports file transfers, directory/symlink/special creation, and
removals. Unchanged objects, policy exclusions, and metadata-only updates are
aggregate-only. Failed mapping operations carry `src`, `dst`, and `kind` when
that identity is sufficient to construct a retry mapping entry. The stream is
observation, not automatic retry authorization.

### `warning` and `error`

A warning contains a stable `code`, aggregate `count`, and `message`. An error
contains `class`, `retryable`, and `message`. Human stderr may contain more
diagnostic context; consumers must not parse it as a substitute for these
fields.

### `result`

The terminal record contains `status` (`success`, `partial`, `refused`, or
`failed`), `exit_code`, and these aggregates:

```text
files_planned                 files_completed
files_unchanged               files_excluded
directories_planned           directories_completed
symlinks_planned              symlinks_completed
specials_planned              specials_completed
deletions_planned             deletions_completed
deletions_blocked             errors
bytes_planned                 bytes_completed
bytes_unchanged
```

Completed counts never exceed their corresponding planned counts. All
completed mutation counts are zero in a dry run. `success` has exit code zero;
other statuses have a nonzero exit code. `partial` means some work failed but
the command settled its queue, `refused` means a policy such as `--max-delete`
prevented a planned phase, and `failed` means the run aborted.

## SDK conformance

The Python client validates the full envelope, path encoding, known record and
enum values, dry/live dispositions, aggregate relationships, terminal
presence, and process-status agreement. It delivers records incrementally to
`on_event` without retaining an unbounded operation ledger.

The native option inventory in `sdk/python/native-api.json` is checked against
the Rust command definitions. A native change must classify each new option as
implemented by Python, SDK-internal, a CLI-only alias/presentation control, or
`follow_up`. Ordinary feature work may use `follow_up`; the release workflow
refuses to publish syq while any such entry remains. After the change reaches
`master`, the Python API synchronization workflow creates or updates a tracking
issue and closes it once the inventory is synchronized. Candidate tests then
run the typed Python `cp`, `cp-prune`, `rm`, and `map` paths against the exact
syq binary that CI built.
