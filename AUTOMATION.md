# Automation schema v1

`syq cp [--prune] ... --results FILE|-` emits a versioned NDJSON event
stream. This is the stable machine-readable output consumed by the Python SDK
and other automation. `syq map` uses a separate, bare mapping-manifest format;
`syq rm` does not yet expose automation-v1 results.

With a named file, normal human output remains available. With `--results -`,
the event stream owns stdout and syq suppresses human stdout automatically.
Stderr remains diagnostic text and is not part of the protocol.

Every record contains:

```json
{"schema":"syq.automation","schema_version":1,"seq":0,"type":"run"}
```

`seq` starts at zero and increases by one in stream order. A complete stream
starts with exactly one `run` record and ends with exactly one `result` record.
EOF without a terminal result means the outcome is unknown, even when the
process exits successfully or every preceding operation appeared successful.

## Records

### `run`

The first record identifies the invocation:

- `run_id`: opaque run identifier;
- `started_at`: Unix time in seconds;
- `syq_version` and `mode` (`cp`);
- `prune`, `mapping`, and `dry_run` booleans; and
- `endpoints`: sanitized source and destination identities with `role`, `kind`
  (`local` or `ssh`), and optional `host` and `user`.

Credentials and raw remote-shell arguments never appear in endpoint records.
The run id and wall-clock start time appear only here, not on every event.

### `progress`

Sampled, lossy telemetry contains `bytes_done`, `bytes_total`,
`bytes_unchanged`, `files_done`, `files_total`, `files_unchanged`,
`files_excluded`, `scanned`, `scan_done`, and `elapsed_ms`. Final results are
not computed from progress samples.

### `trace`

Dry runs emit one trace for each intended mutation. A trace contains `action`,
`dst`, optional `src`, `kind`, optional `bytes`, and `reason`. Reasons are:

- `destination_missing`
- `type_differs`
- `content_differs`
- `metadata_differs`
- `destination_only` for a planned `--prune` deletion

Dry runs do not emit `operation_result` records. A trace describes the state
observed during that run; it is not a transaction or precondition for a later
copy.

### `operation_result`

Live runs emit settled mutations and failed mapping entries. Fields are
`action`, `dst`, optional `src`, `kind`, and `disposition`. Optional fields are
`bytes`, `attempts`, and, on failures, `retryable`, `class`, `os_kind`, and
`message`.

Actions are `transfer_file`, `create_directory`, `create_symlink`,
`create_special`, and `delete`. Dispositions are `succeeded`, `failed`, and
`blocked`. Retryability is `yes`, `no`, or `unknown`.

### `error`

Each counted error has a human-readable `message` and may have a structured
`class` and `os_kind`. Error classes are `io`, `transport`, `conflict`,
`integrity`, `safety_limit`, `usage`, and `internal`. Local OS kinds are
`not_found`, `permission_denied`, `already_exists`, `invalid_input`,
`no_space`, `read_only`, and `other`.

Messages are diagnostic presentation, never parsing contracts.

### `result`

The terminal record is authoritative and flushed immediately. It contains:

- `status`: `success`, `partial`, `refused`, `aborted`, or `failed`;
- `exit_code` and `dry_run`;
- `files_transferred`, `files_unchanged`, and `files_excluded`;
- `directories_created`, `symlinks_created`, and `specials_created`;
- `errors`, `bytes_transferred`, `bytes_unchanged`, and `elapsed_ms`; and
- on `--prune` runs, `deletions_planned`, `deletions_completed`, and
  `deletions_blocked`.

Dry and live calls use the same terminal result shape. During a dry run, the
mutation counts describe the work syq would perform; no mutation is committed.
The human summary is rendered from the same result structure.

Exit status and terminal status agree as follows:

| Exit | Status | Meaning |
|---:|---|---|
| 0 | `success` | Everything requested settled successfully |
| 1 | `failed` or `aborted` | Fatal setup, transport, or scheduler failure |
| 2 | no stream | Argument or usage error |
| 23 | `partial` | Some entries failed and the rest settled |
| 25 | `refused` | A safety guard refused the operation |

## Paths and integers

Paths are lossless tagged objects:

```json
{"encoding":"utf-8","value":"dir/file"}
{"encoding":"base64","value":"cmF3Lf8="}
```

There is no protocol `display` field. Consumers may decode a path lossily for
display without changing its byte identity. Counts and byte values are
non-negative integers in the unsigned 64-bit range.

## Consumer requirements

A v1 consumer must validate the schema major, sequence, first and terminal
records, required fields, path encodings, stable enum values, and agreement
between terminal and process status. It must ignore unknown record types and
unknown optional fields so additions remain compatible. It must fail closed on
an unknown schema major, terminal status, or path encoding.

Operation records need not be retained in memory. Consumers can stream them to
a ledger or callback and retain only the terminal result. A retry manifest is
safe to derive only after receiving a terminal result that says all queued
operations settled; an incomplete stream may omit operations the caller never
saw.

Within schema version 1, required fields do not change type or meaning and
existing record types, actions, dispositions, statuses, classes, reasons, and
path encodings are not renamed or reused. New record types and optional fields
may be added.
