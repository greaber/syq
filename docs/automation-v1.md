# Automation results, schema version 1

`syq cp --results FILE` writes a machine-readable NDJSON stream of
operation outcomes. This document is the contract for that stream:
what each record means, which fields a consumer may rely on, and how
exit codes correspond to terminal statuses. The machine-checkable
counterpart is [`schemas/automation-v1.schema.json`](../schemas/automation-v1.schema.json);
example streams live in
[`tests/fixtures/automation-v1/`](../tests/fixtures/automation-v1/).
For the mapping manifest *input* format, see
[`MAPPINGS.md`](../MAPPINGS.md) — `syq map` output is a manifest, not
this stream, and the two formats never mix.

## The channel

```text
syq cp [--prune] ... --results FILE|-
```

One mechanism, two spellings. With `FILE`, the stream is a sidecar
beside the ordinary human output: watch progress on the terminal,
keep the records. With `-`, the machine owns stdout — syq suppresses
its own human stdout (no `-q` needed); stderr stays human-readable
and is not part of the contract. `--results` is not available on
`syq map` (its stdout is the manifest format) or, yet, on other
commands. `--dry-run` composes; see below.

A `FILE` inside the transfer's own endpoints is refused before
anything is created — the run would copy, overwrite, or prune its own
results file. Mapping runs check only destination containment: their
source base defaults to `.`, and they read only manifest-listed
paths.

Records land in `seq` order. Error and terminal records are flushed
immediately. If writing the stream itself fails, syq warns once on
stderr and stops writing; the consumer detects this as a missing
terminal record. Argument and usage errors exit `2` with no stream at
all — a consumer constructs its own argv, so a usage error is a
consumer bug and gets no JSON. Every run that gets past argument
parsing emits a terminal record, fatal setup failures included.

## Record envelope

Every record is one JSON object per line carrying:

| Field | Value |
|---|---|
| `schema` | `"syq.automation"` |
| `schema_version` | `1` |
| `seq` | integer from 0, strictly increasing within the stream |
| `type` | one of the six record types below |

Paths are tagged objects, lossless for arbitrary filenames:
`{"encoding": "utf-8", "value": "docs/a.txt"}` when the path is valid
UTF-8, otherwise `{"encoding": "base64", "value": "..."}` holding the
standard base64 encoding of the raw bytes. Byte and count fields are
non-negative integers within `u64` range.

## Record types

### `run` — always first

Identifies the run: `run_id` (opaque string, unique per invocation),
`started_at` (unix seconds, wall clock), `syq_version`, `mode`
(`"cp"`), `prune` (bool), `mapping` (bool), `dry_run` (bool), and
`endpoints` — sanitized identities only: `role`
(`source`|`destination`), `kind` (`local`|`ssh`), and for ssh
endpoints `host` and, when given, `user`. Never credentials, ports,
or raw shell arguments.

### `progress` — sampled telemetry

Emitted at most about once per second: `bytes_done`, `bytes_total`,
`bytes_unchanged`, `files_done`, `files_total`, `files_unchanged`,
`files_excluded`, `scanned`, `scan_done`, `elapsed_ms`. Progress is
lossy by design — drive spinners and dashboards from it, never final
accounting; the terminal record is the only authority on totals.

### `trace` — dry-run only, one per intended mutation

Same identity fields as `operation_result` — `action`, `dst`, `src`
(mapping runs), `kind`, `bytes` where applicable — plus `reason`, the
explanation the same decision would print under `-v`:

`destination_missing` | `type_differs` | `content_differs` |
`metadata_differs` | `destination_only` (`--prune` deletions).

There is no identity linking a trace to an operation in a later real
run: the filesystem can change between the two, and the stream does
not pretend otherwise.

### `operation_result` — one per settled mutation

Also one per failed mapping entry. Fields: `action` (`transfer_file`
| `create_directory` | `create_symlink` | `create_special` | `delete`
(`--prune`)), `dst` (container-relative), `src` (base-relative;
mapping runs — a failed record round-trips as a retry manifest
entry), `kind` (`file`|`dir`|`symlink`|`special`), and `disposition`:
`succeeded` | `failed` | `blocked` (a `--max-delete` refusal).
Optional: `bytes`, `attempts`, and on failures `retryable`
(`yes`|`no`|`unknown`), `class`, `os_kind`, `message`. Unchanged and
excluded entries emit no per-operation records; they are aggregated
in the terminal record only. Metadata-only updates (permissions,
ownership, or times reconciled on an otherwise unchanged object) are
not reported per operation in v1 — a live run emits no record for
them, while a dry run does emit a `metadata_differs` trace for the
same situation. Closing that asymmetry with a metadata result action
is a candidate additive extension.

### `error` — one per counted error

`message` is display text, never a parsing contract. Optional `class`
and `os_kind` where the emission site knows them.

The seven classes each call for different consumer behavior: `io`
(the operation failed at the filesystem), `transport` (transient —
retry), `conflict` (permanent for this entry as given), `integrity`
(alarming — verification mismatch), `safety_limit` (a deliberate
refusal, e.g. `--max-delete`), `usage`, `internal`. `os_kind`
appears on local operations where the OS error is known: `not_found`,
`permission_denied`, `already_exists`, `invalid_input`, `no_space`,
`read_only`, `other`. Remote errors currently arrive as strings and
carry `class` only where the caller knows it.

### `result` — exactly one, always last, flushed

`status`: `success` | `partial` | `refused` | `aborted` | `failed`.
Plus `exit_code`, `dry_run`, and the aggregates:
`files_transferred`, `files_unchanged`, `files_excluded`,
`directories_created`, `symlinks_created`, `specials_created`,
`errors`, `bytes_transferred`, `bytes_unchanged`, `elapsed_ms`, and
on `--prune` runs `deletions_planned`, `deletions_completed`,
`deletions_blocked`. On a `failed` terminal record the aggregates
describe what settled before the run died.

The human summary is rendered from this same record, so the numbers a
person reads and a machine parses cannot disagree.

## Exit codes

| Code | Terminal status | Meaning |
|---:|---|---|
| `0` | `success` | Everything requested was done |
| `1` | `failed` / `aborted` | Fatal setup or transport failure / abort |
| `2` | — (no stream) | Argument or usage error |
| `23` | `partial` | Some entries failed; the rest settled |
| `25` | `refused` | A guard such as `--max-delete` refused the action |

The process exit status always equals the terminal record's
`exit_code`; treat a mismatch as a protocol error.

## Dry runs

`--dry-run --results` performs everything except mutations — full
scan, destination stats, per-entry decisions — and emits `trace`
records instead of `operation_result`s. The terminal record carries
`dry_run: true` with the same aggregate fields, meaning planned
rather than committed work. Deletion planning reports exact counts,
reports `blocked` under `--max-delete`, and skips as unsafe on scan
trouble exactly as a real run would.

## Consumer rules

- EOF without a terminal record means the outcome is unknown. Do not
  treat the absence of errors as success.
- Build retry manifests from the stream only when the terminal status
  is `success` or `partial`. Any other status means entries may be
  unsettled — rerun instead. (The retry recipe in `MAPPINGS.md`
  enforces both checks.)
- Ignore record types and optional fields you do not recognize;
  additions within schema version 1 are not breaking.
- Fail closed on an unknown `schema` value or `schema_version`, an
  unknown terminal `status`, or an unknown path `encoding`.

## Compatibility

Within schema version 1: required fields never change type or
meaning; existing types, actions, dispositions, statuses, classes,
and reasons are never renamed or reused; new record types and new
optional fields may be added; human `message` text may change at any
time. The JSON Schema in this repository is deliberately strict —
integration tests validate every line syq emits against it, so any
shape change fails a test and is reviewed as an API change. The
committed fixtures under `tests/fixtures/automation-v1/` are examples
of real streams (regenerate with
`scripts/regen-automation-fixtures.sh`); SDKs develop against them
without running syq.
