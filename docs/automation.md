# Automation results

Native `syq cp --results FILE` and `syq rm --results FILE` write the results
stream: a machine-readable NDJSON record (one JSON object per line) of what
each operation did. This document is the contract for that stream:
what each record means, which fields a consumer may rely on, and how
exit codes correspond to terminal statuses. The machine-checkable
counterpart is [`schemas/automation.schema.json`](https://github.com/greaber/syq/blob/master/schemas/automation.schema.json);
example streams live in
[`tests/fixtures/automation/`](https://github.com/greaber/syq/tree/master/tests/fixtures/automation).
For the format of a mapping manifest (the file of source→destination entries
that `syq cp --mapping` reads), see [Mappings](mappings.md): `syq map` output
is a manifest, not this stream, and the two formats never mix.

## The channel

```text
syq cp [--prune] ... --results FILE
syq cp [--prune] ... --results-fd N
syq rm ... --results FILE
syq rm ... --results-fd N
```

One stream, two ways to say where it goes. `--results FILE`
creates the file fresh and refuses an existing one: a results file
holds exactly one run (`seq` from 0, one terminal record), so
recurring jobs use fresh names; timestamps work well
(`run-$(date +%s).ndjson`). `--results-fd N` writes to a file descriptor
the caller opened before syq ran (`--results-fd 3 3>run.ndjson`, or a
pipe / process substitution for live consumption); N must be above 2,
and a descriptor nobody connected is a startup error. Human output is
untouched in both forms: stdout and stderr keep their usual roles
and are not part of this contract.

Choose a `FILE` outside the copy or removal trees.
syq does not police this: a results file inside the trees it is
copying, pruning, or removing can be copied mid-write, deleted, or otherwise
make the run's own accounting unpredictable. Placing output files in
directories only you can write is the same rule as for any `>` redirect. The
file is opened once and that open handle is held for the whole run. By default
syq refuses a `FILE` that is a symlink, as it does for any other path typed on
the command line (pass `--follow` to allow it).

The results stream is always written on the machine you invoke syq from. A
local removal and a removal over plain SSH both send each entry's outcome back
to that machine. The restricted receiver (the command-restricted receiver, a
forced command on hostB that syq installs when you enroll a destination)
rejects native removal: a signed grant authorizes the changes of one copy,
including that copy's `--prune` deletions under an explicit `--max-delete`
ceiling. There is no grant form for `syq rm`.

For a remote-to-remote copy there are two ways to fill the stream. Through the
restricted receiver, the stream is **receiver-attested**: built from hostB's
signed receipt rather than from what hostA reported. hostB records every
operation and, once the copy has closed, the final state of every path the
transfer could have changed. It puts those facts inside its encrypted, signed
receipt; the invoking machine verifies and decrypts it, and only then writes
the records, marked `"provenance": "receiver_attested"`, into the local file or
descriptor. Data still flows directly between the
remotes; only the verified account comes home. Without an enrollment there is
no trusted channel, so the run fails (with a `failed` terminal record) unless
`--coordinate-at local` explicitly routes the transfer through this machine;
syq never silently relays the data through your machine just to produce the
stream. For attested runs the human summary is also rendered locally from the
verified terminal record (the coordinator, the host that drives the copy,
reports its own summary, which is discarded), so the numbers a person reads
and a machine parses come from the same verified record. `--dry-run` with
`--results` needs a local coordinator (`--coordinate-at local`) today: traces
and planned totals exist only on the coordinator, a receipt cannot attest a
plan, and the coordinator's own stream is not relayed. `--results` is not
available on `syq map` (its stdout is the manifest format) or other commands.
It cannot be combined with `--detach`, because the caller would not remain
attached for the stream and its terminal record. `--dry-run` composes; see
below.

Records land in `seq` order. Error and terminal records are flushed
immediately. If writing the stream itself fails, syq warns once on
stderr and stops writing; the consumer detects this as a missing
terminal record. Failure to write human output does not change the copy or
removal result. For an attached receiver-attested copy, syq continues reading
and verifying the receipt even if forwarding human output to stdout fails;
a missing or invalid receipt still fails verification. Warnings are best effort
when stderr is also unavailable.

Argument and usage errors exit `2` with no stream at
all: a consumer constructs its own argv, so a usage error is a
consumer bug and gets no JSON. If the stream cannot be opened (the results
file already exists, or the descriptor is closed or read-only), syq exits `1`
with no stream. Once the stream is open, a completed run emits a terminal
record, fatal setup failures included, provided the stream stays writable.
A crash or interruption can also leave it incomplete.

## Record envelope

Every record is one JSON object per line carrying:

| Field | Value |
|---|---|
| `schema` | `"syq.automation"` |
| `schema_version` | `1` |
| `seq` | integer from 0, strictly increasing within the stream |
| `type` | one of the record types below |

Paths are tagged objects, lossless for arbitrary filenames:
`{"encoding": "utf-8", "value": "docs/a.txt"}` when the path is valid
UTF-8, otherwise `{"encoding": "base64", "value": "..."}` holding the
standard base64 encoding of the raw bytes. Byte and count fields are
non-negative integers within `u64` range.

## Record types

### `run` — always first

Identifies the run: `run_id` (opaque string, unique per invocation),
`started_at` (unix seconds, wall clock), `syq_version`, `mode` (`"cp"` or
`"rm"`), `dry_run` (bool), and `endpoints`, sanitized identities only: `role`
(`source`|`destination`), `kind` (`local`|`ssh`), and for ssh
endpoints `host` and, when given, `user`. Never credentials, ports,
or raw shell arguments. A copy run also has `prune` and `mapping` booleans and
source and destination endpoints. A removal run omits those copy-only fields
and has exactly one source endpoint, regardless of how many selectors it
contains.

### `progress` — sampled telemetry

Emitted at most about once per second: `bytes_done`, `bytes_total`,
`bytes_unchanged`, `files_done`, `files_total`, `files_unchanged`,
`files_excluded`, `scanned`, `scan_done`, `elapsed_ms`. Progress is
lossy by design: drive spinners and dashboards from it, never final
accounting; the terminal record is the only authority on totals.
Removal has no byte accounting, so its byte and unchanged/excluded fields are
zero; its file counts reflect endpoint outcomes delivered so far.

### `trace` — dry-run only, one per intended mutation

A mutation is any change a run makes at the destination: a create, an
update, or a delete. A trace has the same identity fields as
`operation_result` (`action`, `dst`, `src` on mapping runs, `kind`, and
`bytes` where applicable) plus `reason`, the explanation the same decision
would print under `-v`:

`destination_missing` | `type_differs` | `content_differs` |
`metadata_differs` | `destination_only` (`--prune` deletions).

There is no identity linking a trace to an operation in a later real
run: the filesystem can change between the two, and the stream does
not pretend otherwise.

### `operation_result` — one per settled mutation

A mutation is settled once it has finished, whether it succeeded or failed.
Also one per failed mapping entry. Fields: `action` (`transfer_file`
| `create_directory` | `create_symlink` | `create_special` | `delete`
(a path `--prune` removes) | `set_metadata` | `observe_hash`; the last two
appear in receiver-attested streams today), `dst` (relative to the
destination container), `src` (relative to the source base; mapping runs
only, and a failed record can be fed back as a retry manifest entry), `kind`
(`file`|`dir`|`symlink`|`special`; present when known, and a
receiver-attested `set_metadata` omits it), and `disposition` (the
outcome): `succeeded` | `failed` | `blocked` (a `--max-delete` refusal) |
`incomplete` | `observed` (receiver-attested streams). Optional: `bytes`,
`attempts`, on failures `retryable` (`yes`|`no`|`unknown`), `os_kind`, and
`message`, on failures and on blocked records `class`, and on
receiver-attested records `provenance`, `scope` (the index of the signed
mutation scope, one of the destination areas the grant allows writes in,
that `dst` is relative to), and `code` (the receiver's outcome code).
Unchanged and excluded entries emit no per-operation records; they are
counted in the terminal record only. Metadata-only updates (permissions,
ownership, or times reconciled on an otherwise unchanged object, that is,
an unchanged file, directory, symlink, or special file) are not reported
per operation in v1: a live run emits no record for them, while a dry run
does emit a `metadata_differs` trace for the same situation.

Copy streams use `trace` and `operation_result`; removal streams use the next
three record types instead.

### `selection_result` — one per explicit removal selector

Normally emitted after all selectors have been resolved and opened (syq opens
each selected path once and keeps that handle open for the whole run, so later
work is relative to the handle and renaming the path cannot redirect it),
before any removal outcomes. If a later selector fails resolution, already
resolved selector records can precede the fatal error and terminal record.
`selector` is the selector's zero-based argv order, `path` is its spelling as
the endpoint saw it, losslessly encoded, and `status` is `resolved` or
`missing`. A resolved selector includes its `kind`
(`file`|`dir`|`symlink`|`special`); a missing selector omits it. Missing
selectors are successful no-ops. Duplicate and overlapping selectors keep
distinct indexes, so consumers can attribute every later entry to the explicit
request that produced it.

### `removal_trace` — dry-run only, one per entry that would be removed

Carries `selector`, a lossless diagnostic `path` built from that selector's
spelling, `kind`, and `disposition: "would_remove"`. Directory entries appear after their
descendants, matching the order a real run removes them. A dry run never emits
successful `removal_result` records; an entry that could not be inspected still
emits a failed result so the incomplete plan has a stable per-path outcome.

### `removal_result` — one per settled removal or inspection failure

Carries `selector`, a lossless diagnostic `path` built from that selector's
spelling, `kind` when known, `attempts`, and `disposition`: `removed` |
`already_absent` | `failed`. Already-absent entries are successful: another
duplicate or overlapping selector may already have removed the same entry.
Failures additionally carry `retryable`, `class`, `message`, and `os_kind`
when the endpoint supplied one, and may appear during a dry run when inspection
of an entry fails. A failed entry also has a corresponding counted `error`
record; the result is the stable per-path identity, while the `error` records
are the tally the terminal `errors` count refers to.

### `error` — one per counted error

`message` is display text, never a parsing contract. Optional `class`
and `os_kind` where syq knows them at the point of reporting; a receiver refusal
arrives as an `error` with `class: "safety_limit"`, `provenance`, and
the receiver's `code`.

The seven classes each call for different consumer behavior: `io`
(the operation failed at the filesystem), `transport` (transient;
retry), `conflict` (permanent for this entry as given), `integrity`
(alarming; verification mismatch), `safety_limit` (a deliberate
refusal, e.g. `--max-delete`), `usage`, `internal`. `os_kind`
appears on endpoint operations where the OS error is known: `not_found`,
`permission_denied`, `already_exists`, `invalid_input`, `no_space`,
`quota_exceeded`, `read_only`, `other`. Filesystem errors preserve their OS
error meaning across remote connections even when the endpoints use different
numeric errno values. Errors without an OS classification cannot always be
classified more narrowly than `other`.

### `final_state` — receiver-attested streams only

One per path the transfer could have changed, observed by the
receiver at the end, after every request finished: `scope`, `dst`, and
an `object` that is `{"state": "absent"}`, an observation failure
(`state`, `code`, `message`), or `{"state": "present"}` with `kind`
(the receiver's precise vocabulary: `dir`, `file`, `symlink`, `fifo`,
`socket`, `character_device`, `block_device`, `other`), `size`,
`metadata` (`mode`, `uid`, `gid`, `mtime`, `mtime_nsec`, `rdev`), and, under
`--receiver-receipt digests`, a `digest` (`{"algorithm": "blake3", "value": <hex>}`), plus
`symlink_target` where applicable. Final states are what a verifier
audits: they describe the tree hostB ended with, not what the transfer
said it did.

### `result` — exactly one, always last, flushed

Every terminal carries `status`, `exit_code`, `dry_run`, `errors`, and
`elapsed_ms`. A copy result has `status`: `success` | `partial` | `refused` |
`aborted` | `failed`, plus the aggregates:
`files_transferred`, `files_unchanged`, `files_excluded`,
`directories_created`, `symlinks_created`, `specials_created`,
`bytes_transferred`, `bytes_unchanged`, and
on `--prune` runs `deletions_planned`, `deletions_completed`,
`deletions_blocked` (these count the destination-only paths that `--prune`
removes). On a `failed` terminal record the aggregates
describe what finished before the run died. A receiver-attested
terminal additionally carries `provenance`, the verified
`receipt_status` (`clean`|`failed`|`incomplete`), and receipt
bookkeeping (`operations`, `final_states`, `receipt_records`); its
aggregates cover work the receiver saw only: unchanged and excluded
entries are known only to the coordinator, a receipt cannot attest
them, and they read as zero. Of the deletion totals it carries only
`deletions_completed`, the finished deletions the receipt attests (each also
appears as an individual `delete` record); `deletions_planned` and
`deletions_blocked` never appear because planning and `--max-delete`
blocking happen on the coordinator, not at the receiver. Its `errors` count
equals the
receiver-attested `error` records emitted on the stream: one per
failed or incomplete operation, per refusal, and per failed or
partial final-state observation (a present object whose hash or link
target could not be read).

A removal result is distinguished by `mode: "rm"`, has `status`: `success` |
`partial` | `failed`, and carries `selectors_total`, `selectors_resolved`,
`selectors_missing`, `entries_planned`, `entries_removed`,
`entries_already_absent`, and `entries_failed`. Live runs leave
`entries_planned` at zero; dry runs leave `entries_removed` and
`entries_already_absent` at zero but may count entries that could not be
inspected in `entries_failed`. A fatal setup or transport failure reports what
finished before the failure and exits 1. Per-entry failures finish the remaining
independent work, report `partial`, and exit 23.

The human summary is rendered from this same record, so the numbers a
person reads and a machine parses cannot disagree.

## Exit codes

| Code | Terminal status | Meaning |
|---:|---|---|
| `0` | `success` | Everything requested was done |
| `1` | `failed` / `aborted` | Fatal setup or transport failure / abort |
| `2` | — (no stream) | Argument or usage error |
| `23` | `partial` | Some entries failed; the rest finished |
| `25` | `refused` | A guard such as `--max-delete` refused the action |

The process exit status always equals the terminal record's
`exit_code`; treat a mismatch as a protocol error.

## Dry runs

`--dry-run --results` performs everything except the writes themselves. Copy performs its
full scan, destination stats, and per-entry decisions and emits `trace` records
instead of `operation_result`s. Its terminal aggregate fields mean planned
rather than committed work. Prune planning reports exact counts, reports
`blocked` under `--max-delete`, and skips as unsafe on scan trouble exactly as
a real run would. Removal resolves and opens all selectors, walks every selected
tree, and emits `selection_result` plus `removal_trace` records; its terminal
`entries_planned` is the exact number of entries it would remove.

## Consumer rules

- EOF without a terminal record means the outcome is unknown. Do not
  treat the absence of errors as success.
- For copy, build retry manifests from the stream only when the terminal status
  is `success` or `partial`. Any other status means entries may never
  have been resolved; rerun instead. (The retry recipe in [the mappings guide](mappings.md)
  enforces both checks.)
- Ignore record types and optional fields you do not recognize;
  additions that leave `schema_version` unchanged are not breaking.
- Fail closed on an unknown `schema` value or `schema_version`, an
  unknown terminal `status`, or an unknown path `encoding`.

## Compatibility

While `schema_version` keeps its current value, required fields never
change type or meaning; existing types, actions, dispositions, statuses, classes,
and reasons are never renamed or reused; new record types and new
optional fields may be added; human `message` text may change at any
time. The JSON Schema in this repository is deliberately strict:
integration tests validate every line syq emits against it, so any
shape change fails a test and is reviewed as an API change. The
committed fixtures under `tests/fixtures/automation/` are examples
of real streams (regenerate with
`scripts/regen-automation-fixtures.sh`); client libraries can develop against
them without running syq.
