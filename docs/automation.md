# Automation results

To drive syq from a script, have `syq cp`, `syq rm`, or `syq clean-partials`
write a stream of JSON records alongside their human output:

```sh
syq cp --srcs-in project --into backup --results copy.ndjson
syq rm --src-dir old-output --results removal.ndjson
```

Each line is one JSON record. **Require a final `result` record before trusting
completion.** EOF without one means the outcome is unknown, even if no error
record appeared.

The [JSON Schema](https://github.com/greaber/syq/blob/master/schemas/automation.schema.json)
gives exact field shapes, and the
[example streams](https://github.com/greaber/syq/tree/master/tests/fixtures/automation)
show complete runs. For mapping manifests, see [Mapping format](commands/map.md#mapping-format).
The last sections describe the JSON that the `syq persist` status,
pending-request, and permission commands print.

<a id="the-channel"></a>

## Writing results

`--results FILE` creates a new file and refuses an existing one, so use a new
name for each run and keep it outside the trees being copied or removed. For a
pipe or another open descriptor above 2, use `--results-fd N`:

```sh
syq cp project --into backup --results-fd 3 3>copy.ndjson
```

Syq follows a symlink in the `--results` path only with `--follow`. Human
stdout and stderr are not part of this contract.

Results are written on the machine where you run syq, also for remote removal
and for copies between two servers. In a
[restricted copy between servers](remote-reference.md#results-from-the-destination),
the destination runs a restricted receiver, which reports its own changes,
including the ones it refused or failed. `clean-partials` writes
[removal records](#removal-records). `--results` can't be combined with
`--detach`.

If writing the stream fails, syq warns and stops writing it, but the copy or
removal can continue. Once the stream is open, a completed run or a fatal
failure ends with a terminal record, preceded for a fatal failure by an `error`
record. A crash or interruption can leave the terminal record missing.

## Consumer rules

- Check the terminal record and process exit code; a mismatch is a protocol
  error. Use terminal totals, not progress or a count of operation records.
- Ignore unknown record types and optional fields within a supported schema
  version.
- Reject unknown `schema`, `schema_version`, terminal `status`, or path
  `encoding` values.
- Treat human `message` text as display only; parse structured fields.

## Exit codes

| Code | Terminal status | Meaning |
|---|---|---|
| `0` | `success` | Requested operation succeeded |
| `1` | `failed` / `aborted`, or no stream | Fatal failure or abort; with no stream, the results sink could not be opened |
| `2` | No stream | Invalid arguments |
| `23` | `partial` | Per-entry failures; independent work finished |
| `25` | `refused` | A safety cap refused deletions |

Removal terminals use only `success`, `partial`, or `failed`.

## Record envelope

Every record carries:

| Field | Value |
|---|---|
| `schema` | `"syq.automation"` |
| `schema_version` | `4`; `5` for stream mappings |
| `seq` | Integer starting at 0, strictly increasing |
| `type` | Record type |

Paths are tagged: `{"encoding":"utf-8","value":"docs/a.txt"}`, or
`encoding: "base64"` with standard base64 of raw filename bytes. Byte and
count fields are non-negative integers within the `u64` range.

## Record types

### `run`

Always first: `run_id`, `started_at` (Unix seconds), `syq_version` (as
`syq --version` prints it), `mode` (`cp` or `rm`), `dry_run`, and `endpoints`,
plus `prune` and `mapping` for copies. Each endpoint has a role and kind
(`local`, `ssh`, or `s3`). SSH endpoints carry host and user, and S3 endpoints
`host: "s3://BUCKET"`; none include credentials, headers, ports, or command
arguments. Removal has one source endpoint however many selectors it has.

### `progress`

About once a second, for progress displays rather than accounting: bytes,
files, exclusions, scan state, `timings`, and optional `rate_bytes_per_second`
and `eta_ms` estimates. With `--stats`, a filesystem copy's progress records
also carry [performance measurements](performance-measurements.md) in
`activity`. Removal reports zero bytes and zero unchanged and excluded counts.
A copy that finishes transferring always emits a final progress record.

### `trace`

In a dry run, one record for each change a live run would make: action,
destination, source for mapping entries, kind and bytes where applicable, and a
`reason`: `destination_missing`, `type_differs`, `content_differs`,
`metadata_differs`, or `destination_only`.

For regular files in filesystem copies, `content_differs` means the sizes or
compared hashes differ; `metadata_differs` also covers files selected by the
size-and-time check. A `transfer_file` trace has no `bytes` when only metadata
would change in place, but has them when syq would
[replace the file](reference.md#how-syq-changes-existing-files-and-directories)
to change its metadata; that file counts as transferred.

### `operation_result`

An outcome for a completed copy change or a failed mapping entry.

| Field | Meaning |
|---|---|
| `action` | `transfer_file`, `create_directory`, `create_symlink`, `create_special`, or `delete` |
| `dst` | Path relative to the destination container |
| `src` | Mapping source path, where available; absent for ordinary copies and deletions |
| `kind` | `file`, `dir`, `symlink`, or `special`, when known |
| `disposition` | `succeeded`, `failed`, or `blocked` |
| `bytes`, `attempts` | Optional transfer information |
| `expected_hash` | Expected whole-file digest, when supplied: an object with `algorithm` and hexadecimal `value`; preserve it in retry mappings |
| `metadata` | Explicit destination attributes from the mapping, when supplied; preserve them in retry mappings |
| `retryable` | On failures: `yes`, `no`, or `unknown` |
| `class`, `os_kind`, `message` | Error details where available |

A file that failed its [payload check](integrity-checking.md#payload-checks)
has `class: "integrity"` and, where the record has the field,
`retryable: "yes"`.

A restricted receiver's own records have no `src`, `attempts`, or
`retryable`, and a deletion has no `kind`. A file it didn't finish is `failed`,
and a change it refused is `failed` with `class: "safety_limit"`.

Unchanged and excluded entries appear only in totals, and a live run emits no
record for a metadata-only update. A parent directory that syq failed to
create implicitly can lack `src` and is not retryable.

### `stream_ready`

Tells the program supplying a
[descriptor copy's](commands/cp.md#file-descriptors) data that it can start
writing. Skipped copies and dry runs never emit it. The copy can still fail
afterwards, so wait for the terminal result.

### `stream_result`

Descriptor copies emit one `stream_result` instead of `operation_result` or
`trace` records. `source` and `destination` each contain either `path` (a
tagged path) or `fd` (the caller's descriptor number). Paths are the operands
you gave, with the source's basename appended for `--into`. An FD means
something only within this run.

`disposition` is `succeeded`, `failed`, `skipped`, or `planned`, and `dry_run`
marks a preview. `bytes` counts the bytes transferred, including partial work
on failure, or the planned bytes in a dry run; a preview of input of unknown
length omits it. A skipped copy reads no data, reports zero bytes, and counts
as one excluded file. In the terminal `result`, `bytes_total_known` is false
when the source length is unknown, and preview byte totals then count only
known bytes.

Stream mappings use schema version 5 and emit one `stream_result` for each
callback entry, with a zero-based `entry` index. Each endpoint is
`{"path": <tagged path>}` or `{"entry": N, "callback": true}`, and failed
entries include `message`. These records can't become a pathname retry
manifest; the
[Python callback reference](python-streams.md#callback-mappings)
describes publication and application retries. Pathname entries in the same
mapping still emit their usual records. These runs don't emit `stream_ready`:
the [stream-mapping protocol](stream-mappings.md#entry-lifecycle) starts each
entry instead.

### Removal records

| Type | Meaning |
|---|---|
| `selection_result` | One explicit selector resolved or found missing |
| `removal_trace` | One entry that a dry run would remove |
| `removal_result` | One finished removal or inspection failure |

`selection_result` has a zero-based `selector` index, the original `path`,
`status` (`resolved` or `missing`), and `kind` when resolved. A missing
selector is not an error. Overlapping or duplicate selectors each get their own
index.

`removal_trace` has the selector, path, kind, and
`disposition: "would_remove"`; a directory comes after its contents.

`removal_result` has the selector, path, kind when known, attempts, and a
`disposition` of `removed`, `already_absent` (a success), or `failed`. A
failure includes error details and retryability where available, and also
produces a counted `error` record. A dry run reports failed inspections as
failed results.

S3 version removal adds optional `s3_version_id` (string) and
`s3_delete_marker` (boolean) fields to `removal_trace` and `removal_result`;
each record and count then refers to one version or delete marker.

### `error`

One per counted error. `message` is display text; `class` and `os_kind` are
given where known. Classes are `io`, `transport`, `conflict`, `integrity`,
`safety_limit`, `usage`, and `internal`. OS kinds are `not_found`,
`permission_denied`, `already_exists`, `invalid_input`, `no_space`,
`quota_exceeded`, `read_only`, and `other`.

A restricted receiver's refusals use `class: "safety_limit"` and name
the refused path, or the receiver when the request named none. An error with
`diagnostic_for`, a destination path, is not counted in `errors`: it explains
why the receiver reported that path as failed.

### `result`

The terminal record: exactly one, always last when the stream completes.
Common fields are `status`, `exit_code`, `dry_run`, `errors`, and `timings`.

`timings` gives wall-clock milliseconds. Progress records carry the same
object, advancing as the work runs:

| Field | What it measures |
|---|---|
| `total_ms` | The whole measured run, including helper installation but not process startup and shutdown; use an external timer for those |
| `setup_ms` | Preparing endpoints and connections and choosing the data transport, excluding helper installation. Connections added while files are copying also count, so it can approach `total_ms` |
| `planning_ms` | Finding source entries, inspecting destinations, and deciding what to copy, including directories created meanwhile |
| `transfer_ms` | From the first file operation to the last, including reads, hashing, writes, per-file metadata, waits, and retries |
| `finalization_ms` | Work after file workers finish: remaining hardlinks, pruning, and directory metadata |
| `helper_install_ms` | Installing matching helpers and remote syq commands |

The measurements overlap, so don't add them up: copying can start while
planning continues, for example. Filesystem copies report all six fields, with
zero for work that wasn't needed or took under a millisecond. S3 copies report
`transfer_ms` once file work starts. Other copies and removal report
`total_ms` and omit the rest.

Copy totals count transferred, unchanged, and excluded files, created
directories, symlinks and specials, and transferred and unchanged bytes;
pruning runs add `deletions_planned`, `deletions_completed`, and
`deletions_blocked`. `bytes_transferred` counts the file data syq copied.
`bytes_unchanged` counts data the destination already had: the whole size of
each unchanged file, plus the parts of transferred files syq reused, such as
matching blocks or a partial file from an interrupted copy. So
`bytes_unchanged` can be nonzero while `files_unchanged` is zero.

With `--in-place=update`, `replaced_not_in_place` counts the existing files syq
replaced instead of updating them in place, by reason: `not_regular`,
`other_names`, `untrusted_filesystem`, `owner`, `privileges`,
`wider_permissions` and `not_writable`, each present only when nonzero (see
[In-place writes](reference.md#in-place-writes)). In a dry run these counts are
estimates.

A fatal failure reports what finished before it stopped. Dry-run totals
describe planned work, not committed changes. `files_excluded` counts
ignore-rule skips; an ignored directory counts once, without its contents.

Through a restricted receiver, the totals of what changed come from
the receiver, and `errors` counts the error records in the stream.

Removal terminals have `mode: "rm"` and totals for selectors, resolved and
missing selectors, planned, removed, already-absent, and failed entries. A live
removal leaves `entries_planned` zero. A dry run leaves `entries_removed` and
`entries_already_absent` zero, but failed inspections can increase
`entries_failed`.

## Compatibility

Within a schema version, required fields keep their types and meanings;
existing types, actions, dispositions, statuses, classes, and reasons are not
renamed or reused. New record types and optional fields may be added. Human
messages may change at any time.

## Connection status

`syq persist status --json` reports the persistence setting, scope, and
endpoints without starting connections. Each endpoint has a state (`starting`,
`connecting`, `ready`, `reconnecting`, `failed`, or `inactive`), whether SSH is
connected, and its receiving state and errors. With receiving enabled, `ready`
means the endpoint's allowed receiving profiles are online, even if SSH must
reconnect.

For a connection opened by an `--rsh` ssh command, `ssh_options` lists that
command's options, with relative paths made absolute, and
`ssh_options_directory` the directory where an option's local command ran; its
`receiving_enabled` is `null`. If receiving preferences
can't be read, every `receiving_enabled` is `null` and `receiving_error` says
why.

`receiving_build` names the syq build an endpoint's receiving service runs.
While it switches to a newer installed syq, `receiving_switch` has `to` (the
new build), `phase` (`waiting` until nothing is in progress, `switching`,
`login` until a syq command run in a terminal tries again, or `failed`), and
`error`.
`provider` reports the same `build` and `switch` for the local SSH
authorization provider when it runs another build or switches.

`authorized_ssh` lists approved account connections, each with `authorizer`,
`requested` (the original selection), `endpoint` (the resolved account and
address), `control`, `connected`, and `closing` (it takes no new sessions and
ends once those running end, as after a switch to a new version); the two
endpoint objects have `user`, `host`, and `port`. When a receiving machine
approved the connection, `authorizer` is that machine's name as a string; for
an SSH authorization provider, it is an object whose `ssh` field holds the
provider endpoint.
`authorized_ssh_errors` lists account records that couldn't be read; the command
then exits nonzero after printing the valid entries.

`persist receive status --json` reports the receiving settings:

| Field | Meaning |
|---|---|
| `profiles` | Every profile's `cwd`, `cwd_explicit`, `root`, `auto_approve_root` (null when every download asks), and `servers` (the endpoints set with `--connection`; empty means all) |
| `settings` | The first selected profile's settings |
| `connections` | The profiles allowed on each endpoint, and its service's build (`identity`), what keeps it from switching (`busy`: `requests` in progress, `pending` approvals, and `accounts`, the open account connections the switch waits for; `accounts_in_use` of those have a session running, and the rest can't tell and count until they close), the syq path it follows (`started_from`), and any `switch` to a new build |
| `provider` | The local SSH authorization service, or null when it isn't running; its `profiles` contain `settings`, `sessions`, and `pending` requests, and `decision_error` reports a failed local approval |

`syq persist receive pending --json` prints the requests waiting for approval,
from receiving connections and the local SSH provider. Each has `id`, `from`,
`expires_at` (Unix seconds), `notification`, and, when present, `command`: the
requesting syq command, one displayed argument per element. The other fields
depend on the request:

| `kind` | Request | Fields |
| --- | --- | --- |
| Absent | Copy to this machine or an approved destination | `destination`, `permission`, `max_bytes`, `max_entries`, `max_delete`, `preserve_permissions`, optional `warnings` |
| `command` | Command on this machine | `argv`, `cwd`, `permission` |
| `ssh` | SSH account access through a receiving connection | `destination`, `permission`, `reusable`, optional `account` |
| `provider_ssh` | SSH account access through an ordinary SSH provider login | `destination`, `permission`, `provider_account` |
| `source` | Read selected source paths for a copy | `source`, `scopes`, `permission`, `max_bytes`, `max_entries` |
| `send` | Send files from this machine to the requesting server | `paths`, `permission`, `max_bytes`, `max_entries` |
| `storage` | Storage access | `description` |

`destination`, `paths` and `scopes` are display text, as the prompt shows them:
each path is quoted, and a destination is the place the copy writes, such as
`/data` for another server's `~//data`.

`warnings` lists what a copy lets the server do beyond copying plain files, as
display text that completes "The server …", for example
`can delete up to 3 files or folders anywhere in the destination`. It is absent
or empty when there is nothing to warn about.

`account` contains `profile`, `source`, and `destination`. Each account
identity has an `endpoint`, trusted SHA256 fingerprints in `host_keys`, and an
optional `trusted_host` lookup name. `provider_account` instead contains
`profile`, `provider`, and `destination`; its provider identity has `user` and
`receiver_identity`, the fingerprint of the provider's receiving identity, not
an SSH host key or a verified requesting machine.

The `command`, `argv`, and `cwd` strings are escaped for display; don't run
them as shell input. `ssh` and `provider_ssh` requests grant
[full account access](security.md#ssh-account-access), whatever `command`
shows. Don't treat an unknown kind as a copy request.

## Remembered account permissions

`syq persist receive permissions list --json` prints an array of objects with
`id` and `permission`; pass the ID to `persist receive permissions remove`.
Both take `--pscope PATH` to select the authorizing domain.

Permissions approved through receiving contain `profile`, `source`, and
`destination`, and those for an SSH authorization provider contain `profile`,
`provider`, and `destination`, with identities as in
[Connection status](#connection-status). There is no `kind` field; tell them
apart by `source` or `provider`. Removing a remembered
permission doesn't close a connection that already authenticated. See
[account permissions](persistence-reference.md#account-permissions).

## Retry failed mapping entries

To retry the failed entries of a mapping copy, turn their records into a new
manifest, keeping `src`, `dst`, `kind`, and any `expected_hash` and `metadata`.
Do this only after a terminal `success` or `partial`; otherwise some entries may
have no record, so rerun the original copy.

```bash
set -o pipefail
syq cp --mapping big.ndjson -C src --to nas --into /data --results r.ndjson
jq -cs 'if any(.[]; .schema != "syq.automation" or .schema_version != 4)
        then "unsupported results schema for pathname retry" | halt_error
        elif (.[-1].type? // "") != "result"
        then "incomplete results stream (no terminal record)" | halt_error
        elif (.[-1].status != "success" and .[-1].status != "partial")
        then "run stopped early (status \(.[-1].status)); rerun it instead of retrying" | halt_error
        else .[] | select(.type == "operation_result"
                          and .disposition == "failed"
                          and .retryable != "no")
             | {src, dst, kind}
               + (if has("expected_hash") then {expected_hash} else {} end)
               + (if has("metadata") then {metadata} else {} end)
        end' r.ndjson \
  | syq cp --mapping - -C src --to nas --into /data
```

The filter skips non-retryable entries; fix the underlying errors before
retrying. Records from a restricted receiver carry no source paths, so
retry the original mapping instead.
