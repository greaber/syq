<a id="python-native-api"></a>

<a id="positioning"></a>

<a id="scope"></a>

<a id="product-readiness"></a>

# API reference

Module functions `syq.cp`, `syq.rm`, and `syq.map` use a default `Client`.
`AsyncClient` has the same arguments and result types; await its operations
except `map`, which returns an async context manager.

<a id="synchrony-asyncio-and-resource-ownership"></a>

## Client and executable selection

`Client(*, executable=None, cache_dir=None, process_cwd=None, env=None, timeout=None)`
and `AsyncClient(...)` accept:

| Argument | Meaning |
|---|---|
| `executable` | Custom executable path, or name to find on `PATH`; default: managed syq |
| `cache_dir` | Managed executable cache root |
| `process_cwd` | Local subprocess working directory; default: inherit |
| `env` | Subprocess environment mapping; default: inherit |
| `timeout` | Operation timeout in seconds; default: no limit |

`client.version()` returns the executable version as text.
`syq.version(executable=None)` does the same without a client.
`syq.managed_executable(cache_dir=None)` returns the verified executable path,
downloading it if needed. See [Compatibility](https://greaber.github.io/syq/python-reference.html#compatibility) for version selection and caching.

<a id="the-native-vocabulary-is-the-python-vocabulary"></a>

## Arguments and validation

Options use CLI names with hyphens replaced by underscores. Python keywords
get a trailing underscore: `from_`, `as_`. Paths accept `str`, `bytes`, or
`os.PathLike`; selector keywords accept one path or an iterable of paths.
Use `src=["a", "b"]` for CLI `--srcs a b`, and likewise `src_file` and `src_dir`.

| Shared by `cp`, `rm`, and `map` | Meaning |
|---|---|
| `*sources`, `src` | Select named objects |
| `srcs_in` | Select a directory's contents |
| `src_file`, `src_dir` | Require non-directory objects or directories |
| `cwd` | Source resolution base; may be remote for `cp` and `rm` |
| `root` | Confine source resolution beneath this directory; requires relative selectors; conflicts with `cwd` |
| `follow`, `follow_src` | Follow source symlinks; `follow` also enables destination following for `cp` |
| `timeout` | Omitted: use client default; `None`: no timeout; number: timeout in seconds |

Boolean flags default to `False`; other optional arguments default to `None`,
except `check=True` and `timeout`, whose omitted value inherits the client default.
Invalid argument combinations raise `SyqInvocationError`;
filesystem and remote checks happen in syq.

<a id="a-normal-copy"></a>

<a id="copy-and-prune"></a>

<a id="dry-runs"></a>

## cp

`cp(*sources, **options)` → [CpResult](https://greaber.github.io/syq/python-reference.html#cpresult) copies files. Choose one placement option.
In addition to the shared arguments above, it accepts:

| Options | Values / purpose |
|---|---|
| `from_`, `to` | SSH endpoint strings; omitted endpoints are local |
| `into`, `into_new`, `into_existing` | Destination directory paths |
| `as_`, `as_new`, `as_existing` | Exact destination paths |
| `mapping` | `Mapping`, `MapStream`, manifest path, or iterable of `MappingEntry`; replaces selectors; conflicts with `as_*` and `prune`. Async clients also accept `AsyncMapping` and async iterables |
| `follow_dst` | Boolean: follow destination symlinks |
| `prune`, `dry_run`, `hash`, `verify_only` | Boolean: mirror, preview, compare content, or verify without copying |
| `ignore_existing`, `existing`, `update` | Boolean: skip existing, require existing, or skip newer destination files |
| `ignore` | Pattern string, `IgnoreFrom(path)`, or ordered iterable of either |
| `ignore_from` | Rule file path or iterable of paths; applied after `ignore` |
| `preserve` | Preservation string or iterable of strings |
| `inplace`, `no_compress` | Boolean: update destination files in place or disable compression |
| `bwlimit`, `min_size`, `max_size` | Native rate/size strings or integers |
| `max_delete` | Nonnegative integer deletion limit; requires `prune=True` |
| `connections` | Positive integer connection count |
| `auth_from`, `via` | Credential source string; aliases, so use only one |
| `coordinate_at`, `rsh`, `peer_auth` | Coordinator, SSH command, and peer authentication strings |
| `pscope`, `syq_path` | SSH persistence scope path and remote executable path |
| `no_bootstrap`, `tcp_plain`, `no_tcp` | Boolean remote/transport controls |
| `tcp_ports`, `tcp_congestion` | Port range and congestion-control strings |
| `receiver_max_entries`, `receiver_max_bytes` | Receiver ceilings: integer entries, native size string or integer bytes |
| `receiver_receipt` | `"sizes"` or `"digests"` |
| `on_event`, `results`, `check` | See events and failures below |

Option behavior is covered in [Copy files](https://greaber.github.io/syq/reference.html)
and [Remote copy details](https://greaber.github.io/syq/remote-reference.html).
Typed remote-to-remote copies require an enrolled receiver or
`coordinate_at="local"`. With `dry_run=True` or `verify_only=True`, they require
`coordinate_at="local"`. Use `run` for detached commands and human output options.

`IgnoreFrom(path)` is a frozen dataclass holding a rule-file path (`str`,
`bytes`, or `os.PathLike`). To interleave rule files and inline patterns:
`ignore=[syq.IgnoreFrom("rules"), "!keep.tmp"]`. The last matching rule wins.

<a id="removal"></a>

## rm

`rm(*sources, **options)` → [RmResult](https://greaber.github.io/syq/python-reference.html#rmresult) removes selected entries. Besides the shared
arguments, it accepts `from_`, `dry_run`, `connections`, `syq_path`,
`no_bootstrap`, `pscope`, `on_event`, `results`, and `check` with the types above.
It supports local and ordinary SSH endpoints. Command-restricted receivers
reject removal. See [Remove files](https://greaber.github.io/syq/remove.html).

<a id="complete-input-guarantee"></a>

<a id="mapping-transformation-and-copy"></a>

## map

`map(*sources, **options) → MapStream` lists local mapping entries without
copying. Besides the shared arguments, it accepts `as_` to rename a selected
object. `srcs_in` must be the sole selector when used.

`MapStream` is a `Mapping` and an iterable context manager; use `with`.
`AsyncMapStream` is an `AsyncMapping` and an async context manager; use
`async with`. Streams must be consumed inside their context and cannot be reused
after completion or closure. Async streams capture the producer directory,
environment, and timeout when created, even though execution starts later.

### Mapping and AsyncMapping

A mapping combines entries with their local source context. Pass it directly
to `cp(mapping=...)`, even on a client with a different `process_cwd`.

`Mapping(entries, *, cwd=None, root=None, follow_src=False)` accepts an iterable
of `MappingEntry`. `AsyncMapping(...)` accepts an async iterable. If both `cwd`
and `root` are omitted, the source base is the current directory at construction.
Otherwise exactly one may be supplied. Relative `cwd` and `root` paths resolve
against the Python process directory at construction, not a client's
`process_cwd`. `root` confines source resolution.

| Member | Type | Meaning |
|---|---|---|
| `cwd` | `pathlib.Path` | Absolute source-base spelling, preserving symlinks and `..` |
| `root` | `pathlib.Path` or `None` | Confinement base, when created with `root` |
| `follow_src` | `bool` | Whether the copy should follow source symlinks |
| `transform(function)` | `Mapping` or `AsyncMapping` | Lazy transformation that keeps the source context |

The context properties are read-only. A transform receives each `MappingEntry`
and returns a replacement entry, or `None` to omit it. Transformations can be
chained. Async transforms also accept awaitable callbacks and await them in
entry order. Neither form caches entries; reuse depends on the supplied iterable.

A context-carrying mapping rejects `from_`, `cwd`, and `root` overrides on `cp`.
It automatically enables the source-following policy used by `map`; enabling
`follow` or `follow_src` on the copy is also permitted. The destination options
remain independent. `map(root=..., srcs_in=...)` carries the selected directory
as the consuming copy's root. The copy resolves that root again; it does not
inherit an open directory handle or a snapshot of the source tree.

### MappingEntry

Frozen dataclass describing one source-to-destination mapping. Pass an iterable
of these to `cp(mapping=...)`; use `dataclasses.replace` to change an entry.

| Attribute | Type | Meaning |
|---|---|---|
| `src` | `RelativePath` | Path relative to the copy's source base |
| `dst` | `RelativePath` | Path relative to the destination container |
| `kind` | `EntryKind` or `None` | Object kind, when known; default `None` |
| `size` | `int` or `None` | Informational size in bytes; default `None` |
| `mtime` | `int` or `None` | Informational modification time in Unix seconds; default `None` |

`MappingEntry(src, dst, kind=None, size=None, mtime=None)` also accepts text or
byte paths for `src` and `dst` and converts them to `RelativePath`. `size` and
`mtime` do not impose preconditions on the copy.

### RelativePath and PathValue

`RelativePath(value)` accepts text, bytes, or `os.PathLike`. It rejects empty
paths, absolute paths, NUL bytes, and empty, `.` or `..` components. Join paths
with `/`, for example `syq.RelativePath("archive") / entry.dst`.

`PathValue(raw: bytes)` holds a path received in an event, which may be absolute.
Both types are immutable and provide:

| Member | Type | Meaning |
|---|---|---|
| `raw` | `bytes` | Original filename bytes; also returned by `bytes(path)` |
| `text` | `str` | UTF-8 decoding; raises `UnicodeDecodeError` for invalid UTF-8 |
| `str(path)` | `str` | Filesystem decoding with `os.fsdecode` |
| `PathValue.display` | `str` | Same as `str(path)` |

`RelativePath` also implements `os.PathLike`, returning bytes.

Normal end of stream iteration checks the mapping process status. Leaving its
context early stops the process. An exhausted or closed stream cannot be copied
as an empty mapping.

For `cp(mapping=iterable)`, the entire iterable is saved to a temporary manifest
before copying starts. An iteration, transformation, or serialization failure
starts no copy. Plain iterables and manifest paths have no source context; pass
`cwd`, `root`, or `from_` explicitly as needed. See
[mapping rules](https://greaber.github.io/syq/mappings.html).

<a id="retry-data-not-automatic-retry-policy"></a>

## Events and terminal results

`cp` and `rm` return frozen dataclasses after validating the complete results
stream and process exit status. A truncated stream raises even if the process
exits successfully. Dry runs return the same types, with planned totals.

### CpResult

Returned by `cp()`, or available as `SyqOperationError.result` after an
unsuccessful copy. Read attributes directly, for example
`result.files_transferred`. It includes the common result fields below plus:

| Attribute | Type | Meaning |
|---|---|---|
| `files_transferred` | `int` | Regular files transferred |
| `files_unchanged` | `int` | Regular files skipped as unchanged |
| `files_excluded` | `int` | Files excluded from copying |
| `directories_created` | `int` | Directories created |
| `symlinks_created` | `int` | Symbolic links created |
| `specials_created` | `int` | Special filesystem objects created |
| `bytes_transferred` | `int` | File-content bytes transferred, not compressed network traffic |
| `bytes_unchanged` | `int` | Bytes in unchanged files |
| `deletions_planned` | `int` or `None` | Entries selected for pruning |
| `deletions_completed` | `int` or `None` | Entries pruned |
| `deletions_blocked` | `int` or `None` | Pruning deletions blocked by a safety limit |
| `receipt` | `ReceiptSummary` or `None` | Verified receiver receipt details; `None` for ordinary copies |

With `dry_run=True`, mutation totals describe planned changes. With
`verify_only=True`, matching files count as unchanged; transfer and creation
totals are zero. A failed call reports work completed before it stopped.

Ordinary copies have all three deletion fields only with `prune=True`;
otherwise they are `None`. Receiver-attested results have only
`deletions_completed`, and their unchanged/excluded totals are always zero
because the receiver cannot observe source-side skips. `receipt` is
`None` for ordinary copies.

### RmResult

Returned by `rm()`, or available as `SyqOperationError.result` after an
unsuccessful removal. It includes the common result fields below plus:

| Attribute | Type | Meaning |
|---|---|---|
| `selectors_total` | `int` | Explicit source selectors supplied |
| `selectors_resolved` | `int` | Selectors that resolved to an object |
| `selectors_missing` | `int` | Selectors already missing; this is not an error |
| `entries_planned` | `int` | Entries a dry run would remove; zero in live runs |
| `entries_removed` | `int` | Entries removed; zero in dry runs |
| `entries_already_absent` | `int` | Entries gone by removal time; zero in dry runs |
| `entries_failed` | `int` | Removal or inspection failures, including during dry runs |
| `mode` | `str` | Always `"rm"` |

Selectors identify requests; entries count individual filesystem objects. One
directory selector can account for many entries. Duplicate and overlapping
selectors have separate indexes.

### Common result fields

Both `CpResult` and `RmResult` include:

| Attribute | Type | Meaning |
|---|---|---|
| `status` | `OperationStatus` | Outcome from the table below |
| `exit_code` | `int` | syq process exit code |
| `dry_run` | `bool` | Whether this was a preview |
| `errors` | `int` | Counted errors |
| `elapsed_ms` | `int` | Run duration in milliseconds |
| `protocol` | `ProtocolMetadata` | Automation envelope; also present on every event |

### ProtocolMetadata

Frozen dataclass accessed through `result.protocol` or `event.protocol`.
The SDK checks these fields; applications normally only need them when recording
or diagnosing a stream.

| Attribute | Type | Meaning |
|---|---|---|
| `schema` | `str` | `"syq.automation"` |
| `schema_version` | `int` | `1` |
| `seq` | `int` | Record sequence number, starting at zero |
| `type` | `str` | Wire record type; `"result"` for terminal totals |

### ReceiptSummary

Frozen dataclass accessed through `CpResult.receipt` for receiver-attested copies.

| Attribute | Type | Meaning |
|---|---|---|
| `status` | `ReceiptStatus` | Receiver receipt outcome |
| `operations` | `int` | Attested operation record count |
| `final_states` | `int` | Attested final-state record count |
| `records` | `int` | Total receipt record count |
| `provenance` | `str` | `"receiver_attested"` |

### OperationStatus

String enum: compare with `syq.OperationStatus.SUCCESS`, or use `.value` for
`"success"`.

| Member | Value | Exit code | Meaning |
|---|---|---|---|
| `SUCCESS` | `"success"` | `0` | Requested operation succeeded |
| `PARTIAL` | `"partial"` | `23` | Per-entry failures; independent work finished |
| `REFUSED` | `"refused"` | `25` | A safety cap refused deletions; copy only |
| `ABORTED` | `"aborted"` | `1` | Operation aborted; copy only |
| `FAILED` | `"failed"` | `1` | Fatal failure |

### Event callbacks

`on_event(event)` receives an `AutomationEvent` in stream order. Events are not
stored in the result. `AsyncClient` accepts synchronous or awaitable callbacks;
awaitable callbacks count toward the timeout.

`AutomationEvent` is the union of the event classes below and `CpResult` and
`RmResult`. Each event is a frozen dataclass. Its fields are listed below;
all events also carry `protocol: ProtocolMetadata`, just like results.
`event.protocol.type` identifies the wire record type. Optional fields use `None` when unavailable.

See [Automation results](https://greaber.github.io/syq/automation.html) for stream
semantics. Python exposes `class` as `class_` and paths as `PathValue`.

`results=` accepts a binary file-like object with `write(bytes)` returning a
positive byte count for nonempty writes, and optional `flush()`. The client
copies validated NDJSON records, flushes after completion, and leaves it open.
It withholds the terminal record if stream validation, process completion, or
a callback fails. Sink failures raise and abort the operation.

`OperationResult.is_retryable` identifies retryable failures; `retry_entry()`
returns a `MappingEntry` when a complete mapping identity is available, otherwise
`None`. Only use collected entries after the call returns a validated `success`
or `partial` result. A terminal callback alone does not establish completion.
The client does not retry automatically.


## Event types

### RunEvent

Invocation details. `started_at` is Unix seconds; `mode` is `"cp"` or `"rm"`.
`prune` and `mapping` are `None` for removal; `verify_only` defaults to `False`.

`protocol.type = "run"`. Fields in addition to the common envelope:

```python
run_id: str
started_at: int
syq_version: str
mode: str
prune: bool | None
mapping: bool | None
dry_run: bool
endpoints: tuple[Endpoint, ...]
verify_only: bool
```

### ProgressEvent

Sampled progress for displays; use the terminal result for final totals.
Byte fields measure file content (comparison work with `verify_only=True`),
`scanned` counts scanned entries, and `elapsed_ms` is milliseconds.

`protocol.type = "progress"`. Fields in addition to the common envelope:

```python
bytes_done: int
bytes_total: int
bytes_unchanged: int
files_done: int
files_total: int
files_unchanged: int
files_excluded: int
scanned: int
scan_done: bool
elapsed_ms: int
```

### TraceEvent

One planned copy change. `dst` is relative to the destination container;
`src` is the mapping source when available. `bytes` is the planned file size,
and `reason` describes why the change is needed.

`protocol.type = "trace"`. Fields in addition to the common envelope:

```python
action: OperationAction
dst: PathValue
src: PathValue | None
kind: EntryKind
bytes: int | None
reason: TraceReason
```

### OperationResult

One copy outcome. `dst` is destination-relative, or relative to the signed
destination `scope` for a receiver receipt. `src` is present for mapping entries
when available. `bytes` and `attempts` give transfer information. Error details
are present when known; `message` is display text. `provenance`, `scope`, and
`code` apply to receiver-attested outcomes.

`protocol.type = "operation_result"`. Fields in addition to the common envelope:

```python
action: OperationAction
dst: PathValue
src: PathValue | None
kind: EntryKind | None
disposition: Disposition
bytes: int | None
attempts: int | None
retryable: Retryability | None
class_: ErrorClass | None
os_kind: OsKind | None
message: str | None
provenance: str | None
scope: int | None
code: ReceiptCode | None
```

### SelectionResult

One removal selector, indexed from zero. `path` is the original selector;
`status` says whether it resolved. `kind` is `None` for a missing selector.

`protocol.type = "selection_result"`. Fields in addition to the common envelope:

```python
selector: int
path: PathValue
status: SelectionStatus
kind: EntryKind | None
```

### RemovalTrace

One entry a preview would remove. `selector` identifies its source selector;
`path` identifies the entry. `disposition` is always `WOULD_REMOVE`.

`protocol.type = "removal_trace"`. Fields in addition to the common envelope:

```python
selector: int
path: PathValue
kind: EntryKind
disposition: RemovalDisposition
```

### RemovalResult

One removal outcome or preview inspection failure. `selector` identifies its
source selector; `path` identifies the entry. `attempts` counts attempts;
`retryable`, `class_`, `os_kind`, and `message` describe failures when available.

`protocol.type = "removal_result"`. Fields in addition to the common envelope:

```python
selector: int
path: PathValue
kind: EntryKind | None
disposition: RemovalDisposition
attempts: int
retryable: Retryability | None
class_: ErrorClass | None
os_kind: OsKind | None
message: str | None
```

### ErrorEvent

One counted error. `message` is display text; `class_` and `os_kind` classify
it when known. Receiver errors can also carry `provenance` and `code`.

`protocol.type = "error"`. Fields in addition to the common envelope:

```python
message: str
class_: ErrorClass | None
os_kind: OsKind | None
provenance: str | None
code: ReceiptCode | None
```

### FinalStateEvent

Receiver-attested destination state. `dst` is relative to the signed `scope`.
`provenance` is `"receiver_attested"`. Present objects have `kind` and byte
`size`; `metadata`, `digest`, and `symlink_target` are present where available.
`observation_error` describes a partial observation. Absent objects have no
object details; failed observations have `code` and optional `message`.

`protocol.type = "final_state"`. Fields in addition to the common envelope:

```python
provenance: str
scope: int
dst: PathValue
state: FinalObjectState
kind: FinalObjectKind | None
size: int | None
metadata: ObjectMetadata | None
digest: AttestedDigest | None
symlink_target: PathValue | None
observation_error: str | None
code: ReceiptCode | None
message: str | None
```

### Endpoint, ObjectMetadata, and AttestedDigest

Nested frozen dataclasses used by events:

| Type | Fields | Meaning |
|---|---|---|
| `Endpoint` | `role: EndpointRole`, `kind: EndpointKind`, `host: str \| None`, `user: str \| None` | Source/destination and local/SSH identity; host and user are optional |
| `ObjectMetadata` | `mode: int`, `uid: int`, `gid: int`, `mtime: int`, `mtime_nsec: int`, `rdev: int` | Unix mode, owner/group IDs, modification time (seconds plus nanoseconds), and device ID |
| `AttestedDigest` | `algorithm: str`, `value: str` | `"blake3"` and its 64 lowercase hexadecimal digest characters |

## Enums

All enums are string enums exported by `syq`. Members use uppercase names;
values use lowercase, for example `EntryKind.FILE.value == "file"`.
`OperationStatus` is defined with the result types above.

| Type | Members |
|---|---|
| `EntryKind` | `FILE`, `DIR`, `SYMLINK`, `SPECIAL` |
| `EndpointKind` | `LOCAL`, `SSH` |
| `EndpointRole` | `SOURCE`, `DESTINATION` |
| `OperationAction` | `TRANSFER_FILE`, `CREATE_DIRECTORY`, `CREATE_SYMLINK`, `CREATE_SPECIAL`, `DELETE`, `SET_METADATA`, `OBSERVE_HASH` |
| `Disposition` | `SUCCEEDED`, `FAILED`, `BLOCKED`, `INCOMPLETE`, `OBSERVED` |
| `ReceiptCode` | `NONE`, `EXECUTION_FAILED`, `AUTHORIZATION_REFUSED`, `FILE_LIFECYCLE_INCOMPLETE`, `OBSERVATION_FAILED` |
| `FinalObjectState` | `PRESENT`, `ABSENT`, `OBSERVATION_FAILED` |
| `FinalObjectKind` | `DIR`, `FILE`, `SYMLINK`, `FIFO`, `SOCKET`, `CHARACTER_DEVICE`, `BLOCK_DEVICE`, `OTHER` |
| `ReceiptStatus` | `CLEAN`, `FAILED`, `INCOMPLETE` |
| `Retryability` | `YES`, `NO`, `UNKNOWN` |
| `ErrorClass` | `IO`, `TRANSPORT`, `CONFLICT`, `INTEGRITY`, `SAFETY_LIMIT`, `USAGE`, `INTERNAL` |
| `OsKind` | `NOT_FOUND`, `PERMISSION_DENIED`, `ALREADY_EXISTS`, `INVALID_INPUT`, `NO_SPACE`, `QUOTA_EXCEEDED`, `READ_ONLY`, `OTHER` |
| `TraceReason` | `DESTINATION_MISSING`, `TYPE_DIFFERS`, `CONTENT_DIFFERS`, `METADATA_DIFFERS`, `DESTINATION_ONLY` |
| `SelectionStatus` | `RESOLVED`, `MISSING` |
| `RemovalDisposition` | `WOULD_REMOVE`, `REMOVED`, `ALREADY_ABSENT`, `FAILED` |

`ReceiptStatus.CLEAN` means a clean receipt, `FAILED` reports receiver failures,
and `INCOMPLETE` reports an incomplete lifecycle. `Retryability.YES`, `NO`, and
`UNKNOWN` state whether a failed entry can be retried.

## Failure model

`SyqError` is the base class for every SDK-defined exception below. Specific
subclasses retain their details so callers can distinguish an unsuccessful
operation from a broken results stream.

| Exception | Meaning / useful attributes |
|---|---|
| `SyqInstallError` | Managed executable installation or verification failed |
| `SyqInvocationError` | Invalid Python arguments |
| `SyqOperationError` | Typed operation was unsuccessful; `.result` and `.stderr` (last 8 KiB) |
| `SyqProtocolError` | Invalid, unsupported, inconsistent, or incomplete results; `.returncode`, `.stderr` |
| `SyqProcessError` | Raw `run` exited nonzero; `.result` contains complete output |
| `SyqOutputError` | A helper such as `version()` received unexpected output |

For `cp` and `rm`, `check=False` returns unsuccessful typed results; for `run`,
it returns nonzero process results. It does not suppress other errors.
Spawn failures, timeouts, and ordinary Python type/value errors use standard
Python exceptions. Exceptions from application callbacks or mapping iterators
are re-raised unchanged. Async cancellation remains `asyncio.CancelledError`.
These exceptions are not wrapped in `SyqError`.

Timeout, cancellation, early mapping exit, and streaming failures terminate and
reap the local process group, including SSH children. Filesystem changes already
completed are not rolled back.

<a id="deliberate-exclusions"></a>

<a id="raw-execution"></a>

## run

`client.run(args, *, check=True, cwd=None, env=None, timeout=CLIENT_DEFAULT, input=None)`
returns [Result](https://greaber.github.io/syq/python-reference.html#result). `input` accepts bytes. `args` is a sequence of arguments
after the executable name, passed without a shell.

Here, `cwd` is the local subprocess directory. `cwd` and `env` use client
defaults when omitted or `None`. `timeout` uses the client default only when
omitted; explicit `None` disables it. Module-level `syq.run` takes the same
arguments plus `executable=None` and defaults to no timeout.

Wrappers can forward `syq.CLIENT_DEFAULT` to preserve client inheritance.
`syq.Timeout` is the type alias for a number, `None`, or that sentinel:

```python
def copy_data(client: syq.Client, *, timeout: syq.Timeout = syq.CLIENT_DEFAULT):
    return client.cp("data", into="backup", timeout=timeout)
```

`CLIENT_DEFAULT` applies to client methods (including module-level `cp`, `rm`,
and `map`); client constructors and module-level `run` have no client default
to inherit.

Timeouts cover subprocess execution. Managed installation and mapping-input
materialization happen before the copy process starts and are not covered by
its timeout. Async cancellation still stops mapping-input preparation.

`syq exec` is also available through `run`; its command output and exit status
are a process result:

```python
result = syq.run(
    ["exec", "--on", "@mac", "--cwd", "work/project", "--", "cargo", "test"],
    executable="/path/to/syq",
)
```

For `exec`, pass `--cwd` in the argument list to select the receiving working
directory. The SDK's `cwd=` parameter selects the local working directory of
the requesting syq process.

### Result

Frozen dataclass returned by `run()` and held in `SyqProcessError.result`:

| Attribute | Type | Meaning |
|---|---|---|
| `argv` | `tuple[str \| bytes, ...]` | Executed argument list, including the executable |
| `returncode` | `int` | Process exit status |
| `stdout` | `bytes` | Complete captured standard output |
| `stderr` | `bytes` | Complete captured standard error |

<a id="compatibility-and-versioning"></a>
<a id="syq-language-sdks"></a>

## Compatibility

Python 3.10+ on Linux and macOS; no runtime Python dependencies. Each Python
package uses the matching syq release. `syq.__version__` and
`syq.PINNED_SYQ_VERSION` report those versions. Pin the package in your dependency
file to keep the pairing.

### Managed executable

The default client downloads the matching executable on first use and verifies
it against the package's embedded release manifest. It checks the cached binary
before every use and replaces missing or corrupt entries. It does not search
`PATH`.

The default cache is `$XDG_CACHE_HOME/syq/sdk/python/v<version>/` when
`XDG_CACHE_HOME` is absolute, or `~/.cache/syq/sdk/python/v<version>/` otherwise.
Use `Client(cache_dir=...)` to change the cache root, or
`syq.managed_executable()` to download ahead of time and get the path.

### Custom executable

`Client(executable="/opt/bin/syq")` uses that binary;
`Client(executable="syq")` searches `PATH`. Overrides bypass managed download
and verification, so you are responsible for compatibility and origin. Typed
calls still validate automation output. A failed executable selection does not
fall back to another binary.
