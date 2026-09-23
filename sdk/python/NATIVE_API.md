<!-- ANCHOR: operations-title -->
<a id="python-native-api"></a>

<a id="positioning"></a>

<a id="scope"></a>

<a id="product-readiness"></a>

<!-- ANCHOR_END: operations-title -->

# API reference

<!-- ANCHOR: operations -->

Module functions `syq.cp`, `syq.rm`, `syq.map`, `syq.open_reader`, and
`syq.open_writer` use a default `Client`.
`AsyncClient` has the same arguments and result types; await its operations
except `map`, `open_reader`, and `open_writer`, which return async context managers.

<a id="synchrony-asyncio-and-resource-ownership"></a>

For generated data and entry transformations, see
[Streams and mappings](https://greaber.github.io/syq/python-streams.html).
For returned objects, callbacks, and errors, see
[Results and events](https://greaber.github.io/syq/python-results.html).

## Client and executable selection

`Client(*, executable=None, cache_dir=None, process_cwd=None, env=None, timeout=None)`
and `AsyncClient(...)` accept:

| Argument | Meaning |
|---|---|
| `executable` | Custom executable path, or name to find on `PATH`; default: bundled syq |
| `cache_dir` | Opt into a separately downloaded executable at this cache root |
| `process_cwd` | Local subprocess working directory; default: inherit |
| `env` | Subprocess environment mapping; default: inherit |
| `timeout` | Operation timeout in seconds; default: no limit |

`client.version()` returns the executable version as text.
`syq.version(executable=None)` does the same without a client.
`syq.managed_executable(cache_dir=None)` returns the verified executable path,
downloading it if needed. See [Compatibility](https://greaber.github.io/syq/python-operations.html#compatibility) for version selection and caching.

<a id="the-native-vocabulary-is-the-python-vocabulary"></a>

## Arguments and validation

Options use CLI names with hyphens replaced by underscores. Python keywords
get a trailing underscore: `from_`, `as_`. Paths accept `str`, `bytes`, or
`os.PathLike`; selector keywords accept one path or an iterable of paths.
Use `src=["a", "b"]` for CLI `--srcs a b`, and likewise `src_non_dir` and `src_dir`.

| Shared by `cp`, `rm`, and `map` | Meaning |
|---|---|
| `*sources`, `src` | Select named objects |
| `srcs_in` | Select a directory's contents |
| `src_non_dir`, `src_dir` | Require non-directory objects or directories |
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

`cp(*sources, **options)` → [CpResult](https://greaber.github.io/syq/python-results.html#cpresult) copies files. Choose one placement option unless every destination is a callback.
In addition to the shared arguments above, it accepts:

| Options | Values / purpose |
|---|---|
| `from_`, `to` | SSH endpoint strings or `s3://BUCKET`; omitted endpoints are local |
| `into`, `into_new`, `into_existing` | Destination directory paths |
| `as_`, `as_new`, `as_existing` | Exact destination paths |
| `mapping` | `Mapping`, `MapStream`, manifest path, or iterable of `MappingEntry`; replaces selectors; conflicts with `as_*` and `prune`. Async clients also accept `AsyncMapping` and async iterables |
| `stream_concurrency` | Maximum callback entries active at once; default `4`, range `1..256`; transport worker and request limits are shared across entries |
| `follow_dst` | Boolean: follow destination symlinks |
| `prune`, `dry_run`, `hash` | Boolean: mirror, preview, or compare content |
| `integrity_checking` | Comma-separated string, e.g. `"transfer=sha256"`; defaults to size/mtime comparison and no extra payload checks |
| `only_new` | Boolean: copy missing entries without replacing existing ones |
| `ignore` | Pattern string, `IgnoreFrom(path)`, or ordered iterable of either |
| `ignore_from` | Rule file path or iterable of paths; applied after `ignore` |
| `preserve` | Preservation string or iterable: `times`, `permissions`, `ownership`, `specials`, `hardlinks`, `acls`, `xattrs`, `atimes`, `crtimes`; see [filesystem preservation](https://greaber.github.io/syq/reference.html#preserve-metadata) for platform and route support |
| `open_noatime` | Boolean: request file reads without access-time updates; warns and continues if unavailable |
| `inplace`, `no_compress` | Boolean: update destination files in place or disable compression |
| `max_delete` | Nonnegative integer deletion limit; requires `prune=True` |
| `resource_limits` | Comma-separated ceilings that keep automatic tuning, e.g. `"bandwidth=10M,workers=4"`; a concurrency key conflicts with the same key in `performance_tuning` |
| `performance_tuning` | Comma-separated overrides, e.g. `"workers=4"` or `"s3-objects=4,s3-parts-per-object=8,s3-requests=16"`; omitted means automatic |
| `s3_endpoint`, `s3_region`, `s3_profile` | Endpoint URL, signing region, and AWS profile strings |
| `s3_header` | Iterable of `"NAME: VALUE"` strings; applied before signing every request |
| `auth_from` | Credential source string |
| `coordinate_at`, `rsh`, `peer_auth` | Coordinator, SSH command, and peer authentication strings |
| `pscope` | Existing ephemeral scope path for forward SSH connection reuse |
| `syq_path` | Remote executable path |
| `no_bootstrap`, `tcp_plain`, `no_tcp` | Boolean remote/transport controls |
| `tcp_ports`, `tcp_congestion` | Port range and congestion-control strings |
| `receiver_max_entries`, `receiver_max_bytes` | Receiver ceilings: integer entries, native size string or integer bytes |
| `receiver_receipt` | `"sizes"` or `"hashes"` |
| `on_event`, `results`, `check` | See [events and failures](https://greaber.github.io/syq/python-results.html) |

Option behavior is covered in [Copy files](https://greaber.github.io/syq/reference.html),
[Remote copy details](https://greaber.github.io/syq/remote-reference.html),
and [Object storage](https://greaber.github.io/syq/object-storage.html).

For example, `client.cp("data", to="s3://bucket", into="backup",
s3_header=["X-Tigris-Consistent: true"])` uploads local data using credentials
from the subprocess environment or AWS configuration. Copies between two S3
endpoints use server-side copying within the same service; content verification
options that require reading object bodies are rejected. SSH/S3 combinations
are not supported. S3 results use `EndpointKind.S3`.

`pscope` selects an isolated scope for reusing SSH connections. For return
copies or commands, use `syq persist connect server` and omit `pscope`. See
[persistence in scripts](https://greaber.github.io/syq/persistence-reference.html#isolated-script-scopes)
for setup and cleanup, and
[Compatibility](https://greaber.github.io/syq/python-operations.html#compatibility)
for executable selection.

Typed SSH-to-SSH copies require an enrolled receiver or
`coordinate_at="local"`. With `dry_run=True`, they require
`coordinate_at="local"`. Use `run` for detached commands and human output options.

`IgnoreFrom(path)` is a frozen dataclass holding a rule-file path (`str`,
`bytes`, or `os.PathLike`). To interleave rule files and inline patterns:
`ignore=[syq.IgnoreFrom("rules"), "!keep.tmp"]`. The last matching rule wins.
<!-- ANCHOR_END: operations -->

<!-- ANCHOR: streams -->
## Byte streams

`client.open_writer(*, as_=None, as_new=None, as_existing=None, to=None,
follow_dst=False, ...)` returns a `StreamWriter`. Choose exactly one of
`as_`, `as_new`, or `as_existing`; the latter two require the destination to
be absent or present, following `cp` placement semantics. Writers have no
source basename, so they require an exact destination path.
`client.open_reader(src, *, from_=None, cwd=None, root=None, follow_src=False, ...)`
returns a `StreamReader`. `cwd` resolves relative sources; `root` also confines
them. Choose at most one, as with `cp`. These bases belong to the source
endpoint, independently of the client's local `process_cwd`. Both accept `rsh`,
`syq_path`, `pscope`, `no_bootstrap`, `no_compress`, `no_tcp`, `tcp_plain`,
`tcp_ports`, `tcp_congestion`, `auth_from` (S3), `s3_endpoint`, `s3_region`, `s3_profile`, `s3_header`,
`performance_tuning`, `resource_limits`, `integrity_checking`, `only_new`,
`dry_run`, `stats`, `verbose`, `quiet`, `progress`, `no_progress`,
and `timeout` with the same meanings as `cp`.
See the CLI stream reference for the applicable tuning and integrity controls.
The client supplies the executable, process working directory, environment,
and default timeout. Stream calls always check transfer failures.

These methods transfer raw bytes, using the CLI's [stream semantics](https://greaber.github.io/syq/commands/cp.html#file-descriptors)
for destination permissions, metadata, and endpoint restrictions. They are
sequential, non-seekable interfaces; use one
operation at a time on each stream. No whole-object retry or restart recovery
is attempted. S3 can retry buffered multipart parts.

| Object | Operations |
|---|---|
| `StreamWriter` | `write(bytes)` writes the complete buffer and returns its length; `flush()` has no Python buffer to flush; `close()` ends payload input; `commit()` publishes and checks completion; `abort()` cancels |
| `StreamReader` | `read(size=-1)`, `readinto(buffer)`; `close()` drains remaining bytes in bounded chunks and checks completion; `abort()` cancels |

Streams use bounded transport buffers. `read()` without a size collects all
remaining bytes in Python memory and checks completion before returning.

### Writer completion

Use a `with` block to commit on successful exit or abort on an exception.
An abort before commit does not replace the destination. `close()` only ends
payload input; it does not publish the file. Successful context exit commits
even if you already called `close()`, unless you also called `abort()`.

Writers support `io.BufferedWriter` and `io.TextIOWrapper`. Close the wrapper
before committing the underlying writer so its buffered data is flushed.

Outside a context, finish with `commit()` or `abort()`; `close()` alone leaves
the transfer pending. `commit()` can follow payload closure, is repeatable
after success, and fails after an abort. Explicit commit publishes immediately,
so later application errors cannot undo it.
A timeout or connection loss during commit can leave the outcome uncertain;
the method reports failure rather than claiming rollback. Whole datasets
need their own final publication step after all object transfers succeed.

### Skips and previews

Writers normally return while destination setup continues, so opening several
writers lets their connections start concurrently. Setup errors can surface at
`write()` or `commit()`. With `only_new=True` or `dry_run=True`,
opening waits for the destination decision (also for options inherited from the
environment). Check `output.skipped` before producing data:

```python
with client.open_writer(to="server", as_="archive.tar", only_new=True) as output:
    if not output.skipped:
        produce_archive(output)
```

A skipped writer rejects `write()` and exits its context successfully without
committing anything. Skipped readers return no payload; their `skipped` property
is settled at completion. Both count the skipped object in `files_excluded`.

With `dry_run=True`, a context checks placement without transferring bytes.
Enter and exit a writer context without calling `write()`; preview writers
reject payload writes. Preview readers return no payload. The result contains
planned totals; `bytes_total_known=False` distinguishes an unknown pipe length
from an empty source. A dry run does not check an expected payload hash.

### Results and failures

After completion, `stream.result` holds a `CpResult`, including byte counts and
elapsed time. It remains `None` if no terminal result arrived, such as after
forced termination. Missing or invalid completion records raise
`SyqProtocolError` even if the process exits successfully.

A bounded reader call can yield partial data before a later transfer error.
An unbounded `read()` checks transfer completion before returning its bytes.
An exception inside either context cancels the transfer
and preserves the original exception. Writers that have not committed are
aborted during garbage collection, including after payload closure; cleanup
can block, so use explicit contexts for timely cleanup.

`timeout` covers the stream's lifetime, including blocked reads/writes. Timeout
raises `subprocess.TimeoutExpired` unless the transfer has completed successfully;
transfer failures raise `SyqProcessError`,
whose result contains the exit status and the last 8 KiB of diagnostics, without
capturing payload bytes. The stream's `stderr` property exposes those same
last 8 KiB as bytes, including on success. For example, request `stats=True`
and read `output.stderr.decode()` after the writer context exits.

### Async streams

Async streams use `async with` directly and await I/O and explicit closure:

```python
client = syq.AsyncClient()
async with client.open_writer(to="server", as_="generated.bin") as output:
    await output.write(b"generated bytes")
async with client.open_reader("generated.bin", from_="server") as source:
    while chunk := await source.read(65536):
        await consume(chunk)
```

Async streams start on context entry. Cancellation terminates the owned
transfer process and releases blocked I/O. `AsyncStreamReader` and
`AsyncStreamWriter` expose async `read`/`write`, `close`, and `abort` methods.
`AsyncStreamWriter.commit()` explicitly publishes, with the same semantics
as its synchronous counterpart; successful async context exit commits automatically.
<!-- ANCHOR_END: streams -->

<!-- ANCHOR: removal -->
<a id="removal"></a>

## rm

Positional sources and `src` refuse directories. `src_dir` removes a
tree recursively; `srcs_in` removes its contents recursively and keeps the root.

`on="server"` selects the removal endpoint. A final selected symlink is
always unlinked. Both `follow_src=True` and `follow=True` permit symlinks in
`cwd`, `root`, and selector parent directories.
Directory and contents selectors reject a final symlink even with following
enabled.

`rm(*sources, **options)` → [RmResult](https://greaber.github.io/syq/python-results.html#rmresult) removes selected entries. Besides the shared
arguments, it accepts `on`, `dry_run`, `performance_tuning`, `syq_path`,
`no_bootstrap`, `pscope`, `on_event`, `results`, and `check` with the types above.
It supports local, ordinary SSH, and S3 endpoints. Command-restricted receivers
reject removal. See [Remove files](https://greaber.github.io/syq/remove.html).

S3 removal uses `rm(..., on="s3://bucket")` with optional `s3_endpoint`,
`s3_region`, `s3_profile`, `s3_header`, and `auth_from="@NAME"`. `s3_all_versions=True` permanently
removes all selected versions and delete markers; `s3_version_id="ID"` selects
one version of one exact key. These options are mutually exclusive.
`RemovalTrace` and `RemovalResult` expose optional `s3_version_id` and
`s3_delete_marker` fields. The same arguments work with `AsyncClient.rm`.
<!-- ANCHOR_END: removal -->

<!-- ANCHOR: mappings -->
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

Normal end of stream iteration checks the mapping process status. Leaving its
context early stops the process. An exhausted or closed stream cannot be copied
as an empty mapping.

For `cp(mapping=iterable)`, the entire iterable is saved to a temporary manifest
before copying starts. An iteration, transformation, or serialization failure
starts no copy. Plain iterables and manifest paths have no source context; pass
`cwd`, `root`, or `from_` explicitly as needed. See
[mapping rules](https://greaber.github.io/syq/mappings.html).

<a id="callback-mappings"></a>

### Callback mappings

`StreamSource(produce, *, size=None)` supplies bytes to one mapping entry.
`StreamDestination(consume)` receives them. Pass either or both as the `src`
and `dst` of a `MappingEntry`; callback entries require `kind=None` or `"file"`.
These objects work with live `cp(mapping=...)` calls, not saved pathname manifests.

The complete iterable is validated before any callback or destination change.
Callbacks start lazily, with at most `stream_concurrency` entries active; one
entry can have both a producer and consumer. Pathname entries run first with
their usual comparison and recovery behavior, then callback entries share
transfer sessions. A mixed mapping therefore has one endpoint setup per phase.
A failed entry does not undo entries that already succeeded.

Producers receive a writable binary file object. Returning normally authorizes
publication; closing the object only ends the bytes. An exception, including
one raised after a wrapper closes the writer, cancels unpublished work. Consumers
receive a readable binary object. Reading through EOF checks transfer success;
a normal early return drains and checks the rest. Consumer exceptions cancel
remaining work. Write extracted files into a staging directory and publish it
after `cp` succeeds. syq cannot undo a consumer's own side effects.

`Client` runs callbacks on worker threads. `AsyncClient` accepts the same
synchronous callbacks, or `async def` callbacks that await `read`, `write`, and
`close`; async callbacks run on the caller's event loop. Cancellation releases
blocked payload I/O. Application code that keeps computing without I/O must
cooperate with cancellation. Do not retain the supplied file object after return.

`StreamSource.size` promises the exact byte count; a mismatch fails before
publication. `MappingEntry.size` remains informational. `expected_hash` checks
the bytes during transfer on every backend; it adds no second download. Without
an expectation or requested integrity check, no extra whole-stream hash is made.
`metadata` sets attributes on named destinations without `preserve`. Source
callbacks have no file metadata to preserve. S3 stores explicit attributes in
syq's existing object metadata format; omitted attributes use new-file defaults.

Skip policies and dry runs do not invoke excluded callbacks. Callbacks always
transfer when selected; they have no saved content identity for comparison or
restart recovery. They cannot use `hash`, content comparison, `inplace`, pruning,
or source-tree ignore rules. Filter entries in your script. Named receiver
grants authorize paths and do not accept callbacks. Callbacks run locally;
mixed pathname transfers between SSH hosts require `coordinate_at="local"`.

Callback runs emit `MappingStreamResult` events with the original zero-based
entry index, `source` and `destination` (`PathValue`, or `None` for a callback),
`disposition`, `dry_run`, optional `bytes`, and optional error `message`.
After a completed run, use failed entry indices to construct an application
retry. Callbacks are never replayed automatically. Their automation records use
schema version 3; ordinary pathname and descriptor calls retain version 2.

<a id="digest-and-hashalgorithm"></a>

### Hash and HashAlgorithm

`Hash(algorithm, value)` describes the expected hash of all bytes in one
regular file. `algorithm` accepts a `HashAlgorithm` value or its string:
`"blake3"`, `"sha256"`, `"md5"`, or `"xxh3-128"`. `value` is hexadecimal:
64 digits for BLAKE3 and SHA-256, 32 for MD5 and XXH3-128. The immutable object
validates the length and characters and stores lowercase hex.

The expectation covers the complete resulting file, including reused bytes.
A mismatch fails the file rather than reporting a successful copy. Files excluded
by selection rules are not hash-verified. `hash=True` still controls whether
existing contents are compared instead of trusting size and modification time.
Dry runs preview changes without validating the expectation. An expected
whole-file hash is independent of the algorithm used for block comparison or
transport checks. MD5 and XXH3-128 are useful for compatibility
and accidental-error detection, but do not provide cryptographic collision
resistance.

### MappingEntry

Frozen dataclass describing one source-to-destination mapping. Pass an iterable
of these to `cp(mapping=...)`; use `dataclasses.replace` to change an entry.

| Attribute | Type | Meaning |
|---|---|---|
| `src` | `RelativePath` or `StreamSource` | Path relative to the source base, or a producer callback |
| `dst` | `RelativePath` or `StreamDestination` | Path relative to the destination container, or a consumer callback |
| `kind` | `EntryKind` or `None` | Object kind, when known; default `None` |
| `size` | `int` or `None` | Informational size in bytes; default `None` |
| `mtime` | `int` or `None` | Informational modification time in Unix seconds; default `None` |
| `expected_hash` | `Hash` or `None` | Expected whole-file hash; requires a regular file; default `None` |
| `metadata` | `DestinationMetadata` or `None` | Explicit destination attributes; default `None` |

`MappingEntry(src, dst, kind=None, size=None, mtime=None, expected_hash=None, metadata=None)` also accepts text or
byte paths for `src` and `dst` and converts them to `RelativePath`. `size` and
`mtime` do not impose preconditions on the copy. `expected_hash` does: a file
cannot succeed unless its contents match. For example, an adapter can supply
an MD5 from a DVC manifest without changing syq's ordinary comparison algorithm:

```python
entry = syq.MappingEntry(
    "cache/object", "data.bin", kind="file",
    expected_hash=syq.Hash("md5", "900150983cd24fb0d6963f7d28e17f72"),
)
client.cp(mapping=[entry], cwd="source", into="download")
```

Mapping files encode it as `"expected_hash": {"algorithm": "md5", "value": "..."}`.
Older syq versions that do not support this field reject the mapping.

### DestinationMetadata

Set destination attributes without modifying the source:

```python
entry = syq.MappingEntry(
    "source.bin", "payload.bin",
    metadata=syq.DestinationMetadata(mode=0o640, mtime=1700000000),
)
client.cp(mapping=[entry], cwd="source", into="output")
```

The keyword-only fields are `mode`, `uid`, `gid`, `mtime`, and `mtime_nsec`,
all optional integers. `mode` contains permission bits only; `uid` and `gid`
are numeric IDs. Times use Unix seconds plus optional nanoseconds. Supplying
`mtime` without `mtime_nsec` uses zero nanoseconds. Omitted attributes follow
normal copy behavior. Explicit attributes do not require `preserve`, except
where a restricted receiver's signed grant needs the corresponding permission.
The [mapping reference](https://greaber.github.io/syq/mappings.html#the-format) describes backend behavior.

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

<!-- ANCHOR_END: mappings -->

<!-- ANCHOR: results -->
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
| `bytes_total_known` | `bool \| None` | For descriptor copies, whether the source length is known; otherwise absent (`None`) |
| `bytes_unchanged` | `int` | Bytes in unchanged files |
| `deletions_planned` | `int` or `None` | Entries selected for pruning |
| `deletions_completed` | `int` or `None` | Entries pruned |
| `deletions_blocked` | `int` or `None` | Pruning deletions blocked by a safety limit |
| `receipt` | `ReceiptSummary` or `None` | Verified receiver receipt details; `None` for ordinary copies |

With `dry_run=True`, mutation totals describe planned changes.
A failed call reports work completed before it stopped.

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
| `schema_version` | `int` | `2` |
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
preserves `expected_hash` and `metadata` and returns a `MappingEntry` when a complete mapping
identity is available, otherwise `None`. Only use collected entries after the call returns a validated `success`
or `partial` result. A terminal callback alone does not establish completion.
The client does not retry automatically.


## Event types

### RunEvent

Invocation details. `started_at` is Unix seconds; `mode` is `"cp"` or `"rm"`.
`prune` and `mapping` are `None` for removal.

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
```

### ProgressEvent

Sampled progress for displays; use the terminal result for final totals.
Byte fields measure file content,
`scanned` counts scanned entries, and `elapsed_ms` is milliseconds. Optional
`activity` contains [diagnostic measurements](https://greaber.github.io/syq/performance-measurements.html)
when the producer collects them; otherwise it is `None`.
Optional `rate_bytes_per_second` and `eta_ms` provide rate and remaining-time
estimates; use final byte counts and elapsed time for completed-run measurements.

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
activity: dict[str, Any] | None
rate_bytes_per_second: int | None
eta_ms: int | None
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
expected_hash: Hash | None
metadata: DestinationMetadata | None
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
s3_version_id: str | None
s3_delete_marker: bool | None
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
s3_version_id: str | None
s3_delete_marker: bool | None
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
`size`; `metadata`, `hash`, and `symlink_target` are present where available.
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
hash: AttestedHash | None
symlink_target: PathValue | None
observation_error: str | None
code: ReceiptCode | None
message: str | None
```

<a id="endpoint-objectmetadata-and-attesteddigest"></a>

### Endpoint, ObjectMetadata, and AttestedHash

Nested frozen dataclasses used by events:

| Type | Fields | Meaning |
|---|---|---|
| `Endpoint` | `role: EndpointRole`, `kind: EndpointKind`, `host: str \| None`, `user: str \| None` | Source/destination and local/SSH/S3 identity; host and user are optional |
| `ObjectMetadata` | `mode: int`, `uid: int`, `gid: int`, `mtime: int`, `mtime_nsec: int`, `rdev: int` | Unix mode, owner/group IDs, modification time (seconds plus nanoseconds), and device ID |
| `AttestedHash` | `algorithm: str`, `value: str` | `"blake3"` and its 64 lowercase hexadecimal hash characters |

## Enums

All enums are string enums exported by `syq`. Members use uppercase names;
values use lowercase, for example `EntryKind.FILE.value == "file"`.
`OperationStatus` is defined with the result types above.

| Type | Members |
|---|---|
| `EntryKind` | `FILE`, `DIR`, `SYMLINK`, `SPECIAL` |
| `EndpointKind` | `LOCAL`, `SSH`, `S3` |
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
| `SyqInstallError` | Bundled executable is missing, or managed installation or verification failed |
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

Timeout, cancellation, early mapping exit, and streaming failures stop the
local process group, including SSH children. Filesystem changes already
completed are not rolled back.
<!-- ANCHOR_END: results -->

<!-- ANCHOR: execution -->
<a id="deliberate-exclusions"></a>

<a id="raw-execution"></a>

## run

`client.run(args, *, check=True, cwd=None, env=None, timeout=CLIENT_DEFAULT, input=None)`
returns [Result](https://greaber.github.io/syq/python-operations.html#result). `input` accepts bytes. `args` is a sequence of arguments
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

For `syq exec`, pass `--cwd` in the argument list to select the receiving
working directory. The SDK's `cwd=` parameter selects the local working
directory of the requesting process. See the
[command example](https://greaber.github.io/syq/python.html#run-other-commands).

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

Python 3.13.4+ on Linux and macOS; no runtime Python dependencies. Each Python
package uses the matching syq release. `syq.__version__` and
`syq.PINNED_SYQ_VERSION` report those versions. Pin the package in your dependency
file to keep the pairing.

### Bundled executable

By default, the SDK runs the executable installed with its Python wheel. It
locates that executable through the package's installation record, without
searching `PATH`, downloading files, or creating an executable cache. Each
Python environment has its own installation. Removing the package also removes
its executable.

### Managed executable

For callers using a separate cache, `Client(cache_dir=...)` downloads the matching executable on first use and verifies
it against the package's embedded release manifest. It checks the cached binary
before every use and replaces missing or corrupt entries. It does not search
`PATH`. `syq.managed_executable()` uses the same download and verification checks.

The default cache is `$XDG_CACHE_HOME/syq/sdk/python/v<version>/` when
`XDG_CACHE_HOME` is absolute, or `~/.cache/syq/sdk/python/v<version>/` otherwise.
Use `Client(cache_dir=...)` to change the cache root, or
`syq.managed_executable()` to download ahead of time and get the path.

### Custom executable

`Client(executable="/opt/bin/syq")` uses that binary;
`Client(executable="syq")` searches `PATH`. Overrides bypass bundled selection and managed download
and verification, so you are responsible for compatibility and origin. Typed
calls still validate automation output. A failed executable selection does not
fall back to another binary.
<!-- ANCHOR_END: execution -->
