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
| `cwd` | Source resolution base, interpreted on the source endpoint, which may be remote |
| `root` | Confine source resolution beneath this directory; requires relative selectors; conflicts with `cwd` |
| `follow`, `follow_src` | Follow source symlinks; `follow` also enables destination following for `cp` |
| `auth_from` | `"auto"`, `"ssh"`, `"@NAME"`, or an SSH provider endpoint; SSH operations request or reuse account access. S3 `cp` and `rm` can request operation authorization through `"@NAME"` |
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
| `mapping` | `Mapping`, `MapStream`, manifest path, or iterable of `MappingEntry`; replaces selectors; conflicts with `as_*`, `prune`, and `prune_before`. Async clients also accept `AsyncMapping` and async iterables |
| `stream_concurrency` | Maximum callback entries active at once; default `4`, range `1..256` |
| `follow_dst` | Boolean: follow destination symlinks |
| `prune_before` | Boolean: remove extras before copying to free space; implies pruning. Later copy failures do not restore removals |
| `widen_dirs` | `"none"` (default), `"rsync"`, or `"all"`: which directories you own may briefly get the owner permission the copy needs, as `--widen-dirs` describes |
| `prune`, `dry_run`, `hash` | Boolean: mirror, preview, or compare content |
| `hash_or_copy` | Boolean: like `hash`, but compare only where the transfer strategy reuses blocks and copy other files whole; cannot combine with `hash` |
| `integrity_checking` | Comma-separated string, e.g. `"transfer=sha256"`; defaults to size/mtime comparison and no extra payload checks |
| `if_exists` | `"error-if-different"`, `"error"`, `"keep"`, `"update"` (default), or `"update-if-older"` |
| `where`, `copy_if` | Expression strings: `where` selects non-directory source entries; `copy_if` decides which entries the copy may create or update; see [expressions](https://greaber.github.io/syq/expressions.html) |
| `ignore` | Pattern string, `IgnoreFrom(path)`, or ordered iterable of either |
| `ignore_from` | Rule file path or iterable of paths; applied after `ignore` |
| `copy_metadata` | Metadata string or iterable, with the values [`--copy-metadata`](https://greaber.github.io/syq/commands/cp.html#metadata-and-symlinks) accepts (`times` is an alias for `mtime`); applies even on unchanged files |
| `open_noatime` | Boolean: request file reads without access-time updates; warns and continues if unavailable |
| `sparse` | Boolean: turn written zero ranges into sparse holes on filesystem destinations |
| `in_place` | `"new"`: write new files directly at their final names, with no staging file; existing files are still replaced. `"update"`: also update existing files in place, as `--in-place=update` does |
| `no_compress` | Boolean: disable compression |
| `max_delete` | Nonnegative integer deletion limit; requires `prune=True` or `prune_before=True` |
| `resource_limits` | Comma-separated ceilings that keep automatic tuning, e.g. `"bandwidth=10M,workers=4"`; a concurrency key conflicts with the same key in `performance_tuning` |
| `transfer_strategy` | `"whole-file"`, `"aligned-block"`, or `"locality"` (default); filesystem copies only; see [transfer strategies](https://greaber.github.io/syq/reference.html#choose-a-transfer-strategy) |
| `performance_tuning` | Comma-separated overrides, e.g. `"workers=4"` or `"s3-objects=4,s3-parts-per-object=8,s3-requests=16"`; omitted means automatic |
| `s3_endpoint`, `s3_region`, `s3_profile` | Endpoint URL, signing region, and AWS profile strings |
| `s3_header` | Iterable of `"NAME: VALUE"` strings; applied before signing every request |
| `s3_retries` | Integer from 0 to 100: how many times to retry each S3 request after a temporary failure or throttling; omitted means 10, and `0` turns retries off |
| `s3_write_header` | Iterable of `"NAME: VALUE"` strings; applied only to requests that create or replace objects |
| `coordinate_at`, `rsh`, `peer_auth` | Coordinator, SSH command, and peer authentication strings |
| `pscope` | Existing persistence domain for connections and saved authorization choices |
| `syq_path` | Remote executable path |
| `no_bootstrap`, `no_tcp_encryption`, `no_tcp` | Boolean remote/transport controls |
| `tcp_ports`, `tcp_congestion` | Port range and congestion-control strings |
| `receiver_max_entries`, `receiver_max_bytes` | Receiver ceilings: integer entries, native size string or integer bytes |
| `on_event`, `results`, `check` | See [events and failures](https://greaber.github.io/syq/python-results.html) |

Option behavior is covered in [Copy files](https://greaber.github.io/syq/reference.html),
[Remote copy details](https://greaber.github.io/syq/remote-reference.html),
and [Object storage](https://greaber.github.io/syq/object-storage.html).

For example, `client.cp("data", to="s3://bucket", into="backup",
s3_header=["X-Tigris-Consistent: true"])` uploads local data using credentials
from the subprocess environment or AWS configuration. A copy cannot combine an
SSH endpoint with an S3 endpoint.

`pscope` selects an isolated domain for connections, receiving settings, and
saved authorization choices; see
[persistence in scripts](https://greaber.github.io/syq/persistence-reference.html#isolated-script-scopes).

Typed SSH-to-SSH copies use an enrolled receiver, approved account access to
both endpoints, or `coordinate_at="local"`. Use `run` for detached commands and
human output options.

`IgnoreFrom(path)` is a frozen dataclass holding a rule-file path (`str`,
`bytes`, or `os.PathLike`). To interleave rule files and inline patterns:
`ignore=[syq.IgnoreFrom("rules"), "!keep.tmp"]`. The last matching rule wins.
<!-- ANCHOR_END: operations -->

<!-- ANCHOR: streams -->
## Byte streams

`client.open_writer(*, as_=None, as_new=None, as_existing=None, to=None,
follow_dst=False, ...)` returns a `StreamWriter`. Choose exactly one of
`as_`, `as_new`, or `as_existing`; the latter two require the destination to
be absent or present, as in `cp`.
`client.open_reader(src, *, from_=None, cwd=None, root=None, follow_src=False, ...)`
returns a `StreamReader`. `cwd` resolves relative sources on the source
endpoint, and `root` also confines them; choose at most one. Both accept `rsh`,
`syq_path`, `pscope`, `no_bootstrap`, `no_compress`, `no_tcp`, `no_tcp_encryption`,
`tcp_ports`, `tcp_congestion`, `auth_from`, `s3_endpoint`, `s3_region`, `s3_profile`, `s3_header`,
`s3_retries`, `performance_tuning`, `resource_limits`, `integrity_checking`, `if_exists`,
`dry_run`, `stats`, `verbose`, `quiet`, `progress`, `no_progress`,
and `timeout` with the same meanings as `cp`. `open_writer` also accepts
`s3_write_header`.
See the [CLI stream reference](https://greaber.github.io/syq/commands/cp.html#transport-and-limits)
for the tuning and integrity controls that apply to streams. Stream calls
always check transfer failures.

These methods transfer raw bytes, using the CLI's [stream semantics](https://greaber.github.io/syq/commands/cp.html#file-descriptors)
for destination permissions, metadata, and endpoint restrictions. They are
sequential and not seekable; use one operation at a time on each stream. An
interrupted stream is not resumed.

| Object | Operations |
|---|---|
| `StreamWriter` | `write(bytes)` writes the complete buffer and returns its length; `flush()` has no Python buffer to flush; `close()` ends payload input; `commit()` publishes and checks completion; `abort()` cancels |
| `StreamReader` | `read(size=-1)`, `readinto(buffer)`; `close()` reads any remaining bytes and checks completion; `abort()` cancels |

`read()` without a size collects all remaining bytes in memory and checks
completion before returning.

### Writer completion

Use a `with` block to commit on successful exit or abort on an exception.
An abort before commit does not replace the destination. `close()` only ends
payload input; it does not publish the file. Successful context exit commits
even if you already called `close()`, unless you also called `abort()`.

Writers support `io.BufferedWriter` and `io.TextIOWrapper`. Close the wrapper
before committing the underlying writer so its buffered data is flushed.

Outside a context, finish with `commit()` or `abort()`; `close()` alone leaves
the transfer pending. `commit()` publishes immediately, so later application
errors cannot undo it; it can be repeated after success and fails after an
abort. A timeout or connection loss during commit can leave the outcome
uncertain, and the method then reports failure. A dataset of several objects
needs its own final publication step after every transfer succeeds.

### Skips and previews

Opening a writer returns before the destination is ready, so setup errors can
surface at `write()` or `commit()`. With `if_exists="keep"` or `dry_run=True`,
opening waits for the destination decision; check `output.skipped` before
producing data:

```python
with client.open_writer(to="server", as_="archive.tar", if_exists="keep") as output:
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

A bounded `read(size)` can return data before a later transfer error. An
exception inside either context cancels the transfer and propagates unchanged.
A writer that was never committed is aborted when it is garbage collected,
which can block, so use a `with` block for timely cleanup.

`timeout` covers the stream's whole lifetime, including blocked reads and
writes, and raises `subprocess.TimeoutExpired` unless the transfer has already
succeeded. Transfer failures raise `SyqProcessError`, whose result contains the
exit status and the last 8 KiB of diagnostics. The stream's `stderr` property
holds the same bytes, including on success; for example, request `stats=True`
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

Async streams start on context entry, and cancellation stops the transfer.
`AsyncStreamReader` and `AsyncStreamWriter` have async `read`/`write`, `close`,
and `abort` methods, and `AsyncStreamWriter.commit()` works like its
synchronous counterpart.
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

`rm(*sources, **options)` → [RmResult](https://greaber.github.io/syq/python-results.html#rmresult) removes selected entries on local, SSH, or S3
endpoints; restricted receivers refuse removal. Besides the shared arguments, it accepts `on`, `dry_run`,
`performance_tuning`, `syq_path`, `no_bootstrap`, `pscope`, `on_event`,
`results`, and `check` with the types above. `performance_tuning="workers=N"`
fixes filesystem deletion concurrency, and `"s3-requests=N"` fixes it for S3.
See [Remove files](https://greaber.github.io/syq/remove.html).

S3 removal uses `rm(..., on="s3://bucket")` with optional `s3_endpoint`,
`s3_region`, `s3_profile`, `s3_header`, `s3_retries`, and `auth_from="@NAME"`. `s3_all_versions=True` permanently
removes all selected versions and delete markers; `s3_version_id="ID"` selects
one version of one exact key. These options are mutually exclusive.
`RemovalTrace` and `RemovalResult` expose optional `s3_version_id` and
`s3_delete_marker` fields.
<!-- ANCHOR_END: removal -->

<!-- ANCHOR: mappings -->
<a id="complete-input-guarantee"></a>

<a id="mapping-transformation-and-copy"></a>

## map

`map(*sources, **options) → MapStream` lists local, SSH, or S3 source entries
without copying. Use `from_="server"` or `from_="s3://bucket"` for a remote
source. Besides the shared arguments, it accepts `as_` to rename a selected
object. `srcs_in` must be the sole selector when used. `where` accepts the same
source expression as `cp(where=...)`. As in `cp`, it does not filter
directories, and expression fields are included in output only when requested
through `include`.

By default entries contain only source and destination paths. `include` is an
iterable of field names: `kind`, `size`, `mtime`, and `s3_last_modified`, with
the meanings given in the
[mapping format](https://greaber.github.io/syq/commands/map.html#mapping-format).
`kind` adds a copy-time type check; the other fields are informational.

Connection options are `auth_from`, `rsh`, `syq_path`, `no_bootstrap`, `pscope`,
`s3_endpoint`, `s3_region`, `s3_profile`, and `s3_header`, with the same types as on `cp`.
Explicit connection options are kept through transformations and copying.
For example, the consumer uses the same object service here:

```python
with client.map(from_="s3://photos", srcs_in="originals",
                s3_endpoint="https://objects.example.com",
                s3_region="us-east-1") as mapping:
    client.cp(mapping=mapping, into="restored")
```

`s3_retries` works as on `cp` but applies only to the listing; the mapping
does not keep it, so pass it to `cp` as well if the copy should use it.

`MapStream` is a `Mapping` and an iterable context manager; use `with`.
`AsyncMapStream` is an `AsyncMapping` and an async context manager; use
`async with`. Consume a stream inside its context; it cannot be reused after
completion or closure. Async streams use the client's directory, environment,
and timeout as they were when the stream was created.

### Mapping and AsyncMapping

A mapping combines entries with their source endpoint, base, and explicit
connection options. Pass it directly to `cp(mapping=...)`, even on a client
with a different `process_cwd`.

`Mapping(entries, *, from_=None, cwd=None, root=None, follow_src=False,
**connection_options)` accepts an iterable of `MappingEntry`.
`AsyncMapping(...)` accepts an async iterable. The connection options are the
same options listed for `map` above.

Supply at most one of `cwd` and `root`; `root` confines source resolution.
Local relative bases resolve against the Python process directory at
construction, not a client's `process_cwd`. With neither supplied, the local
base is that directory. Remote bases remain strings interpreted at the source
endpoint, defaulting to `"."`; remote `~` is not expanded using the local home.

| Member | Type | Meaning |
|---|---|---|
| `from_` | `str` or `None` | Source endpoint; `None` means local |
| `cwd` | `pathlib.Path` or `str` | Absolute local source-base spelling, or a base interpreted at the remote endpoint |
| `root` | `pathlib.Path`, `str`, or `None` | Confinement base, when created with `root` |
| `follow_src` | `bool` | Whether the copy should follow source symlinks |
| `transform(function)` | `Mapping` or `AsyncMapping` | Lazy transformation that keeps the source context |

The context properties are read-only. A transform receives each `MappingEntry`
and returns a replacement entry, or `None` to omit it. Transformations can be
chained. Async transforms also accept awaitable callbacks and await them in
entry order. Neither form caches entries; reuse depends on the supplied iterable.

When you copy a mapping that carries a source context, `cp` rejects `from_`,
`cwd`, and `root`, and rejects connection options that conflict with the ones
the mapping was created with. Connection settings you did not specify come from
the copy's environment and configuration, so specify `s3_endpoint` when the
service must stay the same across clients. The mapping holds no credentials
and no snapshot of the source; the copy reads the sources again.
`map(root=..., srcs_in=...)` makes the selected directory the copy's root.

Iterating a stream to its end checks the mapping process status, and leaving
its context early stops the process. An exhausted or closed stream cannot be
copied as an empty mapping.

`cp(mapping=iterable)` reads the entire iterable before copying starts, so an
iteration, transformation, or serialization failure starts no copy. Plain
iterables and manifest paths have no source context; pass `cwd`, `root`, or
`from_` as needed. See
[mapping rules](https://greaber.github.io/syq/mappings.html).

<a id="callback-mappings"></a>

### Callback mappings

`StreamSource(produce, *, size=None)` supplies bytes to one mapping entry.
`StreamDestination(consume)` receives them. Pass either or both as the `src`
and `dst` of a `MappingEntry`; callback entries require `kind=None` or `"file"`.
These objects work with live `cp(mapping=...)` calls, not saved pathname manifests.

The complete iterable is validated before any callback runs or the
destination changes. Callbacks start as needed, with at most
`stream_concurrency` entries active; one entry can have both a producer and a
consumer. Pathname entries in the same mapping copy first. A failed entry does
not undo entries that already succeeded.

Producers receive a writable binary file object. Returning normally authorizes
publication; closing the object only ends the bytes. An exception, including
one raised after a wrapper closes the writer, cancels unpublished work. Consumers
receive a readable binary object. Reading through EOF checks transfer success;
a normal early return drains and checks the rest. Consumer exceptions cancel
remaining work. Write extracted files into a staging directory and publish it
after `cp` succeeds. syq cannot undo a consumer's own side effects.

`Client` runs callbacks on worker threads. `AsyncClient` accepts the same
synchronous callbacks, or `async def` callbacks that await `read`, `write`, and
`close` on the caller's event loop. Cancellation interrupts blocked reads and
writes, but code that keeps computing without I/O must check for cancellation
itself. Do not keep the file object after the callback returns.

`StreamSource.size` promises the exact byte count, and a mismatch fails before
publication; `MappingEntry.size` remains informational. `expected_hash` checks
the bytes as they transfer. `metadata` sets attributes on named destinations
without `copy_metadata`; source callbacks have no file metadata to preserve.

Skip policies and dry runs do not invoke excluded callbacks. A selected
callback always transfers, since there is nothing to compare it with or resume
from, so callbacks cannot use `hash`, content comparison, `in_place`, pruning,
or ignore rules; filter entries in your script instead. Copies to or from a
receiving name do not accept callbacks. Callbacks run locally, so a mapping
that also copies pathnames between SSH hosts requires `coordinate_at="local"`.

Callback runs emit `MappingStreamResult` events with `entry`, the original
zero-based entry index, `source` and `destination` (`PathValue`, or `None` for a callback),
`disposition`, `dry_run`, optional `bytes`, and optional error `message`.
Use the failed entry indices to build your own retry; callbacks are never
replayed automatically. These records use automation schema version 5.

<a id="digest-and-hashalgorithm"></a>

### Hash and HashAlgorithm

`Hash(algorithm, value)` describes the expected hash of all bytes in one
regular file. `algorithm` accepts a `HashAlgorithm` value or its string:
`"blake3"`, `"sha256"`, `"md5"`, or `"xxh3-128"`. `value` is hexadecimal:
64 digits for BLAKE3 and SHA-256, 32 for MD5 and XXH3-128. The immutable object
validates the length and characters and stores lowercase hex.

The expectation covers the complete resulting file, including reused bytes,
and a mismatch fails the file. Files that selection rules skip are not checked,
and dry runs do not check the expectation. `hash=True` still controls whether
existing contents are compared instead of trusting size and modification time.
MD5 and XXH3-128 detect accidental errors but do not resist deliberate
collisions.

### MappingEntry

Frozen dataclass describing one source-to-destination mapping. Pass an iterable
of these to `cp(mapping=...)`; use `dataclasses.replace` to change an entry.

| Attribute | Type | Meaning |
|---|---|---|
| `src` | `RelativePath` or `StreamSource` | Path relative to the source base, or a producer callback |
| `dst` | `RelativePath` or `StreamDestination` | Path relative to the destination container, or a consumer callback |
| `kind` | `EntryKind` or `None` | Object kind, when known; default `None` |
| `size` | `int` or `None` | Informational size in bytes; default `None` |
| `mtime` | `int` or `None` | Informational filesystem modification time in Unix seconds; default `None` |
| `s3_last_modified` | `int` or `None` | Informational S3 object modification time in Unix seconds; default `None` |
| `expected_hash` | `Hash` or `None` | Expected whole-file hash; requires a regular file; default `None` |
| `metadata` | `DestinationMetadata` or `None` | Explicit destination attributes; default `None` |

`MappingEntry(src, dst, kind=None, size=None, mtime=None, expected_hash=None,
metadata=None, s3_last_modified=None)` also accepts text or byte paths for
`src` and `dst` and converts them to `RelativePath`. With `expected_hash`, a file
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
normal copy behavior. Explicit attributes do not require `copy_metadata`, except
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
| `files_excluded` | `int` | Source entries excluded from copying, including ignore matches; an ignored directory counts once |
| `directories_created` | `int` | Directories created |
| `symlinks_created` | `int` | Symbolic links created |
| `specials_created` | `int` | Special filesystem objects created |
| `bytes_transferred` | `int` | File-content bytes transferred, not compressed network traffic |
| `bytes_total_known` | `bool \| None` | For descriptor copies, whether the source length is known; otherwise absent (`None`) |
| `bytes_unchanged` | `int` | Bytes not copied because the destination already had them: unchanged files and data reused inside transferred files |
| `deletions_planned` | `int` or `None` | Entries selected for pruning |
| `deletions_completed` | `int` or `None` | Entries pruned |
| `deletions_blocked` | `int` or `None` | Pruning deletions blocked by a safety limit |
| `replaced_not_in_place` | `dict[str, int]` or `None` | With `in_place="update"`, existing files replaced instead of updated in place, by reason (see `--results`) |

With `dry_run=True`, mutation totals describe planned changes.
A failed call reports work completed before it stopped.

Copies have all three deletion fields with `prune=True` or `prune_before=True`;
otherwise they are `None`.

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
| `timings` | `Timings` | Run and work measurements in milliseconds |
| `protocol` | `ProtocolMetadata` | Automation envelope; also present on every event |

### Timings

Frozen dataclass accessed through `result.timings` or `event.timings` on progress
events. Durations are wall-clock milliseconds. Work measurements can overlap and
must not be added together. `None` means unavailable; zero means no work or less than a millisecond.
See [measurement boundaries](https://greaber.github.io/syq/automation.html#result).

| Attribute | Type | Meaning |
|---|---|---|
| `total_ms` | `int` | Measured run, including helper installation |
| `setup_ms` | `int \| None` | Endpoint and connection setup, excluding installation |
| `planning_ms` | `int \| None` | Discovery, destination inspection, and work preparation |
| `transfer_ms` | `int \| None` | First through last selected file operation |
| `finalization_ms` | `int \| None` | Remaining work after file workers finish |
| `helper_install_ms` | `int \| None` | Helper and remote command installation |

### ProtocolMetadata

Frozen dataclass accessed through `result.protocol` or `event.protocol`.
The SDK checks these fields; applications normally only need them when recording
or diagnosing a stream.

| Attribute | Type | Meaning |
|---|---|---|
| `schema` | `str` | `"syq.automation"` |
| `schema_version` | `int` | `4`; callback mappings use `5` |
| `seq` | `int` | Record sequence number, starting at zero |
| `type` | `str` | Wire record type; `"result"` for terminal totals |

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

`AutomationEvent` is the union of the event classes below, `CpResult`,
`RmResult`, and `MappingStreamResult` from
[callback mappings](https://greaber.github.io/syq/python-streams.html#callback-mappings).
Each event is a frozen dataclass. Its fields are listed below;
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
`scanned` counts scanned entries, and `timings` contains elapsed measurements. Optional
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
timings: Timings
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

One copy outcome. `dst` is relative to the destination container. `src` is
present for mapping entries when available. `bytes` and `attempts` give transfer
information. Error details are present when known; `message` is display text.
Outcomes reported by a restricted receiver have no `src`, `attempts`, or
`retryable`.

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

One error. `message` is display text; `class_` and `os_kind` classify it when
known. Each counts toward `errors`, except one with `diagnostic_for`: it
explains why a command-restricted receiver reported that destination path as
failed, and the receiver's own error counts the failure.

`protocol.type = "error"`. Fields in addition to the common envelope:

```python
message: str
class_: ErrorClass | None
os_kind: OsKind | None
diagnostic_for: PathValue | None
```

### Endpoint

A nested frozen dataclass used by run events:

| Type | Fields | Meaning |
|---|---|---|
| `Endpoint` | `role: EndpointRole`, `kind: EndpointKind`, `host: str \| None`, `user: str \| None` | Source/destination and local/SSH/S3 identity; host and user are optional |

## Enums

All enums are string enums exported by `syq`. Members use uppercase names;
values use lowercase, for example `EntryKind.FILE.value == "file"`.
`OperationStatus` is defined with the result types above.

| Type | Members |
|---|---|
| `EntryKind` | `FILE`, `DIR`, `SYMLINK`, `SPECIAL` |
| `EndpointKind` | `LOCAL`, `SSH`, `S3` |
| `EndpointRole` | `SOURCE`, `DESTINATION` |
| `OperationAction` | `TRANSFER_FILE`, `CREATE_DIRECTORY`, `CREATE_SYMLINK`, `CREATE_SPECIAL`, `DELETE` |
| `Disposition` | `SUCCEEDED`, `FAILED`, `BLOCKED` |
| `Retryability` | `YES`, `NO`, `UNKNOWN` |
| `ErrorClass` | `IO`, `TRANSPORT`, `CONFLICT`, `INTEGRITY`, `SAFETY_LIMIT`, `USAGE`, `INTERNAL` |
| `OsKind` | `NOT_FOUND`, `PERMISSION_DENIED`, `ALREADY_EXISTS`, `INVALID_INPUT`, `NO_SPACE`, `QUOTA_EXCEEDED`, `READ_ONLY`, `OTHER` |
| `TraceReason` | `DESTINATION_MISSING`, `TYPE_DIFFERS`, `CONTENT_DIFFERS`, `METADATA_DIFFERS`, `DESTINATION_ONLY` |
| `SelectionStatus` | `RESOLVED`, `MISSING` |
| `RemovalDisposition` | `WOULD_REMOVE`, `REMOVED`, `ALREADY_ABSENT`, `FAILED` |

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

A timeout covers the syq process only, not a managed download or reading a
mapping iterable before the process starts; async cancellation also stops
reading the iterable.

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

By default, the SDK runs the executable installed with its Python wheel,
without searching `PATH` or downloading anything. Each Python environment has
its own copy, and removing the package removes it.

### Managed executable

`Client(cache_dir=...)` instead downloads the matching executable on first use
and verifies it against the package's embedded release manifest. It checks the
cached binary before every use and replaces a missing or corrupt one.

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
