<!-- ANCHOR: operations-title -->
<a id="python-native-api"></a>

<a id="positioning"></a>

<a id="scope"></a>

<a id="product-readiness"></a>

<!-- ANCHOR_END: operations-title -->

# API reference

<!-- ANCHOR: operations -->

The module functions `syq.cp`, `syq.rm`, `syq.map`, `syq.open_reader`, and
`syq.open_writer` use a default `Client`; create your own client to share
settings across calls. `AsyncClient` takes the same arguments and returns the
same types. Await its operations, except `map`, `open_reader`, and
`open_writer`, which return async context managers.

<a id="synchrony-asyncio-and-resource-ownership"></a>

## Client and executable selection

`Client(*, executable=None, cache_dir=None, process_cwd=None, env=None, timeout=None)`
and `AsyncClient(...)` accept:

| Argument | Meaning |
|---|---|
| `executable` | Path of another syq, or a name to find on `PATH`; default: the bundled syq |
| `cache_dir` | Download a verified syq into this cache directory instead of using the bundled one |
| `process_cwd` | Working directory of the syq process; default: inherited |
| `env` | Environment of the syq process; default: inherited |
| `timeout` | Timeout for each operation, in seconds; default: none |

`client.version()` and `syq.version(executable=None)` return the executable's
version. See
[Compatibility](https://greaber.github.io/syq/python-operations.html#compatibility)
for how the executable is chosen.

<a id="the-native-vocabulary-is-the-python-vocabulary"></a>

## Arguments and validation

Arguments use the CLI option names, with underscores for hyphens and a trailing
underscore on Python keywords (`from_`, `as_`). Paths can be `str`, `bytes`, or
`os.PathLike`, and a selector takes one path or an iterable of paths:
`src=["a", "b"]` is the CLI's `--srcs a b`.

| Shared by `cp`, `rm`, and `map` | Meaning |
|---|---|
| `*sources`, `src` | Select named objects |
| `srcs_in` | Select a directory's contents |
| `src_non_dir`, `src_dir` | Select objects that must be non-directories or directories |
| `cwd` | Directory that relative source paths start from, on the source machine |
| `root` | Like `cwd`, but refuse any path that escapes it; selectors must be relative; cannot combine with `cwd` |
| `follow`, `follow_src` | Follow source symlinks; for `cp`, `follow` also follows destination symlinks |
| `auth_from` | `"auto"`, `"ssh"`, `"@NAME"`, or an SSH provider endpoint, as for `--auth-from`. For S3 `cp` and `rm`, `"@NAME"` asks that machine to authorize the operation |
| `timeout` | Seconds, or `None` for no timeout; omitted: the client's timeout |

Flags default to `False` and other optional arguments to `None`, except `check`,
which defaults to `True`, and `timeout`, which defaults to the client's
timeout. Invalid combinations raise
`SyqInvocationError`.

<a id="a-normal-copy"></a>

<a id="copy-and-prune"></a>

<a id="dry-runs"></a>

## cp

`cp(*sources, **options)` → [CpResult](https://greaber.github.io/syq/python-results.html#cpresult)
copies files. Choose one placement argument unless every destination is a
callback. Besides the shared arguments, it accepts the following;
[Copy files](https://greaber.github.io/syq/reference.html),
[Remote copy details](https://greaber.github.io/syq/remote-reference.html), and
[Object storage](https://greaber.github.io/syq/object-storage.html) describe
what they do.

| Options | Values / purpose |
|---|---|
| `from_`, `to` | SSH endpoint or `s3://BUCKET`; omitted means local. One copy cannot combine SSH and S3 |
| `into`, `into_new`, `into_existing` | Destination directory |
| `as_`, `as_new`, `as_existing` | Exact destination path |
| `mapping` | `Mapping`, `MapStream`, manifest path, or iterable of `MappingEntry`, instead of selectors; conflicts with `as_*`, `prune`, and `prune_before`. Async clients also accept `AsyncMapping` and async iterables |
| `stream_concurrency` | Most callback entries active at once; default `4`, range `1..256` |
| `follow_dst` | Follow destination symlinks |
| `prune`, `dry_run`, `hash` | Mirror, preview, or compare contents |
| `prune_before` | Like `prune`, but remove extras before copying, to free space; a later failure does not restore them |
| `max_delete` | Refuse all deletions if more than this many are planned; requires `prune` or `prune_before` |
| `hash_or_copy` | Like `hash`, but compare only where blocks can be reused and copy other files whole; cannot combine with `hash` |
| `integrity_checking` | String such as `"transfer=sha256"`; default: size and time comparison, no extra checks |
| `if_exists` | `"error-if-different"`, `"error"`, `"keep"`, `"update"` (default), or `"update-if-older"` |
| `where`, `copy_if` | [Expressions](https://greaber.github.io/syq/expressions.html): `where` selects non-directory sources; `copy_if` decides which entries may be created or updated |
| `ignore` | Pattern, `IgnoreFrom(path)`, or an ordered iterable of both |
| `ignore_from` | Rule file path or paths; applied after `ignore` |
| `copy_metadata` | String or iterable of [`--copy-metadata`](https://greaber.github.io/syq/commands/cp.html#metadata-and-symlinks) values (`times` is an alias for `mtime`); applies to unchanged files too |
| `widen_dirs` | `"none"` (default), `"rsync"`, or `"all"`: which of your directories may briefly get the owner permission the copy needs, as `--widen-dirs` describes |
| `open_noatime` | Read without updating access times where possible; warns otherwise |
| `sparse` | Write zero ranges as sparse holes on filesystem destinations |
| `in_place` | `"new"`: write new files at their final names instead of under a temporary name, except a new file that must not replace anything (`as_new`, or under `if_exists="error"` or `"error-if-different"`). `"update"`: also update existing files in place, as `--in-place=update` describes |
| `no_compress` | Disable compression |
| `transfer_strategy` | `"whole-file"`, `"aligned-block"`, or `"locality"` (default); filesystem copies only; see [transfer strategies](https://greaber.github.io/syq/reference.html#choose-a-transfer-strategy) |
| `performance_tuning` | Overrides such as `"workers=4"` or `"s3-objects=4,s3-parts-per-object=8"`; default: automatic |
| `resource_limits` | Ceilings such as `"bandwidth=10M,workers=4"`, below which tuning stays automatic; a concurrency key cannot also appear in `performance_tuning` |
| `s3_endpoint`, `s3_region`, `s3_profile` | S3 endpoint URL, signing region, and AWS profile |
| `s3_header` | Iterable of `"NAME: VALUE"` headers added before signing to every S3 request |
| `s3_write_header` | Like `s3_header`, but only on requests that create or replace objects |
| `s3_retries` | Retries per S3 request after a temporary failure or throttling, 0 to 100; default 10 |
| `coordinate_at`, `rsh`, `peer_auth` | As `--coordinate-at`, `--rsh`, and `--peer-auth` |
| `pscope` | An [isolated persistence domain](https://greaber.github.io/syq/persistence-reference.html#isolated-script-scopes) for connections and saved authorization choices |
| `syq_path`, `no_bootstrap` | Use this remote syq, or the one on the remote `PATH`, instead of installing one |
| `no_tcp_encryption`, `no_tcp`, `tcp_ports`, `tcp_congestion` | As the CLI options of the same names |
| `receiver_max_entries`, `receiver_max_bytes` | Limits for a restricted copy: an entry count, and a size string or byte count |
| `on_event`, `results`, `check` | See [events and failures](https://greaber.github.io/syq/python-results.html) |

To copy between two SSH servers, `cp` uses
[restricted copying](https://greaber.github.io/syq/remote-to-remote.html) on
the destination, which the first copy sets up as in the CLI; approved account
access to both servers; or `coordinate_at="local"`. For `--detach` and
human-readable output options, use `run`.

`IgnoreFrom(path)` names a rule file, so you can interleave files and patterns:
`ignore=[syq.IgnoreFrom("rules"), "!keep.tmp"]`. The last matching rule wins.
<!-- ANCHOR_END: operations -->

<!-- ANCHOR: streams -->
## Byte streams

Use a byte stream to write one destination or read one source from your own
code, without a temporary file. Streams follow the CLI's
[descriptor-copy rules](https://greaber.github.io/syq/commands/cp.html#file-descriptors)
for permissions, metadata, and which endpoints work. They are sequential and
not seekable, and start over if interrupted.

`client.open_writer(*, as_=None, as_new=None, as_existing=None, to=None,
follow_dst=False, ...)` returns a `StreamWriter`. Give exactly one of `as_`,
`as_new`, or `as_existing`.

`client.open_reader(src, *, from_=None, cwd=None, root=None, follow_src=False, ...)`
returns a `StreamReader`. `cwd` and `root` work as in `cp`; give at most one.

Both also accept these `cp` arguments: `rsh`, `syq_path`, `pscope`,
`no_bootstrap`, `no_compress`, `no_tcp`, `no_tcp_encryption`, `tcp_ports`,
`tcp_congestion`, `auth_from`, `s3_endpoint`, `s3_region`, `s3_profile`,
`s3_header`, `s3_retries`, `performance_tuning`, `resource_limits`,
`integrity_checking`, `if_exists`, `dry_run`, `stats`, `verbose`, `quiet`,
`progress`, `no_progress`, and `timeout`. `open_writer` also accepts
`s3_write_header`. Only some tuning settings apply; see
[descriptor copy limits](https://greaber.github.io/syq/commands/cp.html#transport-and-limits).
A stream always raises on a transfer failure; it has no `check` argument.

| Object | Operations |
|---|---|
| `StreamWriter` | `write(bytes)` writes the whole buffer and returns its length; `flush()` does nothing; `close()` ends the input without publishing; `commit()` publishes and waits for success; `abort()` cancels |
| `StreamReader` | `read(size=-1)` and `readinto(buffer)`, where `read()` with no size reads everything left into memory and returns once the transfer succeeds; `close()` reads the rest and waits for success; `abort()` cancels |

### Writer completion

Use a `with` block: the writer publishes when the block exits without an
exception. An exception inside a writer's or reader's block cancels the
transfer, leaves the destination unchanged, and propagates unchanged. Calling
`close()` in the block does not stop publication; only `abort()` does. If you wrap the writer in
`io.BufferedWriter` or `io.TextIOWrapper`, close the wrapper before the writer
commits, so its buffered data is written.

Without a `with` block, finish with `commit()` or `abort()`; after `close()`
alone, the transfer stays pending, and an uncommitted writer is aborted only
when it is garbage-collected, which can block. `commit()` publishes at once, so a later
error in your program cannot undo it. If a timeout or lost connection
interrupts it, `commit()` raises without knowing whether the file was
published.

### Skips and previews

`open_writer` returns before the destination is ready, so setup errors can
appear at `write()` or `commit()`. With `if_exists="keep"` or `dry_run=True`,
it waits for syq's decision instead; check `output.skipped` before producing
data:

```python
with client.open_writer(to="server", as_="archive.tar", if_exists="keep") as output:
    if not output.skipped:
        produce_archive(output)
```

A skipped writer rejects `write()`, and its block exits without publishing. A
skipped reader returns no data, and its `skipped` is set once it completes.

With `dry_run=True`, entering and leaving the block checks placement without
transferring data: writers reject `write()`, readers return nothing, and the
result has the planned totals.

### Results and failures

After completion, `stream.result` holds a `CpResult`, or `None` if syq never
reported one, as after a forced kill.

`read(size)` can return data before a later transfer error, so treat the data
as complete only when the reader's block exits without an exception.

`timeout` covers the stream's whole life, including time blocked in reads and
writes, and raises `subprocess.TimeoutExpired` unless the transfer already
succeeded. A failed transfer raises `SyqProcessError`, whose result holds the
exit status and the last 8 KiB of diagnostics. The stream's `stderr` holds the
same bytes, also after success; for example, pass `stats=True` and read
`output.stderr.decode()` after the writer's block.

### Async streams

Async streams use `async with` and await reads, writes, and closing:

```python
client = syq.AsyncClient()
async with client.open_writer(to="server", as_="generated.bin") as output:
    await output.write(b"generated bytes")
async with client.open_reader("generated.bin", from_="server") as source:
    while chunk := await source.read(65536):
        await consume(chunk)
```

An async stream starts when its block is entered, and cancellation stops the
transfer. Their `read` or `write`, `close`, `abort`, and (on writers) `commit`
methods are coroutines.
<!-- ANCHOR_END: streams -->

<!-- ANCHOR: removal -->
<a id="removal"></a>

## rm

`rm(*sources, **options)` → [RmResult](https://greaber.github.io/syq/python-results.html#rmresult)
removes the selected entries locally, on an SSH server (`on="server"`), or in
S3 (`on="s3://bucket"`); see [Remove files](https://greaber.github.io/syq/remove.html).
Besides the shared arguments, it accepts `on`, `dry_run`, `performance_tuning`,
`syq_path`, `no_bootstrap`, `pscope`, `on_event`, `results`, and `check`, as on
`cp`. `performance_tuning="workers=N"` sets how many filesystem deletions run
at once, and `"s3-requests=N"` does the same for S3.

Selectors follow the
[`syq rm` rules](https://greaber.github.io/syq/commands/rm.html#selection-rules):
positional sources and `src` refuse directories, `src_dir` removes a directory,
and `srcs_in` empties it.

For S3, `s3_endpoint`, `s3_region`, `s3_profile`, `s3_header`, `s3_retries`,
and `auth_from="@NAME"` work as on `cp`. In a versioned bucket,
`s3_all_versions=True` permanently removes all versions and delete markers of
the selected keys, and `s3_version_id="ID"` removes one version of one exact
key; use at most one of them.
<!-- ANCHOR_END: removal -->

<!-- ANCHOR: mappings -->
<a id="complete-input-guarantee"></a>

<a id="mapping-transformation-and-copy"></a>

## map

`map(*sources, **options) → MapStream` lists source entries without copying,
locally or from `from_="server"` or `from_="s3://bucket"`. Besides the shared
arguments, it accepts `as_` to rename one selected object, and `include`, an
iterable of the extra fields to add to each entry: `kind`, `size`, `mtime`, or
`s3_last_modified`. `where`, `srcs_in`, and these fields work as for
[`syq map`](https://greaber.github.io/syq/commands/map.html#mapping-format).

The connection options are `auth_from`, `rsh`, `syq_path`, `no_bootstrap`,
`pscope`, `s3_endpoint`, `s3_region`, `s3_profile`, and `s3_header`. The
mapping keeps the ones you pass and uses them when you copy it, so here the
copy reaches the same service as the listing:

```python
with client.map(from_="s3://photos", srcs_in="originals",
                s3_endpoint="https://objects.example.com",
                s3_region="us-east-1") as mapping:
    client.cp(mapping=mapping, into="restored")
```

`s3_retries` applies only to the listing; pass it to `cp` too if the copy needs
it.

Use a `MapStream` in a `with` block and an `AsyncMapStream` in `async with`,
and consume it inside the block; it cannot be reused afterwards. Reading it to
the end checks that the listing succeeded, and leaving the block early stops
the listing.

### Mapping and AsyncMapping

A `Mapping` holds entries together with their source machine, base
directory, and the connection options you passed, so `cp(mapping=...)` reads
the same sources on any client, even one with another `process_cwd`.

`Mapping(entries, *, from_=None, cwd=None, root=None, follow_src=False,
**connection_options)` takes an iterable of `MappingEntry`, and
`AsyncMapping(...)` an async iterable, with the connection options listed for
`map`. Give at most one of `cwd` and `root`. A local base is resolved when you
create the mapping, against the Python process's directory rather than
`process_cwd`; a remote base is left for the source machine to interpret.

| Member | Type | Meaning |
|---|---|---|
| `from_` | `str` or `None` | Source endpoint; `None` means local |
| `cwd` | `pathlib.Path` or `str` | Absolute local base, or the remote base as given |
| `root` | `pathlib.Path`, `str`, or `None` | Confining base, when created with `root` |
| `follow_src` | `bool` | Whether the copy follows source symlinks |
| `transform(function)` | `Mapping` or `AsyncMapping` | A new mapping with the same sources that applies `function` to each entry as it is read |

`function` receives each `MappingEntry` and returns a replacement, or `None`
to drop it; transforms can be chained, and an async mapping's function can be
async. Mappings do not store entries, so whether you can read one twice depends
on the iterable you supplied.

When you copy a mapping that knows its sources, do not pass `from_`, `cwd`,
`root`, or a conflicting connection option. Settings the mapping does not carry
come from the copy's environment and configuration, so pass `s3_endpoint`
explicitly if the copy must reach the same service as the listing. The mapping
holds no credentials or data; `cp` reads the sources again.

`cp(mapping=...)` reads the whole mapping before copying, so if iterating,
transforming, or encoding entries fails, nothing is copied. A plain iterable or
a manifest path does not know its sources; pass `cwd`, `root`, or `from_` with
it. See [mapping rules](https://greaber.github.io/syq/mappings.html).

<a id="callback-mappings"></a>

### Callback mappings

Use callbacks to produce or consume an entry's bytes in your own code.
`StreamSource(produce, *, size=None)` produces one entry's bytes, and
`StreamDestination(consume)` receives them; use either or both as the `src` and
`dst` of a `MappingEntry` whose `kind` is `None` or `"file"`. Callbacks work
only in a `cp(mapping=...)` call, not in a saved manifest.

Entries with paths copy first; then up to `stream_concurrency` callback
entries run at once. A failed entry does not undo the others.

A producer gets a writable binary file object. Its entry is published only if
it returns normally, and cancelled if it raises, even after closing the file
object. A consumer gets a readable one. Reading to the end checks that the
transfer succeeded; if the consumer returns early, the SDK reads and checks the
rest, and if it raises, the remaining work is cancelled. Syq cannot undo what a
consumer did, so write extracted files to a staging directory and publish it
after `cp` succeeds.

`Client` runs callbacks on worker threads. `AsyncClient` also accepts
`async def` callbacks, which await `read`, `write`, and `close` on your event
loop. Cancellation interrupts blocked reads and writes, but code that computes
without I/O must check for cancellation itself.

`StreamSource(size=...)` promises the exact byte count, and a mismatch fails
the entry before publication; `MappingEntry.size` stays informational.
`expected_hash` is checked as the bytes transfer, and `metadata` sets a named
destination's attributes without `copy_metadata`.

A skip policy or dry run never calls the callbacks of entries it excludes,
but a selected callback always transfers. Callback mappings cannot use `hash`,
content comparison, `in_place`, pruning, or ignore rules; leave unwanted
entries out instead. Callbacks run on this machine, so a mapping that also
copies paths between two SSH servers needs `coordinate_at="local"`.

Each callback entry is reported as a `MappingStreamResult` event, using
automation schema version 5:

```python
entry: int                     # zero-based index in your mapping
source: PathValue | None       # None for a callback
destination: PathValue | None  # None for a callback
disposition: str               # "succeeded", "failed", "skipped", or "planned"
dry_run: bool
bytes: int | None
message: str | None            # on failure
```

Callbacks are never rerun automatically; to retry, build a new mapping from
the indices of the failed entries.

<a id="digest-and-hashalgorithm"></a>

### Hash and HashAlgorithm

To require known contents for a mapped file, give its entry an
`expected_hash`. `Hash(algorithm, value)` is the expected hash of a whole
regular file.
`algorithm` is a `HashAlgorithm` or its string: `"blake3"`, `"sha256"`, `"md5"`,
or `"xxh3-128"`. `value` is hexadecimal: 64 digits for BLAKE3 and SHA-256, 32 for MD5 and
XXH3-128.

A file fails if its complete contents do not match; see
[expected hashes](https://greaber.github.io/syq/integrity-checking.html#expected-hashes)
for when syq checks. MD5 and XXH3-128 catch accidental errors, not deliberate
collisions.

### MappingEntry

A frozen dataclass for one source-to-destination pair. Pass an iterable of
them to `cp(mapping=...)`, and use `dataclasses.replace` to change one.

| Attribute | Type | Meaning |
|---|---|---|
| `src` | `RelativePath` or `StreamSource` | Path relative to the source base, or a producer callback |
| `dst` | `RelativePath` or `StreamDestination` | Path relative to the destination directory, or a consumer callback |
| `kind` | `EntryKind` or `None` | Object kind, when known; default `None` |
| `size` | `int` or `None` | Informational size in bytes; default `None` |
| `mtime` | `int` or `None` | Informational filesystem modification time in Unix seconds; default `None` |
| `s3_last_modified` | `int` or `None` | Informational S3 object modification time in Unix seconds; default `None` |
| `expected_hash` | `Hash` or `None` | Expected whole-file hash; requires a regular file; default `None` |
| `metadata` | `DestinationMetadata` or `None` | Explicit destination attributes; default `None` |

`MappingEntry(src, dst, kind=None, size=None, mtime=None, expected_hash=None,
metadata=None, s3_last_modified=None)` also accepts text or byte paths and
converts them to `RelativePath`. For example, a DVC adapter can require the MD5
that DVC recorded:

```python
entry = syq.MappingEntry(
    "cache/object", "data.bin", kind="file",
    expected_hash=syq.Hash("md5", "900150983cd24fb0d6963f7d28e17f72"),
)
client.cp(mapping=[entry], cwd="source", into="download")
```

### DestinationMetadata

Give a destination attributes that differ from its source:

```python
entry = syq.MappingEntry(
    "source.bin", "payload.bin",
    metadata=syq.DestinationMetadata(mode=0o640, mtime=1700000000),
)
client.cp(mapping=[entry], cwd="source", into="output")
```

The optional keyword-only fields are `mode` (permission bits), numeric `uid`
and `gid`, `mtime` in Unix seconds, and `mtime_nsec` (zero when omitted).
Attributes you set apply without `copy_metadata`, and the others follow normal
copy behavior. The
[mapping format](https://greaber.github.io/syq/commands/map.html#mapping-format)
says how S3 handles them.

### RelativePath and PathValue

`RelativePath(value)` takes text, bytes, or `os.PathLike`, and refuses empty or
absolute paths, NUL bytes, and empty, `.`, or `..` components. Join paths with
`/`, as in `syq.RelativePath("archive") / entry.dst`. It is also
`os.PathLike`, returning bytes.

`PathValue(raw: bytes)` holds a path from an event, which can be absolute. Both
types are immutable and provide:

| Member | Type | Meaning |
|---|---|---|
| `raw` | `bytes` | Original filename bytes; also returned by `bytes(path)` |
| `text` | `str` | UTF-8 decoding; raises `UnicodeDecodeError` for invalid UTF-8 |
| `str(path)` | `str` | Filesystem decoding with `os.fsdecode` |
| `PathValue.display` | `str` | Same as `str(path)` |

<!-- ANCHOR_END: mappings -->

<!-- ANCHOR: results -->
<a id="retry-data-not-automatic-retry-policy"></a>

<a id="events-and-terminal-results"></a>

## Operation results

`cp` and `rm` return a frozen dataclass once syq has exited and its results
stream has been checked; a stream cut short raises even if syq exits
successfully. A dry run returns the same type with planned totals, and a failed
call counts the work done before it stopped.

### CpResult

Returned by `cp()`, and available as `SyqOperationError.result` after an
unsuccessful copy. Besides the common result fields below, it has:

| Attribute | Type | Meaning |
|---|---|---|
| `files_transferred` | `int` | Regular files transferred |
| `files_unchanged` | `int` | Regular files skipped as unchanged |
| `files_excluded` | `int` | Source entries excluded from copying, including ignore matches; an ignored directory counts once |
| `directories_created` | `int` | Directories created |
| `symlinks_created` | `int` | Symbolic links created |
| `specials_created` | `int` | Special filesystem objects created |
| `bytes_transferred` | `int` | File-content bytes transferred, not compressed network traffic |
| `bytes_total_known` | `bool \| None` | For byte streams, whether the source length is known; otherwise `None` |
| `bytes_unchanged` | `int` | Bytes not copied because the destination already had them: unchanged files and data reused inside transferred files |
| `deletions_planned` | `int` or `None` | Entries selected for pruning; `None` without `prune` or `prune_before` |
| `deletions_completed` | `int` or `None` | Entries pruned; `None` without pruning |
| `deletions_blocked` | `int` or `None` | Deletions blocked by a safety limit; `None` without pruning |
| `replaced_not_in_place` | `dict[str, int]` or `None` | With `in_place="update"`, existing files replaced instead of updated in place, by [reason](https://greaber.github.io/syq/automation.html#result) |

### RmResult

Returned by `rm()`, and available as `SyqOperationError.result` after an
unsuccessful removal. Besides the common result fields below, it has:

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

A selector is one path you asked to remove, and an entry is one object that
removal visits, so a directory selector can account for many entries.

### Common result fields

Both `CpResult` and `RmResult` include:

| Attribute | Type | Meaning |
|---|---|---|
| `status` | `OperationStatus` | Outcome from the table below |
| `exit_code` | `int` | syq process exit code |
| `dry_run` | `bool` | Whether this was a preview |
| `errors` | `int` | Counted errors |
| `timings` | `Timings` | Time spent in each phase, in milliseconds |
| `protocol` | `ProtocolMetadata` | Automation envelope; also present on every event |

### Timings

To see where a run spent its time, read `result.timings`, or `event.timings`
on progress events. Values are wall-clock milliseconds. They overlap, so do not
add them together. `None` means syq does not measure that phase for this
operation; zero means there was no such work, or it took under a millisecond.
See [measurement boundaries](https://greaber.github.io/syq/automation.html#result).

| Attribute | Type | Meaning |
|---|---|---|
| `total_ms` | `int` | The whole measured run, including installing syq on servers |
| `setup_ms` | `int \| None` | Preparing and connecting to the source and destination, excluding installation |
| `planning_ms` | `int \| None` | Finding source entries, checking destinations, and deciding what to copy |
| `transfer_ms` | `int \| None` | From the first file operation to the last |
| `finalization_ms` | `int \| None` | Work after file copying ends, such as pruning and directory metadata |
| `helper_install_ms` | `int \| None` | Installing syq on servers |

### ProtocolMetadata

Frozen dataclass at `result.protocol` and `event.protocol`. The SDK checks
these fields; you need them only to record or diagnose a results stream.

| Attribute | Type | Meaning |
|---|---|---|
| `schema` | `str` | `"syq.automation"` |
| `schema_version` | `int` | `4`; callback mappings use `5` |
| `seq` | `int` | Record sequence number, starting at zero |
| `type` | `str` | Record type; `"result"` for the final totals |

### OperationStatus

String enum: compare with `syq.OperationStatus.SUCCESS`, or use `.value` for
`"success"`.

| Member | Value | Exit code | Meaning |
|---|---|---|---|
| `SUCCESS` | `"success"` | `0` | Requested operation succeeded |
| `PARTIAL` | `"partial"` | `23` | Some entries failed; the rest of the work finished |
| `REFUSED` | `"refused"` | `25` | A safety limit such as `max_delete` refused the deletions; `cp` only |
| `ABORTED` | `"aborted"` | `1` | The copy stopped partway, for example when the destination filled up; `cp` only |
| `FAILED` | `"failed"` | `1` | Fatal failure |

### Event callbacks

`on_event` receives each event in the order syq reports it; events are not
kept in the result. With
`AsyncClient`, the callback can be async, and awaiting it counts toward the
timeout.

An event is one of the event types below, a final `CpResult` or `RmResult`, or
a `MappingStreamResult` from
[callback mappings](https://greaber.github.io/syq/python-streams.html#callback-mappings).
Each is a frozen dataclass with `protocol: ProtocolMetadata`. Fields match the
[automation results](https://greaber.github.io/syq/automation.html) records,
except that `class` is `class_` and paths are `PathValue`; optional fields are
`None` when absent.

`results=` saves the checked records as NDJSON to a binary file-like object,
whose `write(bytes)` must return a positive count for nonempty data, and leaves
it open. If checking the stream, the process, or a callback fails,
the final record is left out, so the saved stream shows an incomplete run. If
writing fails, the operation is aborted and the error raised.

To retry a failed mapping entry, call `retry_entry()` on an `OperationResult`
whose `is_retryable` is true. It returns a `MappingEntry` with the same
`expected_hash` and `metadata`, or `None` if the event does not identify the
whole entry. Use these entries only once the call has returned `success` or
`partial`; the client never retries by itself.

## Event types

Each event type lists its `protocol.type` and its fields besides `protocol`.

### RunEvent

Sent first. `started_at` is Unix seconds, `mode` is `"cp"` or `"rm"`, and
`prune` and `mapping` are `None` for removal.

`protocol.type = "run"`:

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

Periodic progress for displays; use the final result for totals. `activity`
holds [diagnostic measurements](https://greaber.github.io/syq/performance-measurements.html)
when syq collects them.

`protocol.type = "progress"`:

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

One change a dry run would make, and the `reason` for it. `dst` is relative
to the destination directory, and `src` is the mapping source when available.

`protocol.type = "trace"`:

```python
action: OperationAction
dst: PathValue
src: PathValue | None
kind: EntryKind
bytes: int | None
reason: TraceReason
```

### OperationResult

The outcome of one copy change. `src` is present for mapping entries when
available, and error fields when known. Outcomes reported by a restricted
receiver have no `src`, `attempts`, or `retryable`.

`protocol.type = "operation_result"`:

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

One removal selector, indexed from zero, and whether it resolved.

`protocol.type = "selection_result"`:

```python
selector: int
path: PathValue
status: SelectionStatus
kind: EntryKind | None
```

### RemovalTrace

One entry a dry run would remove, under the selector it came from.

`protocol.type = "removal_trace"`:

```python
selector: int
path: PathValue
kind: EntryKind
disposition: RemovalDisposition
s3_version_id: str | None
s3_delete_marker: bool | None
```

### RemovalResult

One removal outcome, or a dry run's failure to inspect an entry.

`protocol.type = "removal_result"`:

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

One error. It counts toward the result's `errors` unless it has
`diagnostic_for`: then it explains why a restricted receiver reported that
destination path as failed, and the receiver's own error counts the failure.

`protocol.type = "error"`:

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

All enums are string enums exported by `syq`. Members use uppercase names and
values lowercase, for example `EntryKind.FILE.value == "file"`.
`OperationStatus` is described with the results above.

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

Catch `SyqError` for every exception the SDK defines, or a subclass to tell an
unsuccessful operation from a broken results stream:

| Exception | Meaning / useful attributes |
|---|---|
| `SyqInstallError` | Bundled executable is missing, or a managed download or its verification failed |
| `SyqInvocationError` | Invalid Python arguments |
| `SyqOperationError` | Typed operation was unsuccessful; `.result` and `.stderr` (last 8 KiB) |
| `SyqProtocolError` | Results stream was invalid, unsupported, inconsistent, or incomplete; `.returncode`, `.stderr` |
| `SyqProcessError` | Raw `run` exited nonzero; `.result` contains complete output |
| `SyqOutputError` | A function such as `version()` got output it could not parse |

`check=False` makes `cp` and `rm` return an unsuccessful result instead of
raising, and `run` return a nonzero exit; it suppresses nothing else. Failures
to start syq, timeouts (`subprocess.TimeoutExpired`), and ordinary type and
value errors are standard Python exceptions, not `SyqError`. Exceptions from
your callbacks and mapping iterators propagate unchanged, and async
cancellation stays `asyncio.CancelledError`.

A timeout, cancellation, early exit from a mapping, or stream failure stops
syq and every process it started locally, including SSH. Completed changes are
not rolled back.
<!-- ANCHOR_END: results -->

<!-- ANCHOR: execution -->
<a id="deliberate-exclusions"></a>

<a id="raw-execution"></a>

## run

`client.run(args, *, check=True, cwd=None, env=None, timeout=CLIENT_DEFAULT, input=None)`
runs syq with any arguments and returns a
[Result](https://greaber.github.io/syq/python-operations.html#result) with the
captured output. Use it for commands without a typed method. `args` are the
arguments after the executable name, passed without a shell; `input` is
optional bytes for standard input.

Here `cwd` is the working directory of the syq process. `cwd` and `env` fall
back to the client's settings when omitted or `None`; `timeout` falls back only
when omitted, and `None` disables it. Module-level `syq.run` also takes
`executable=None`, and has no timeout by default.

To pass the client's timeout through your own wrapper, give its parameter the
default `syq.CLIENT_DEFAULT`. `syq.Timeout` is the type of a timeout: a number,
`None`, or that sentinel:

```python
def copy_data(client: syq.Client, *, timeout: syq.Timeout = syq.CLIENT_DEFAULT):
    return client.cp("data", into="backup", timeout=timeout)
```

A timeout covers only the syq process, not downloading a managed executable or
reading a mapping iterable before syq starts.

For `syq exec`, `cwd=` sets only the local directory; put `--cwd DIR` in `args`
for the receiving machine, as in the
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

The package supports Python 3.13.4 and later on Linux and macOS, with no
runtime Python dependencies. Each package version runs one syq release;
`syq.__version__` and `syq.PINNED_SYQ_VERSION` report them. Pin the package
version in your dependencies to keep the same syq.

### Bundled executable

By default the SDK runs the syq installed with its wheel, without searching
`PATH` or downloading anything.

### Managed executable

`Client(cache_dir=DIR)` instead downloads the matching syq on first use into
`DIR/syq/sdk/python/v<version>/<target>/`, where `<target>` names the platform,
such as `linux-x86_64`. It verifies the download against the release manifest
in the package and checks it again before every use.
`syq.managed_executable(cache_dir=None)` downloads ahead of time and returns the
executable's path. Without `cache_dir`, `DIR` is `$XDG_CACHE_HOME` when that is
an absolute path, and `~/.cache` otherwise.

### Custom executable

`Client(executable="/opt/bin/syq")` runs that file, and
`Client(executable="syq")` searches `PATH`. The SDK then skips its bundled and
downloaded copies and their verification, so the executable's compatibility
and origin are up to you. If it cannot run, the call fails without falling back
to another syq.
<!-- ANCHOR_END: execution -->
