# Proposed Python native API

Status: design specification for review. The API in this document is not
implemented. The current public package remains the process adapter documented
in [README.md](README.md).

This document describes the first useful Python interface to syq's native
filesystem commands. Examples are intended to be executable once the proposal
is implemented; during design review they are specifications, not current
usage examples.

## Positioning

Direct subprocess execution remains a good syq API:

```python
import subprocess

subprocess.run(
    ["syq", "cp", "project", "--to", "server", "--into", "/backup"],
    check=True,
)
```

A caller that only needs to start one command and fail when it fails does not
need a Python abstraction. The Python package is for callers that need one or
more of these additional guarantees:

- a verified syq executable pinned to the Python package;
- lossless structured mapping input and output;
- typed, streaming operation events and terminal results;
- detection of malformed, unsupported, or incomplete machine output;
- safe process cancellation and cleanup; or
- composition of map, transform, copy, and retry workflows in Python.

The library invokes the syq executable. It does not reimplement copying, path
resolution, conflict detection, remote access, or retry policy in Python.

## Scope

The typed interface covers the native filesystem operations:

- `syq cp` as `Client.copy`;
- `syq cp-prune` as `Client.copy_prune`;
- `syq rm` as `Client.remove`;
- `syq map` as `Client.mapping`; and
- their read-only previews once the stable automation stream represents them.

It does not wrap `syq rsync`. The rsync-shaped surface remains available
through `Client.run` and the module-level `syq.run` function. Enrollment and
other administrative commands also remain raw operations until they have a
stable machine contract that benefits from Python types.

## A normal copy

```python
import syq

client = syq.Client()
server = syq.Remote("server")

result = client.copy(
    syq.Sources("project"),
    syq.Into("/backup", endpoint=server),
)

print(result.files_transferred, result.bytes_transferred)
```

`Sources("project")` is shorthand for a named selector. The corresponding
native command is:

```text
syq cp --src project --to server --into /backup --output=ndjson
```

The exact machine-output spelling is owned by the automation-interface
contract. It is shown here only to make the subprocess boundary explicit.

`Client.copy` returns only after it has received and validated the terminal
result and reaped the process. By default, a non-successful terminal result
raises `SyqOperationError`; the exception retains the same typed result. Pass
`check=False` when partial or refused outcomes are expected program logic.

## Client and executable selection

```python
client = syq.Client(
    cache_dir="/var/cache/my-application",
    cwd="/srv/jobs",
    timeout=3600,
)
```

`Client()` lazily installs and uses the exact official syq release pinned by
the Python package. Each operation verifies the cached executable according to
the package's existing complete-byte manifest policy before it starts. A
`Client` may reuse configuration and safe validation metadata, but it does not
turn path reuse into a weaker executable check.

An explicit executable opts out of the supported binary pairing:

```python
client = syq.Client(executable="/opt/syq/bin/syq")
```

Typed operations still validate the automation schema they receive, but the
package makes no behavioral compatibility or provenance guarantee for an
override. It never silently falls back from an override to the managed binary
or from the managed binary to `PATH`.

Client defaults may be overridden for one operation. A client is safe to use
for independent sequential calls. Concurrent-call and thread-safety promises
must be decided from the implementation rather than implied by this document.

## Endpoints

Endpoints and paths are distinct values, matching the native interface:

```python
local = syq.LOCAL
server = syq.Remote("server")
server_as_grant = syq.Remote("server", user="grant")
server_v6 = syq.Remote("2001:db8::1", user="grant")
```

`Remote` contains only the non-secret SSH login identity accepted by native
`--from` and `--to`. Paths are supplied separately through `Sources`, `Into`,
`Exact`, or `SourceRoot`. An endpoint never contains a path, password, private
key, remote-shell command, or other credential material.

`LOCAL` is the default source and destination endpoint. The implementation
serializes users and IPv6 brackets; callers do not construct `[USER@]HOST`
strings themselves.

## Sources and selectors

One `Sources` value contains selectors that share an endpoint and source
working directory:

```python
sources = syq.Sources(
    syq.Named("README.md"),
    syq.Directory("assets"),
    syq.NonDirectory("release.json"),
    endpoint=syq.Remote("build-server"),
    cwd="/srv/build",
)
```

The selector types preserve the native meanings:

| Python | Native spelling | Meaning |
|---|---|---|
| `Named(path)` or a bare path | `--src PATH` | Select the named object |
| `Contents(path)` | `--src-src DIR` | Select a directory's contents |
| `NonDirectory(path)` | `--src-file PATH` | Require a non-directory object |
| `Directory(path)` | `--src-dir DIR` | Require a directory |

`Sources("a", "b")` is therefore shorthand for
`Sources(Named("a"), Named("b"))`. There are no Python equivalents of the
CLI's bulk option spellings: bulk spellings solve command-line parsing, while
Python already has sequences.

The executable remains authoritative for filesystem type checks and path
resolution. Python performs only structural validation that can be answered
without filesystem or network access.

Copy selectors may be absolute, with the same behavior as native `cp`.
`Client.remove` rejects absolute selectors and explicit `.` or `..` components
before launch because native `rm` cannot accept them.

Input paths accept text and byte path-like objects on supported Unix systems.
Byte paths are not decoded merely to build argv.

## Destinations and placement

```python
destination = syq.Into(
    "/srv/archive",
    endpoint=syq.Remote("storage"),
    existence=syq.Existence.EXISTING,
)

exact = syq.Exact(
    "/srv/releases/current.tar",
    endpoint=syq.Remote("storage"),
    existence=syq.Existence.NEW,
)
```

`Into` places selected names in a directory and corresponds to `--into`,
`--into-new`, or `--into-existing`. `Exact` maps one named source to one path
and corresponds to `--as`, `--as-new`, or `--as-existing`.

`Existence.ANY` is the default. `NEW` and `EXISTING` have exactly the native
placement-root precondition semantics; the Python API does not strengthen
them into locks or compare-and-swap operations.

Invalid structural combinations, such as multiple sources with `Exact`, are
rejected before launch. Conditions that require endpoint inspection are left
to syq and appear in its structured result.

## Copy controls

The initial typed copy signature is conceptually:

```python
client.copy(
    sources,
    destination,
    *,
    comparison=syq.Comparison.QUICK,
    compression=True,
    bandwidth_limit=None,
    connections=None,
    on_event=None,
    timeout=None,
    check=True,
)
```

- `Comparison.QUICK` uses the native size-and-mtime decision.
- `Comparison.HASH` requests native BLAKE3 content comparison.
- `compression=False` selects native `--no-compress`.
- `bandwidth_limit` is an integer number of bytes per second. The executable's
  documented minimum and nearest-KiB rounding still apply.
- `connections` fixes the worker count; `None` preserves native autotuning.
- `on_event` receives structured events as they arrive.
- `timeout` is a client-side wall-clock deadline for the whole subprocess.

Human presentation flags are deliberately absent. Typed operations select
machine output and do not expose `quiet`, `verbose`, `stats`, terminal progress,
or `--progress-json` as competing result mechanisms. Applications render the
structured events and result themselves. `Client.run` remains available when
the caller specifically wants native human output.

Future native copy policies become semantic Python parameters or types after
they merge into the product. Rsync-only transport and compatibility switches
do not become typed options merely because the engine contains them.

## Mapping, transformation, and copy

A mapping entry is a frozen dataclass:

```python
@dataclass(frozen=True, slots=True)
class MappingEntry:
    src: RelativePath
    dst: RelativePath
    kind: EntryKind | None = None
    size: int | None = None
    mtime: int | None = None
```

`size` and `mtime` are informational when emitted by `syq map`; copying does
not turn them into preconditions. `kind` retains the manifest's current
disambiguation semantics.

`RelativePath` stores raw path bytes, validates mapping-relative syntax, and
provides explicit text access plus byte-preserving joins. A valid UTF-8 path is
convenient to construct from `str`; a non-UTF-8 path is constructed from
`bytes`. Callers do not encode or inspect the NDJSON `{encoding, value}` form.

`SourceRoot(path, endpoint=LOCAL)` identifies the endpoint and base directory
against which a mapping entry's `src` is resolved. It contains no selectors.
Caller-authored mappings supply it explicitly; a `MappingStream` derives it
from the source selection used to run `syq map`.

```python
from dataclasses import replace

import syq

client = syq.Client()
prefix = syq.RelativePath("by-year")

with client.mapping(syq.Sources(syq.Contents("photos"))) as mapping:
    entries = (
        replace(entry, dst=prefix / entry.dst)
        for entry in mapping
        if entry.kind is syq.EntryKind.FILE
    )
    result = client.copy_mapping(
        entries,
        source=mapping.source_root,
        destination=syq.Into(
            "/archive",
            endpoint=syq.Remote("storage"),
        ),
    )
```

`Client.mapping` returns a context-managed `MappingStream`. It yields entries
as `syq map` emits them. Reaching normal EOF verifies the producer's process
status. Leaving the context early kills and reaps the owned process. A parse
error, nonzero producer status, timeout, or interruption raises instead of
presenting the yielded prefix as a complete mapping.

The initial operation retains `syq map`'s native limits: mapping emission is
local and read-only, and the accepted selector combinations are the ones the
executable supports. The client rejects unsupported endpoint and selector
shapes without inventing a different mapping operation.

`MappingStream.source_root` is the source base against which emitted `src`
paths are relative. Supplying it to `copy_mapping` avoids manually duplicating
`-C` logic.

### Complete-input guarantee

`copy_mapping` consumes and serializes the entire Python iterable into a secure
temporary manifest before it launches a mutating syq command. If iteration,
transformation, serialization, or the `syq map` producer fails, no copy process
has started and the destination is untouched.

This is load-bearing. A pipe cannot distinguish a producer that cleanly
finished from one that failed after writing a valid prefix. Launching the copy
first could therefore apply an incomplete mapping. Materializing the complete
mapping matches native syq's current whole-manifest conflict preflight and
scales on disk rather than retaining another complete Python object graph.

After successful materialization, syq performs its own authoritative manifest
validation and conflict checks. The temporary file remains available until the
child exits and is then removed.

Callers that intentionally want raw stdin behavior can use:

```python
client.run(["cp", "--mapping", "-", "--into", "dst"], input=manifest)
```

That low-level call does not acquire `copy_mapping`'s complete-generator
guarantee. The typed API does not initially expose a `stream=True` switch.

## Copy and prune

```python
result = client.copy_prune(
    syq.Sources(syq.Contents("build")),
    syq.Into(
        "/srv/app",
        endpoint=syq.Remote("server"),
        existence=syq.Existence.EXISTING,
    ),
    max_delete=100,
)
```

`copy_prune` uses the same source, destination, comparison, transport, event,
timeout, and checking parameters as `copy`, plus `max_delete`. It does not
accept mapping entries because native mappings do not define deletion scopes.
The library does not infer a deletion scope or retry a refused prune.

## Removal

```python
result = client.remove(
    syq.Sources(
        syq.Directory("old-output"),
        endpoint=syq.Remote("server"),
    ),
    root="/srv",
)
```

`remove` exposes the native endpoint-resolved removal model:

```python
client.remove(
    sources,
    *,
    root=None,
    follow=False,
    connections=None,
    on_event=None,
    timeout=None,
    check=True,
)
```

`root` conflicts with `Sources.cwd`, matching native `--root` and `--cwd`.
`follow` controls selector-resolution symlinks exactly as native `--follow`
does; it does not cause the directory walk to follow descendant symlinks.

The method never supplies confirmation automatically and never retries a
removal automatically. Applications that need approval first use the preview
operation described below and must still treat it as a view of filesystem
state, not a transaction or lock.

## Read-only previews

Dry-run is represented as separate methods rather than a boolean that changes
the return type:

```python
preview = client.preview_copy(sources, destination)
preview = client.preview_copy_prune(sources, destination, max_delete=100)
preview = client.preview_remove(sources, root="/srv")
```

Preview methods accept the corresponding operation controls and return a
typed `PreviewResult`. Trace items are delivered through `on_event` rather
than accumulated without bound.

A preview describes what syq observed and would have done. It is not an
executable transaction, authorization token, or promise that the filesystem
will remain unchanged before a later operation.

These methods cannot ship until automation v1 defines the read-only execution
trace and terminal result for the corresponding native command.

## Events and terminal results

Typed operations consume the stable automation stream. `on_event` receives
frozen dataclasses corresponding to the schema's records, including:

- run-start information;
- operation results;
- warnings and structured errors;
- progress samples;
- preview trace items; and
- the terminal result.

The schema, not this document, owns their exact fields and enum members. The
Python types expose every stable schema field without parsing display text.

The client validates at least these stream invariants:

- the schema identifier and supported major version;
- the required first record;
- one run identity and strictly increasing sequence numbers;
- path tags and integer ranges;
- required fields and documented enum values;
- exactly one terminal result, with nothing after it; and
- agreement between the terminal exit code and the reaped process status.

EOF without a terminal result is never success, even if every observed
operation succeeded or the process status is zero.

Successful operation events are not retained by default. A copy may contain
millions of entries; callers that need a ledger consume `on_event` and write
one. Terminal aggregates are retained in the returned result.

## Failure model

The exception families have distinct meanings:

| Exception | Meaning |
|---|---|
| `SyqInstallError` | The managed executable could not be installed or verified |
| `SyqInvocationError` | Python inputs cannot form a valid native operation |
| `SyqProcessError` | Raw `run` completed with a nonzero status, preserving its current meaning |
| `SyqOutputError` | A raw helper such as `version()` could not interpret its expected output |
| `SyqProtocolError` | Machine output was malformed, unsupported, inconsistent, or incomplete |
| `SyqOperationError` | A valid terminal result reports a non-successful operation |

`SyqOperationError.result` contains the typed terminal result.
`SyqProtocolError` retains the raw process status and bounded diagnostic
context needed to investigate without storing an unbounded stream in the
exception. Process spawn failures and timeouts retain the existing standard
Python exception behavior of the raw adapter.

`check=False` affects only `SyqOperationError`. It cannot turn install,
invocation, process, or protocol failures into successful return values.

If an event callback raises, the client stops scheduling through process
termination, kills and reaps the owned process group, and re-raises the
callback exception. Filesystem operations already committed by syq are not
rolled back.

## Retry data, not automatic retry policy

A failed `OperationResult` exposes its structured retryability and can produce
a `MappingEntry` only when it contains a complete mapping identity:

```python
retryable = []

def collect_retryable(event: syq.AutomationEvent) -> None:
    if isinstance(event, syq.OperationResult) and event.is_retryable:
        entry = event.retry_entry()
        if entry is not None:
            retryable.append(entry)
```

The package may provide a disk-backed `RetryManifest` convenience, but it does
not automatically rerun operations. Retry timing, attempt limits, and whether
the source/destination state is still appropriate belong to the application.

An incomplete stream cannot produce a complete retry manifest: unobserved
operations may exist. Retry helpers therefore become usable only after a
terminal result whose status says every queued operation settled.

## Raw execution

The existing escape hatch remains small and transparent:

```python
result = client.run(
    ["enrollments"],
    check=True,
    timeout=30,
)
```

`Client.run` and `syq.run` accept only arguments after the executable name and
never construct a shell command. The proposed process-layer additions are:

- `input=` for bounded bytes;
- text and byte path-like argv entries on Unix; and
- a context-managed streaming primitive for callers that deliberately need
  raw stdout/stderr.

Raw execution returns raw bytes and a process status. It does not parse human
output, infer native objects from argv, or claim the structured completion
guarantees of typed methods.

## Synchrony and resource ownership

The first API is synchronous. `on_event` provides live observation without
requiring every caller to manage threads and pipes. Applications can place a
synchronous call in a worker thread when integrating with `asyncio`; a native
async API should wait for demonstrated demand.

Every object that owns a subprocess is a context manager. Normal method calls
reap before returning. Early context exit, timeout, interruption, callback
failure, or decoder failure terminates and verifies the whole process group so
SSH transports and other descendants cannot survive as stale work.

## Compatibility and versioning

Every published Python package pins one exact syq release. That is the tested
default pairing. Several Python releases may pin the same syq release, but one
published Python version never changes its pin.

The automation schema has its own version. The Python package supports stated
schema major versions rather than guessing compatibility from the executable's
marketing version. Additive fields and enum values follow the automation
schema's compatibility policy.

Mapping entries also need an explicit compatibility decision before this API
is stable: either the manifest gains its own schema version, or public
`MappingEntry` support is documented as exact-binary-pair only.

Python API changes follow Python package semantic versioning. Adding support
for a new syq release does not by itself justify a breaking Python API change.

## Deliberate exclusions

The initial typed API does not provide:

- a Python implementation of the transfer engine;
- FFI or an in-process Rust runtime;
- a typed mirror of `syq rsync`;
- a generic `extra_args` hole in typed methods—use `run` instead;
- automatic retries or rollback;
- an unbounded in-memory operation ledger;
- implicit confirmation for destructive operations;
- implicit selection of a newer `syq` from `PATH`; or
- API promises for human stdout, stderr, or progress formatting.

## Product dependencies and implementation order

| Proposed layer | Product dependency | Current readiness |
|---|---|---|
| Managed executable and raw `run` | Released binary manifest | Already shipped |
| Raw stdin and safe streaming | Process behavior only | Can be implemented now |
| `RelativePath` and mapping codecs | Mapping format compatibility decision | Exact pinned version is usable now |
| `mapping` and safe `copy_mapping` input | `syq map` and `cp --mapping` | Native support shipped; Python design pending |
| Typed `copy` results | Stable automation result stream | Blocked on automation v1; schema 0 is preview |
| Typed `copy_prune` and `remove` | Stable command-specific events/results | Not yet present in native output |
| Preview methods | Stable execution-trace records | Not yet present in native output |

The implementation should proceed in that order. A preview namespace may
experiment with schema-0 result decoding, but it must not silently become the
stable types specified here.

## Review questions

The draft makes these choices deliberately and they should be reviewed before
implementation:

1. Is a small `RelativePath` value worth the API surface, or should mapping
   entries expose `str | bytes` directly?
2. Should `MappingEntry` wait for a separately versioned mapping schema, or is
   the exact executable pin a sufficient compatibility boundary?
3. Are semantic method names (`copy`, `copy_prune`, `remove`, `mapping`) better
   than exact CLI names (`cp`, `cp_prune`, `rm`, `map`)?
4. Should the first typed release include all three mutating native commands,
   or ship `mapping` and `copy` as soon as their contracts are stable?
5. Is pre-materializing every Python mapping the correct safe default despite
   its temporary-disk cost?
6. Should `bandwidth_limit` be integer bytes per second, a dedicated rate
   value, or the CLI's rate string?
