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

## The native vocabulary is the Python vocabulary

The typed API mirrors the native command grammar. It must not require users to
learn a second set of names for concepts that syq already names.

| Native spelling | Python spelling |
|---|---|
| `syq cp` | `syq.cp()` or `Client.cp()` |
| `syq cp-prune` | `syq.cp_prune()` or `Client.cp_prune()` |
| `syq rm` | `syq.rm()` or `Client.rm()` |
| `syq map` | `syq.map()` or `Client.map()` |
| `--src-src` | `src_src=` |
| `--into-existing` | `into_existing=` |
| `--no-compress` | `no_compress=` |
| `--max-delete` | `max_delete=` |
| `--from` | `from_=` |
| `--as` | `as_=` |

The only spelling transformations are mechanical:

1. Replace hyphens with underscores because Python identifiers cannot contain
   hyphens.
2. Add a trailing underscore when the result is a Python keyword.

This rule excludes semantic aliases such as `copy`, `remove`, `mapping`,
`Sources`, `Remote`, `Into`, `Exact`, `comparison`, `compression`, and
`bandwidth_limit`. Those names may read naturally in isolation, but they make
every caller translate between two APIs.

SDK-only controls have Python names because they have no native spelling. The
initial ones are `on_event`, `timeout`, and `check`; their documentation must
identify them as process- or library-level behavior rather than syq options.

Not every command-line parsing convenience needs another Python parameter.
The plural options `--srcs`, `--src-srcs`, `--src-files`, and `--src-dirs`
only batch values on a command line. Python passes a sequence to the matching
singular keyword instead. This removes redundant syntax without renaming a
product concept:

```python
syq.cp(src=["a", "b"], src_dir=["assets", "fonts"], into="archive")
```

The implementation serializes this as repeated `--src` and `--src-dir`
options. A keyword accepts either one path or an iterable of paths; `str`,
`bytes`, and path-like objects are always treated as scalar paths rather than
iterables.

## Scope

The typed interface covers the native filesystem operations `cp`, `cp_prune`,
`rm`, and `map`. It does not wrap `syq rsync`. The rsync-shaped surface remains
available through `Client.run` and the module-level `syq.run` function.
Enrollment and other administrative commands also remain raw operations until
they have a stable machine contract that benefits from Python types.

Module functions and client methods have the same operation names and
signatures. A module function uses a default `Client`; applications that need
shared configuration or an explicit executable construct a client.

## A normal copy

```python
import syq

result = syq.cp(
    "project",
    to="server",
    into="/backup",
)

print(result.files_transferred, result.bytes_transferred)
```

The corresponding native command is:

```text
syq cp project --to server --into /backup
```

There are no endpoint or placement wrapper objects. Endpoint strings use the
native `[USER@]HOST` grammar, paths remain separate arguments, and omission of
`from_` or `to` means local exactly as it does on the command line:

```python
syq.cp(
    src=["a", "b"],
    from_="grant@server",
    cwd="/data",
    into="./data",
)

syq.cp(
    "report",
    to="grant@[2001:db8::1]",
    as_new="/reports/final",
    hash=True,
)
```

`cp` returns only after it has received and validated the terminal result and
reaped the process. By default, a non-successful terminal result raises
`SyqOperationError`; the exception retains the same typed result. Pass
`check=False` when a partial or refused outcome is expected program logic.

## Client and executable selection

```python
client = syq.Client(
    cache_dir="/var/cache/my-application",
    process_cwd="/srv/jobs",
    timeout=3600,
)

result = client.cp("project", to="server", into="/backup")
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

`process_cwd` is the local subprocess working directory. It is deliberately
not called `cwd`: on typed commands, `cwd` always means native `--cwd`.
The existing raw `run(cwd=...)` spelling retains its subprocess meaning for
backward compatibility.

## Arguments and validation

The conceptual `cp` signature is:

```python
syq.cp(
    *sources,
    src=None,
    src_src=None,
    src_file=None,
    src_dir=None,
    from_=None,
    cwd=None,
    to=None,
    into=None,
    into_new=None,
    into_existing=None,
    as_=None,
    as_new=None,
    as_existing=None,
    mapping=None,
    dry_run=False,
    hash=False,
    no_compress=False,
    bwlimit=None,
    connections=None,
    on_event=None,
    timeout=None,
    check=True,
)
```

Bare positional paths have the native bare-source meaning. Selector keywords
retain the native meanings:

| Python keyword | Native option | Meaning |
|---|---|---|
| `src` | `--src` | Select a named object |
| `src_src` | `--src-src` | Select a directory's contents |
| `src_file` | `--src-file` | Require a non-directory object |
| `src_dir` | `--src-dir` | Require a directory |

Placement is expressed by exactly one of the six native placement keywords:
`into`, `into_new`, `into_existing`, `as_`, `as_new`, or `as_existing`.
Their behavior, including the `new` and `existing` pathname checks, is the
native behavior. The Python package does not strengthen them into locks or
compare-and-swap operations.

Python performs structural validation that requires no filesystem or network
access, such as conflicting placement parameters, `as_` with multiple
sources, selectors combined with `mapping`, and `cwd` combined with `root`.
The executable remains authoritative for path resolution, type checks,
endpoint behavior, and filesystem state. Errors should use native option names
so they remain searchable in `syq --help` and the README.

Copy selectors may be absolute, with the same behavior as native `cp`. `rm`
rejects absolute selectors and explicit `.` or `..` components. Input paths
accept text and byte path-like objects on supported Unix systems; byte paths
are not decoded merely to build argv.

`hash`, `no_compress`, `bwlimit`, `connections`, and `dry_run` retain the exact
native meanings. In particular, `bwlimit` accepts the native rate spelling;
the Python API does not replace it with a differently defined unit type.

Human presentation options such as `verbose`, `quiet`, `stats`, `progress`,
`no_progress`, and `progress_json` are initially omitted from typed methods.
Typed methods consume structured results and applications render their own
presentation. Callers that specifically want native human output use `run`.
If a presentation option is later useful on a typed method, it must appear
under its native name rather than under a Python synonym.

`results` is also not a typed `cp` parameter: it is the transport the library
uses internally to obtain `CpResult`. Callers that need direct control of
`--results FILE` use `run`. The parameter is reserved rather than repurposed.

## Mapping, transformation, and copy

A mapping entry is a frozen dataclass. It represents the native NDJSON record,
not a replacement command vocabulary:

```python
@dataclass(frozen=True, slots=True)
class MappingEntry:
    src: RelativePath
    dst: RelativePath
    kind: EntryKind | None = None
    size: int | None = None
    mtime: int | None = None
```

`size` and `mtime` are informational when emitted by `syq map`; `syq cp` does
not turn them into preconditions. `kind` retains the manifest's current
disambiguation semantics.

`RelativePath` stores raw path bytes, validates mapping-relative syntax, and
provides explicit text access plus byte-preserving joins. A valid UTF-8 path is
convenient to construct from `str`; a non-UTF-8 path is constructed from
`bytes`. Callers do not encode or inspect the NDJSON `{encoding, value}` form.

`map` returns a context-managed `MapStream`:

```python
from dataclasses import replace

import syq

prefix = syq.RelativePath("by-year")

with syq.map(src_src="photos") as mapping:
    entries = (
        replace(entry, dst=prefix / entry.dst)
        for entry in mapping
        if entry.kind is syq.EntryKind.FILE
    )
    result = syq.cp(
        mapping=entries,
        cwd=mapping.cwd,
        to="storage",
        into="/archive",
    )
```

This corresponds to `syq map --src-src photos` followed by a transformed
manifest and `syq cp --mapping ... -C photos --to storage --into /archive`.
`MapStream.cwd` is the effective source base needed to execute its emitted
`src` paths. Keeping that property named `cwd` makes it directly usable as the
native `cwd=` parameter.

`MapStream` yields entries as `syq map` emits them. Reaching normal EOF
verifies the producer's process status. Leaving the context early kills and
reaps the owned process. A parse error, nonzero producer status, timeout, or
interruption raises instead of presenting the yielded prefix as a complete
mapping.

The method retains `syq map`'s native limits for the pinned binary. Initially,
mapping emission is local and read-only, and the accepted selector and
placement combinations are the ones documented for the executable. The
client may reject a known-invalid combination before launch, but it does not
invent a broader mapping operation.

### Complete-input guarantee

When `mapping` is a Python iterable, `cp` consumes and serializes the entire
iterable into a secure temporary manifest before launching the mutating syq
command. If iteration, transformation, serialization, or the `syq map`
producer fails, no copy process has started and the destination is untouched.

This is load-bearing. A pipe cannot distinguish a producer that cleanly
finished from one that failed after writing a valid prefix. Launching the copy
first could therefore apply an incomplete mapping. Materializing the complete
mapping matches syq's whole-manifest conflict preflight and scales on disk
rather than retaining another complete Python object graph.

After successful materialization, syq performs its own authoritative manifest
validation and conflict checks. The temporary file remains available until the
child exits and is then removed. Passing a manifest path to `mapping` skips
Python materialization and passes that file to syq.

Callers that intentionally want raw stdin behavior can use:

```python
client.run(["cp", "--mapping", "-", "--into", "dst"], input=manifest)
```

That low-level call does not acquire typed `cp`'s complete-generator guarantee.
The typed API does not initially expose a `stream=True` switch.

## Copy and prune

```python
result = syq.cp_prune(
    src_src="build",
    to="server",
    into_existing="/srv/app",
    max_delete=100,
)
```

`cp_prune` accepts the same valid native selector, placement, copy, and
process-level parameters as `cp`, plus `max_delete`. It does not accept
`mapping`, because native mappings do not define deletion scopes. The library
does not infer a deletion scope or retry a refused prune.

## Removal

```python
result = syq.rm(
    src_dir="old-output",
    from_="server",
    root="/srv",
)
```

The conceptual signature follows `syq rm`:

```python
syq.rm(
    *sources,
    src=None,
    src_src=None,
    src_file=None,
    src_dir=None,
    from_=None,
    cwd=None,
    root=None,
    follow=False,
    dry_run=False,
    connections=None,
    on_event=None,
    timeout=None,
    check=True,
)
```

`root` conflicts with `cwd`, matching native `--root` and `--cwd`. `follow`
controls selector-resolution symlinks exactly as native `--follow` does; it
does not cause the directory walk to follow descendant symlinks.

The method never supplies confirmation automatically and never retries a
removal automatically. An application that needs approval first calls the
same operation with `dry_run=True` and must still treat that result as a view
of filesystem state, not a transaction or lock.

## Dry runs

`--dry-run` remains `dry_run=True` on the same operation:

```python
preview = syq.cp(src_src="build", into="staging", dry_run=True)
preview = syq.cp_prune(
    src_src="build",
    into_existing="staging",
    max_delete=100,
    dry_run=True,
)
preview = syq.rm("cache", dry_run=True)
```

There are no `preview_copy`, `preview_copy_prune`, or `preview_remove`
commands. Those would rename the native operation and make one flag change the
Python verb. The command-specific result carries `dry_run=True`; its operation
events describe planned work instead of completed work.

A dry run describes what syq observed and would have done. It is not an
executable transaction, authorization token, or promise that the filesystem
will remain unchanged before a later operation. Typed dry-run results cannot
ship until automation v1 defines the corresponding execution trace and
terminal result.

## Events and terminal results

Typed operations consume the stable automation stream. `on_event` receives
frozen dataclasses corresponding to the schema's records, including run-start
information, operation results, warnings, structured errors, progress samples,
dry-run trace items, and the terminal result.

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
one. Terminal aggregates are retained in the returned command-specific result,
such as `CpResult`, `CpPruneResult`, or `RmResult`.

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

The naming rule is part of compatibility. A new native command `foo-bar`
reserves `foo_bar`; a new semantic `--some-option` reserves `some_option`.
SDK-only concepts must not occupy names that are the mechanical Python form of
current or planned native grammar. A parsing-only alias may be omitted, as with
the plural selector options, but must not be exposed under a different name.

## Deliberate exclusions

The initial typed API does not provide:

- a Python implementation of the transfer engine;
- FFI or an in-process Rust runtime;
- a typed mirror of `syq rsync`;
- semantic aliases for native commands or options;
- a generic `extra_args` hole in typed methods—use `run` instead;
- automatic retries or rollback;
- an unbounded in-memory operation ledger;
- implicit confirmation for destructive operations;
- implicit selection of a newer syq from `PATH`; or
- API promises for human stdout, stderr, or progress formatting.

## Product dependencies and implementation order

| Proposed layer | Product dependency | Current readiness |
|---|---|---|
| Managed executable and raw `run` | Released binary manifest | Already shipped |
| Raw stdin and safe streaming | Process behavior only | Can be implemented now |
| `RelativePath` and mapping codecs | Mapping format compatibility decision | Exact pinned version is usable now |
| `map` and safe `cp(mapping=...)` input | `syq map` and `cp --mapping` | Native support shipped; Python design pending |
| Typed `cp` results | Stable automation result stream | Blocked on automation v1; schema 0 is preview |
| Typed `cp_prune` and `rm` | Stable command-specific events/results | Not yet present in native output |
| Typed `dry_run=True` | Stable execution-trace records | Not yet present in native output |

The implementation should proceed in that order. A preview namespace may
experiment with schema-0 result decoding, but it must not silently become the
stable types specified here.

## Review questions

The command and option naming rule is a decision in this draft, not an open
question. The remaining choices to review before implementation are:

1. Is a small `RelativePath` value worth the API surface, or should mapping
   entries expose `str | bytes` directly?
2. Should `MappingEntry` wait for a separately versioned mapping schema, or is
   the exact executable pin a sufficient compatibility boundary?
3. Should repeated selector keywords accept a scalar or iterable, as proposed,
   or require sequences consistently?
4. Are matching module functions and `Client` methods worth the duplicated
   public surface?
5. Is pre-materializing every Python mapping the correct safe default despite
   its temporary-disk cost?
6. Should the first typed release include every mutating native command, or
   ship `map` and `cp` as soon as their contracts are stable?
7. Should any native presentation flags be exposed on typed methods, and if
   so, how should their output be delivered without competing with structured
   events?
