# syq for Python

The official Python client for [syq](https://github.com/greaber/syq), a fast
file transfer tool. Call `syq.cp(...)` (including `cp --prune`), `syq.rm(...)`,
and `syq.map(...)` and get typed results back; every other syq command remains
one `syq.run([...])` away.

```sh
python -m pip install syq
```

Installing the package does not install syq itself. The first default call that
needs syq downloads the matching syq release if it is not
already cached, checks it against the signed release manifest, and uses that
managed binary for subsequent default calls.
The Python package and its managed syq executable share one version: package `0.1.8`
manages syq `0.1.8`.
syq always runs as a subprocess with an argument list, never through a shell.

```python
import syq

print(syq.__version__)           # Python package version
print(syq.PINNED_SYQ_VERSION)    # tested executable version
print(syq.managed_executable())  # downloads once, then returns the cached path

plan = syq.cp("project", to="server", into="/backup", dry_run=True)
print(plan.files_transferred, plan.bytes_transferred)
```

The typed API validates syq's complete automation-v1 stream and its agreement
with the process status. Dry and live calls return the same `CpResult` type;
dry runs report planned mutation totals and emit `TraceEvent` records:

```python
client = syq.Client(process_cwd="/srv/jobs")

preview = client.cp(
    src_src="build",
    to="server",
    into_existing="/srv/app",
    prune=True,
    max_delete=100,
    dry_run=True,
)

removal = client.rm(
    src_dir="old-output",
    from_="server",
    root="/srv",
)
print(removal.entries_removed, removal.selectors_missing)
```

Typed `rm` works for local and ordinary SSH endpoints. A command-restricted
receiver rejects native removal because its signed grants currently authorize
copy mutations only.

Remote-copy controls use the same names with underscores, including `coordinate_at`,
`rsh`, `pscope`, `syq_path`, `no_bootstrap`, `tcp_plain`, `no_tcp`, `tcp_ports`,
`tcp_congestion`, and the native agent-forwarding policy flags. `detach` stays
on raw `run()` because a detached command cannot return typed attached results.
`pscope` is also available on typed `rm`. Direct remote-to-remote copies can
request native receiver receipt detail with `receipt="sizes"` or
`receipt="hashed"`.
Ignore rules retain native ordering when interleaved by using
`ignore=[syq.IgnoreFrom("rules"), "!keep.tmp"]`; `ignore_from=` remains the
simple form when every file follows the inline patterns.

`on_event` receives typed records as syq produces them without keeping a
potentially enormous operation ledger in memory:

```python
def observe(event: syq.AutomationEvent) -> None:
    if isinstance(event, (syq.TraceEvent, syq.OperationResult)):
        print(event.action, event.dst)
    elif isinstance(event, (syq.RemovalTrace, syq.RemovalResult)):
        print(event.disposition, event.path)

result = syq.cp("data", into="backup", on_event=observe)
```

Pass a caller-owned binary file-like object as `results=` to retain the same
validated NDJSON stream that produced the returned `CpResult` or `RmResult`:

```python
with open("run.ndjson", "wb") as records:
    result = syq.cp("data", into="backup", results=records)
```

The object must report positive byte counts for non-empty writes. Nonblocking
sinks that return `None` when full are rejected so an incomplete result stream
cannot appear successful. The SDK flushes but never closes the object. Typed
calls receive automation records through native `--results-fd`; stdout is not
treated as machine output. Callers that need native `--results FILE` path
behavior can use `run()`.

Asyncio applications use the same command names and result types. Native
asyncio subprocesses keep the event loop responsive; async callbacks are
awaited in stream order:

```python
import asyncio
import syq

client = syq.AsyncClient(process_cwd="/srv/jobs")
events = asyncio.Queue()

async def observe(event: syq.AutomationEvent) -> None:
    await events.put(event)

result = await client.cp(
    "data",
    to="server",
    into="backup",
    on_event=observe,
)

removed = await client.rm("old-data", from_="server", on_event=observe)
```

Mapping output is streaming and context-managed. Passing Python mapping
entries to `cp` first materializes the complete iterable on disk, so a failed
transform cannot launch a copy with only a valid prefix:

```python
from dataclasses import replace

with syq.map(src_src="photos") as mapping:
    entries = (
        replace(entry, dst=syq.RelativePath("archive") / entry.dst)
        for entry in mapping
    )
    result = syq.cp(mapping=entries, cwd=mapping.cwd, into="published")
```

The async mapping stream is lazy and uses an async context manager:

```python
async with client.map(src_src="photos") as mapping:
    result = await client.cp(
        mapping=mapping,
        cwd=mapping.cwd,
        into="published",
    )
```

`mapping.cwd` is the absolute source-base spelling to pass to the consuming
copy. It preserves component order such as `link/../selected` so the native
walker encounters the link before `..`, and it expands `~/` with the mapping
subprocess's `HOME`. Do not normalize or resolve it between `map` and `cp`.

The source tree may contain typed support ahead of the latest released syq
pin. During that development interval, use `Client(executable=...)` or
`AsyncClient(executable=...)` with the candidate binary; the next SDK release
updates the immutable pin only after candidate conformance tests pass.

The managed executable is stored below
`$XDG_CACHE_HOME/syq/sdk/python/v0.1.8/` or, when `XDG_CACHE_HOME` is not an
absolute path, `~/.cache/syq/sdk/python/v0.1.8/`. The SDK checks the complete
cached binary against its embedded release manifest before every use. A corrupt
or missing cache entry is replaced atomically with a freshly downloaded,
verified binary.

`run()` raises `SyqProcessError` for a nonzero process status by default. The
exception retains the complete result, including stdout and stderr as bytes.
Pass `check=False` when the caller wants to interpret the status directly.
When `timeout` expires or the caller is interrupted, the SDK kills and reaps
syq's local process group, including child processes such as SSH transports,
before propagating the exception.

## Custom executable override

An explicit executable bypasses the managed version:

```python
result = syq.run(["--help"], executable="/opt/custom/bin/syq")
custom_version = syq.version(executable="syq")  # intentional PATH lookup
```

The SDK makes no compatibility or provenance guarantee for an override. Use it
for local development, controlled offline provisioning, or when deliberately
testing a different syq release.

The package targets Python 3.10 or newer on Linux and macOS and has no runtime
Python dependencies. See the [SDK compatibility policy](../README.md) for the
release mapping.

## Native API reference

See [Python native API](NATIVE_API.md) for command signatures, mappings,
failure behavior, resource ownership, and the CLI/SDK synchronization policy.
