# syq for Python

`syq` is the official Python client for the
[syq parallel file copier](https://github.com/greaber/syq). It invokes syq with
an argument array and never constructs a shell command. The typed API mirrors
native `cp`, including `cp --prune`, and `map`. Commands without an automation
result stream, including `rm`, remain available through `run`.

```sh
python -m pip install syq
```

Package installation does not download an executable. The first call that
needs syq downloads the exact release pinned by this SDK into the user cache.
For Python package `0.0.3`, that release is syq `0.1.8`.

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
```

Remote-copy controls use the same names with underscores, including `run_at`,
`rsh`, `syq_path`, `no_bootstrap`, `tcp_plain`, `no_tcp`, `tcp_ports`,
`tcp_congestion`, and the native agent-forwarding policy flags. `detach` stays
on raw `run()` because a detached command cannot return typed attached results.

`on_event` receives typed records as syq produces them without keeping a
potentially enormous operation ledger in memory:

```python
def observe(event: syq.AutomationEvent) -> None:
    if isinstance(event, (syq.TraceEvent, syq.OperationResult)):
        print(event.action, event.dst)

result = syq.cp("data", into="backup", on_event=observe)
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

The source tree may contain typed support ahead of the latest released syq
pin. During that development interval, use `Client(executable=...)` with the
candidate binary; the next SDK release updates the immutable pin only after
candidate conformance tests pass.

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
