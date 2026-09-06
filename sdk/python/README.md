<a id="syq-for-python"></a>

# Guide and examples

Use the `syq` package to call syq from Python. See
[installation](https://greaber.github.io/syq/python.html#install) if you have not
installed it yet.

## Copy files

Copy a directory named `data` into `backup`, producing `backup/data`:

```python
import syq

result = syq.cp("data", into="backup")
print(result.files_transferred, result.bytes_transferred)
```

To copy just its contents, use `srcs_in`:

```python
result = syq.cp(srcs_in="data", into="backup")
```

Arguments follow the command-line names: replace hyphens with underscores,
and add a trailing underscore for Python keywords, such as `from_` and `as_`.
The [copy guide](https://greaber.github.io/syq/reference.html) explains placement,
filtering, and verification options.

## Copy over SSH

Use `to` for an SSH destination and `from_` for an SSH source:

```python
syq.cp("data", to="user@server", into="/backup")
syq.cp("report.csv", from_="user@server", cwd="/exports", into="downloads")
```

SSH hosts and paths are separate arguments. See
[Copy between servers](https://greaber.github.io/syq/remote-to-remote.html)
for copies with two remote endpoints. A typed remote-to-remote preview needs
`coordinate_at="local"`; a live copy can also use an enrolled receiver.

## Preview changes

Pass `dry_run=True` to preview a copy or removal. The result has the same type
as a live call, with counters describing the planned changes:

```python
preview = syq.cp("data", into="backup", dry_run=True)
print(preview.files_transferred, preview.bytes_transferred)
```

Remove `dry_run=True` to apply the changes. syq checks the filesystem again
when that call runs.

## Mirror a directory

Use `prune=True` to also remove destination entries absent from the source.
Here, `staging` must already exist, and `max_delete` limits deletions:

```python
result = syq.cp(
    srcs_in="build",
    into_existing="staging",
    prune=True,
    max_delete=100,
)
```

## Remove files

```python
result = syq.rm(src_dir="old-output", root="/srv/jobs")
print(result.entries_removed, result.selectors_missing)
```

`root` confines removal to that directory. Add `from_="server"` to remove files
over ordinary SSH. Command-restricted receivers do not support `rm`. See
[Remove files](https://greaber.github.io/syq/remove.html) for selector behavior.

## Handle failures

A failed copy or removal raises `SyqOperationError` with its typed result:

```python
try:
    result = syq.cp("data", into="backup")
except syq.SyqOperationError as error:
    print(error.result.status, error.result.errors)
    print(error.stderr.decode(errors="replace"))
```

Use `check=False` to receive unsuccessful results without that exception.
Invalid arguments, installation failures, and incomplete or invalid results
still raise exceptions. Completed filesystem changes are not rolled back.

## Watch events and save results

`on_event` receives records as the operation runs. For example, show each copied
entry or planned change:

```python
def observe(event: syq.AutomationEvent) -> None:
    if isinstance(event, (syq.TraceEvent, syq.OperationResult)):
        print(event.action, event.dst)

result = syq.cp("data", into="backup", on_event=observe)
```

Events are not collected in the returned result. To save the validated NDJSON
records, pass an open binary stream:

```python
with open("run.ndjson", "wb") as records:
    result = syq.cp("data", into="backup", results=records)
```

## Rename while copying

Create a mapping, change its destination paths, then copy:

```python
from dataclasses import replace

with syq.map(srcs_in="photos") as mapping:
    entries = (
        replace(entry, dst=syq.RelativePath("archive") / entry.dst)
        for entry in mapping
    )
    result = syq.cp(mapping=entries, cwd=mapping.cwd, into="published")
```

This places the contents of `photos` under `published/archive`. Pass
`mapping.cwd` through unchanged so the copy uses the mapping's source base.
If the mapping required `follow_src=True`, use it on the copy too.
The iterable must finish successfully before copying starts; a failed transform
leaves the destination untouched. See
[Rename and reorganize](https://greaber.github.io/syq/mappings.html) for mapping rules.

## Use asyncio

Await operations on `AsyncClient`. Its arguments and results match `Client`:

```python
import asyncio
import syq

async def main():
    client = syq.AsyncClient()
    result = await client.cp("data", into="backup")
    print(result.files_transferred)

asyncio.run(main())
```

Async event callbacks are awaited in record order. Mapping streams use
`async with` and `async for`; there is no `await` before `client.map()`:

```python
async def copy_photos():
    client = syq.AsyncClient()
    async with client.map(srcs_in="photos") as mapping:
        return await client.cp(mapping=mapping, cwd=mapping.cwd, into="published")
```

<a id="custom-executable-override"></a>

## Configure a client

Share a local working directory and timeout across calls:

```python
client = syq.Client(process_cwd="/srv/jobs", timeout=3600)
result = client.cp("data", into="backup")
```

`process_cwd` sets the local subprocess directory; typed `cwd` sets the source
base, which may be on a remote host.

To use an existing executable, pass `Client(executable="/opt/bin/syq")`.
This bypasses the managed version; see
[Compatibility](https://greaber.github.io/syq/python-reference.html#compatibility).

<a id="native-api-reference"></a>

## Run other commands

`run` accepts arguments after the executable name and returns captured bytes:

```python
result = syq.run(["--help"])
print(result.stdout.decode())
```

Use it for commands without a typed method, including `rsync` and receiver
administration. See the
[API reference](https://greaber.github.io/syq/python-reference.html) for process
options and exceptions.
