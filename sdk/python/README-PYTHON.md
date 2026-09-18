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
filtering, and verification options. Advanced groups take comma-separated
strings, for example `resource_limits="bandwidth=10M"`,
`performance_tuning="workers=4"`, or
`integrity_checking="compare=blake3,transfer=sha256"`. They are optional;
ordinary copies choose performance settings automatically.

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

Positional paths and `src` refuse directories. Use `src_dir` to remove
a tree, or `srcs_in` to recursively empty it while keeping its root.

`root` confines removal to that directory. Add `on="server"` to remove files
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
still raise exceptions. Catch `syq.SyqError` to handle any SDK-defined exception,
or catch a specific subclass as above. Completed filesystem changes are not
rolled back.

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
    renamed = mapping.transform(
        lambda entry: replace(entry, dst=syq.RelativePath("archive") / entry.dst)
    )
    result = syq.cp(mapping=renamed, into="published")
```

This places the contents of `photos` under `published/archive`. The mapping
carries its source base and symlink-following policy through the transform.
Return `None` from the transform to skip an entry. The entire transform must
finish successfully before copying starts; a failed transform leaves the
destination untouched. See
[Rename and reorganize](https://greaber.github.io/syq/mappings.html) for mapping rules.

For a complete program built on mappings, see
[Pull and push DVC data](https://greaber.github.io/syq/dvc.html).

## Generated data and binary streams

Use `open_writer` to generate one file or object without a temporary payload
file. A successful context exit commits the upload; an exception aborts it.
For example, the standard library can write an archive directly to S3:

```python
import tarfile
import syq

with syq.open_writer(to="s3://backups", as_="dataset.tar") as output:
    with tarfile.open(fileobj=output, mode="w|") as archive:
        archive.add("dataset", arcname="dataset")
```

`open_reader` supplies the contents of one local file, SSH file, or S3 object:

```python
with syq.open_reader("dataset.tar", from_="s3://backups") as source:
    while chunk := source.read(65536):
        consume(chunk)
```

The streams use bounded transport buffers. Reading without a size requests
all remaining bytes into Python memory. Reader context exit drains unread
bytes and checks transfer success, so archive readers may stop at their own
end marker. Call `abort()` to cancel instead. If a consumer publishes files,
keep them staged until both decoding and the reader context finish successfully.
See [byte streams](https://greaber.github.io/syq/python-reference.html#byte-streams)
for lifecycle, timeout, and async behavior.

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
        return await client.cp(mapping=mapping, into="published")
```

<a id="custom-executable-override"></a>

## Configure a client

Share a local working directory and timeout across calls:

```python
client = syq.Client(process_cwd="/srv/jobs", timeout=3600)
result = client.cp("data", into="backup")
```

`process_cwd` sets the local subprocess directory; typed `cwd` sets the source
base, which may be on a remote host. Omit `timeout` on a call to use the client
default; pass `timeout=None` to disable it for that call:

```python
result = client.cp("data", into="backup", timeout=None)
```

To use an existing executable, pass `Client(executable="/opt/bin/syq")`.
This bypasses the bundled version; see
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
