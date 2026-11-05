<a id="syq-for-python"></a>
<a id="python-sdk"></a>
<a id="guide-and-examples"></a>

# Python

The `syq` package runs syq from Python. Copy, remove, and reorganize files,
and get typed results and events back, with a synchronous or asyncio client.
The [operations reference](https://greaber.github.io/syq/python-operations.html)
lists every argument.

<a id="preview-a-copy"></a>

## Install

The [syq package on PyPI](https://pypi.org/project/syq/) supports Python 3.13.4+
on Linux and macOS:

```sh
python -m pip install syq
```

Prebuilt wheels include the matching syq executable, also available as the
`syq` command in the Python environment.

<a id="try-a-copy"></a>

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

Arguments use the command-line names, with underscores for hyphens and a
trailing underscore on Python keywords such as `from_` and `as_`. The
[copy guide](https://greaber.github.io/syq/reference.html) explains the
options.

## Copy over SSH

Use `to` for an SSH destination and `from_` for an SSH source:

```python
syq.cp("data", to="user@server", into="/backup")
syq.cp("report.csv", from_="user@server", cwd="/exports", into="downloads")
```

Pass both `from_` and `to` to
[copy between servers](https://greaber.github.io/syq/remote-to-remote.html).

## Preview changes

Pass `dry_run=True` to preview a copy or removal; the result counts the
planned changes:

```python
preview = syq.cp("data", into="backup", dry_run=True)
print(preview.files_transferred, preview.bytes_transferred)
```

## Mirror a directory

`prune=True` also removes destination entries the source does not have. Here
`staging` must already exist, and `max_delete` caps the deletions:

```python
result = syq.cp(
    srcs_in="build",
    into_existing="staging",
    prune=True,
    max_delete=100,
)
```

## Filter with expressions

`where` selects source files, and `copy_if` decides which files the copy may
create or update:

```python
syq.cp(srcs_in="project", into="backup",
       where='src.kind = "file" and src.size >= 1MiB',
       copy_if='not dst.exists or src.mtime > dst.mtime')
```

See [Select entries with expressions](https://greaber.github.io/syq/expressions.html)
for the fields and operators.

## Remove files

```python
result = syq.rm(src_dir="old-output", root="/srv/jobs")
print(result.entries_removed, result.selectors_missing)
```

Positional paths and `src` refuse directories; use `src_dir` to remove a tree
or `srcs_in` to empty it. `root` keeps removal inside that directory. Pass
`on="server"` or `on="s3://bucket"` to remove files elsewhere; see
[Remove files](https://greaber.github.io/syq/remove.html).

## Handle failures

A failed copy or removal raises `SyqOperationError` with its typed result:

```python
try:
    result = syq.cp("data", into="backup")
except syq.SyqOperationError as error:
    print(error.result.status, error.result.errors)
    print(error.stderr.decode(errors="replace"))
```

Pass `check=False` to get unsuccessful results back instead. Catch
`syq.SyqError` for any SDK exception. Completed changes are not rolled back.

## Watch events and save results

`on_event` receives records while the operation runs, for example each copied
entry or planned change:

```python
def observe(event: syq.AutomationEvent) -> None:
    if isinstance(event, (syq.TraceEvent, syq.OperationResult)):
        print(event.action, event.dst)

result = syq.cp("data", into="backup", on_event=observe)
```

Events are not kept in the result. To save them as NDJSON, pass a binary
file:

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

This puts the contents of `photos` under `published/archive`. Return `None`
from the transform to skip an entry. The mapping remembers where its sources
are, so the same code works with `map(from_="server")` or
`map(from_="s3://bucket")`. A failed transform copies nothing. See
[Rename and reorganize](https://greaber.github.io/syq/mappings.html), or
[Pull and push DVC data](https://greaber.github.io/syq/dvc.html) for a complete
program.

## Generated data and binary streams

`open_writer` writes one file or object without a temporary file. For example,
write an archive directly to S3:

```python
import tarfile
import syq

with syq.open_writer(to="s3://backups", as_="dataset.tar") as output:
    with tarfile.open(fileobj=output, mode="w|") as archive:
        archive.add("dataset", arcname="dataset")
```

`open_reader` reads one local file, SSH file, or S3 object:

```python
with syq.open_reader("dataset.tar", from_="s3://backups") as source:
    while chunk := source.read(65536):
        consume(chunk)
```

A writer publishes its file only when its `with` block exits normally. A
reader checks that the transfer succeeded when its block exits, so if you
extract files from a stream, use them only after both decoding and the reader's
block finish. See
[Byte streams](https://greaber.github.io/syq/python-streams.html#byte-streams).

To generate several files in one copy, put producers in a mapping:

```python
from functools import partial

def pack(directory, output):
    with tarfile.open(fileobj=output, mode="w|") as archive:
        archive.add(directory, arcname=directory)

syq.cp(mapping=[syq.MappingEntry(syq.StreamSource(partial(pack, name)), f"{name}.tar")
                for name in ("images", "labels")],
       to="s3://backups", into="dataset", stream_concurrency=2)
```

`StreamDestination(consumer)` receives downloaded bytes the same way; see
[Callback mappings](https://greaber.github.io/syq/python-streams.html#callback-mappings).

## Use asyncio

`AsyncClient` takes the same arguments and returns the same results; await
its operations:

```python
import asyncio
import syq

async def main():
    client = syq.AsyncClient()
    result = await client.cp("data", into="backup")
    print(result.files_transferred)

asyncio.run(main())
```

Use mappings with `async with`, without `await` before `client.map()`:

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

`process_cwd` sets the local working directory, while `cwd` sets the source
base, which can be on a remote host. Pass `timeout=None` to disable the
client's timeout for one call:

```python
result = client.cp("data", into="backup", timeout=None)
```

`Client(executable="/opt/bin/syq")` runs another syq instead of the bundled
one; see [Compatibility](https://greaber.github.io/syq/python-operations.html#compatibility).

<a id="native-api-reference"></a>

## Run other commands

`run` runs any syq command, such as `rsync` or receiver administration, and
returns its captured output:

```python
result = syq.run(["--help"])
print(result.stdout.decode())
```

To request a command on your receiving machine, use the syq executable you use
for receiving:

```python
import syq

result = syq.run(
    ["exec", "--on", "@laptop", "--cwd", "work/project", "--", "cargo", "test"],
    executable="/path/to/syq",
    timeout=600,
)
print(result.stdout.decode())
```

The receiving machine asks for approval first, and `run` raises if the
command exits nonzero. See
[Run commands on your laptop](https://greaber.github.io/syq/receive.html#run-commands-on-your-laptop).

## Building from source

Installing from a source distribution builds the executable, which needs Rust
and a C compiler. By default, a source build uploads its own executable to SSH
servers, so they must be able to run it. See
[source builds](https://github.com/greaber/syq/blob/master/CONTRIBUTING.md).
