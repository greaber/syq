<a id="python-sdk"></a>

# Python

Copy, remove, and reorganize files from Python, with typed results and streaming
events. Synchronous and asyncio clients are available.

<a id="preview-a-copy"></a>

## Install

The [syq package on PyPI](https://pypi.org/project/syq/) supports Python 3.13.4+
on Linux and macOS:

```sh
python -m pip install syq
```

Prebuilt wheels include the matching syq executable, so no Rust compiler or
separate syq installation is needed. The `syq` command is also available in
the Python environment.

## Try a copy

```python
import syq

result = syq.cp("data", into="backup")
print(result.files_transferred, result.bytes_transferred)
```

This copies `data` to `backup/data`. Add `to="server"` to use an SSH destination,
or `dry_run=True` to preview the changes. See the [guide and examples](python-guide.md)
for filtering, mappings, removal, and error handling.

## Building from source

Installing from a source distribution builds the executable and requires Rust
and a C compiler. Source builds upload themselves to compatible SSH hosts by
default. See
[source builds](https://github.com/greaber/syq/blob/master/CONTRIBUTING.md) for
compiler requirements and SSH helper selection.
