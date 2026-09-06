# Python SDK

Use syq from Python to copy, remove or reorganize files, with typed results
and streaming events. Synchronous and asyncio clients are available.

## Install

The [syq package on PyPI](https://pypi.org/project/syq/) supports Python 3.10+
on Linux and macOS:

    python -m pip install syq

On first use, the default client downloads and verifies the matching syq
executable, then caches it. It does not use an unrelated syq from your PATH.

## Preview a copy

    import syq

    plan = syq.cp("data", into="backup", dry_run=True)
    print(plan.files_transferred, plan.bytes_transferred)

Remove `dry_run=True` to perform the copy. Use `to="server"` for an SSH destination;
the same placement options are described in [Copy files](reference.md).

The typed API includes `syq.cp()`, `syq.rm()` and `syq.map()`. Call `syq.run([...])`
for other commands. Asyncio programs use `await syq.AsyncClient().cp(...)`.
Failures raise exceptions; typed calls also check the complete results stream
rather than treating a truncated stream as success.

## Guide and reference

- [Python guide and examples](python-guide.md):
  event callbacks, asyncio, mapping transformations, errors and custom binaries.
- [Native API reference](python-reference.md):
  signatures, option mappings and result types.
- [SDK compatibility](sdk-compatibility.md):
  package versions and their pinned executables.
- [Rename and reorganize](mappings.md) and [Automation results](automation.md):
  the underlying CLI interfaces.
