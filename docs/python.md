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

Prebuilt wheels include the matching syq executable. Installation needs no Rust
compiler, and SDK calls need no executable download or writable home directory
for installation. The `syq` command is also available in the Python environment.

Installing from a source distribution builds the executable and requires Rust
and a C compiler. Its remote behavior follows the native source version bundled
in that distribution: source builds upload themselves to compatible SSH hosts
by default. See [source builds](https://github.com/greaber/syq/blob/master/CONTRIBUTING.md) for helper selection and symbols
when building from a checkout with those options. Older distributions retain
their bundled native version's build options.
