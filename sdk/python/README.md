# syq for Python

`syq` is the official preview Python adapter for the
[syq parallel file copier](https://github.com/greaber/syq). It invokes syq with
an argument array and never constructs a shell command.

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

plan = syq.run([
    "cp",
    "project",
    "--to",
    "server",
    "--into",
    "/backup",
    "--dry-run",
])
print(plan.stdout.decode())
```

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

## Proposed native API

The next typed layer is being designed in
[Proposed Python native API](NATIVE_API.md). That document is a specification
for review, not an implemented usage guide. The process adapter described above
remains the current public API.
