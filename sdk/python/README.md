# syq for Python

`syq` is the official preview Python adapter for the
[syq parallel file copier](https://github.com/greaber/syq). It invokes an
installed `syq` executable directly with an argument array; it never constructs
a shell command and it does not download or install a binary as a package
installation side effect.

The preview API intentionally offers raw execution and version discovery only.
A typed copy and event API will follow syq's versioned NDJSON automation
interface.

```python
import syq

print(syq.version())

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

`run()` raises `SyqProcessError` for a nonzero process status by default. The
exception retains the complete result, including stdout and stderr as bytes.
Pass `check=False` when the caller wants to interpret the status directly.

The `syq` executable must already be on `PATH`, or its explicit path can be
passed with `executable=`.

This package currently targets Python 3.10 or newer on Linux and macOS.
