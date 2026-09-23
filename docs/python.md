{{#include ../sdk/python/README-PYTHON.md}}

For [expression filtering](expressions.md), pass `where` and `copy_if` to
`cp` (also available on `AsyncClient`):

```python
syq.cp(srcs_in="project", into="backup",
       where='src.kind = "file" and src.size >= 1MiB',
       copy_if='not dst.exists or src.mtime > dst.mtime')
```
