<a id="syq-language-sdks"></a>

# Compatibility

The Python package supports Python 3.10+ on Linux and macOS and has no runtime
Python dependencies.

## Managed executable

Each package version uses the same version of syq. Pin the Python package in
your dependency file to keep that pairing.
`syq.__version__` and `syq.PINNED_SYQ_VERSION` report these versions.

The default client downloads the matching official executable on first use,
verifies it against the release manifest embedded in the package, and caches it.
It checks the cached binary before each use and replaces a missing or corrupt
entry. It does not search `PATH`.

The default cache is `$XDG_CACHE_HOME/syq/sdk/python/v<version>/` when
`XDG_CACHE_HOME` is absolute, or `~/.cache/syq/sdk/python/v<version>/` otherwise.
Set `Client(cache_dir=...)` to choose a different cache root. Call
`syq.managed_executable()` to download ahead of time and get the executable path.

## Custom executable

Pass `executable=` to use a local build or an offline-provisioned executable:

```python
import syq

client = syq.Client(executable="/opt/bin/syq")
print(client.version())
```

`executable="syq"` explicitly selects syq from `PATH`. An override bypasses the
managed download and verification; you are responsible for its compatibility
and origin. Typed calls still reject unsupported or invalid automation output.
The client does not fall back to another executable if the selected one fails.
