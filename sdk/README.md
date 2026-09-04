# syq language SDKs

This directory contains the Python client for syq. It invokes the syq
executable rather than inventing a second transfer implementation, and it
implements synchronous and asyncio clients for typed
`cp` (including `prune=True`), `rm`, and `map` against syq's versioned machine
interfaces. Every other command and mode, such as a detached remote-to-remote
copy, remains available through raw `run`. The executable remains authoritative
for argument semantics, filesystem behavior, exit status, and safety checks.

The Python-native surface is documented in
[`python/NATIVE_API.md`](python/NATIVE_API.md).

| Ecosystem | Package/module | Source |
|---|---|---|
| Python | `syq` | [`python/`](python/) |

Every SDK release pins one exact, tested syq release. The default client does
not search `PATH` or adopt a separately installed syq. On first use it downloads
the pinned official binary for the current platform into an SDK-owned cache,
verifies its archive and decompressed bytes against the release manifest
embedded in the package, checks its version and release identity, and then
always invokes that cached binary.

The Python package uses the same version as the syq release it manages. Its
package version, `syq.__version__`, and `syq.PINNED_SYQ_VERSION` therefore agree.
The embedded mapping remains immutable for a published package. Every
successful official syq release automatically prepares the matching Python SDK
release pull request with its exact signed manifest. Maintainers review and
merge that release before creating the signed Python SDK tag.

Callers that need a local build, a newer syq, or an offline-provisioned binary
may pass `executable=` explicitly. That opts out of the tested pairing; the
caller owns compatibility and provenance for the override.

This makes the supported SDK/runtime combination hermetic. SDK consumers can
pin the Python package version in their own lockfile and choose when to adopt a
new SDK-plus-syq release. The supported subprocess behavior is never exposed
to untested executable drift.

The Python package implements this model.

See [`RELEASING.md`](RELEASING.md) for the one-time registry setup and exact
tag conventions.
