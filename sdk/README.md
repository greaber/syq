# syq language SDKs

This directory contains preview subprocess adapters for syq. They are small,
real packages that establish the canonical language names without inventing a
second transfer implementation.

The initial packages deliberately expose only two operations:

- run the `syq` executable with an argument array, never through a shell;
- query and validate `syq --version`.

They do not parse human output or yet offer a structured copy API. That surface
will be added after syq's versioned NDJSON automation interface is released.
The executable remains authoritative for argument semantics, filesystem
behavior, exit status, and safety checks.

The proposed Python-native surface is documented separately in
[`python/NATIVE_API.md`](python/NATIVE_API.md). It is a design specification,
not a description of the currently released package.

| Ecosystem | Package/module | Source |
|---|---|---|
| Python | `syq` | [`python/`](python/) |
| JavaScript and TypeScript | `@syq/sdk` | [`js/`](js/) |
| Go | `github.com/greaber/syq/sdk/go` | [`go/`](go/) |

Every SDK release pins one exact, tested syq release. The default client does
not search `PATH` or adopt a separately installed syq. On first use it downloads
the pinned official binary for the current platform into an SDK-owned cache,
verifies its archive and decompressed bytes against the release manifest
embedded in the package, checks its version and release identity, and then
always invokes that cached binary.

The current mapping is:

| Python SDK | syq executable |
|---|---|
| `0.0.1` | `0.1.5` |
| `0.0.2` | `0.1.7` |
| `0.0.3` | `0.1.8` |

The two version numbers do not need to match, but the mapping is immutable for
a published SDK release. Multiple SDK releases may pin the same syq release.
Moving to another syq release requires a new SDK release and its compatibility
tests. Every successful official syq release automatically prepares a Python
SDK patch-release pull request that pins its exact signed manifest. Maintainers
review and merge that mapping before creating the signed Python SDK tag.

Callers that need a local build, a newer syq, or an offline-provisioned binary
may pass `executable=` explicitly. That opts out of the tested pairing; the
caller owns compatibility and provenance for the override.

This makes the supported SDK/runtime combination hermetic. SDK consumers can
pin the Python package version in their own lockfile and choose when to adopt a
new SDK-plus-syq pair. The SDK still versions changes to its Python API normally,
but its supported subprocess behavior is never exposed to untested executable
drift.

The Python package implements this model. The JavaScript and Go preview
packages must adopt it before their first registry releases.

See [`RELEASING.md`](RELEASING.md) for the one-time registry setup and exact
tag conventions.
