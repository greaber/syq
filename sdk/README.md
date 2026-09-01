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

| Ecosystem | Package/module | Source |
|---|---|---|
| Python | `syq` | [`python/`](python/) |
| JavaScript and TypeScript | `@syq/sdk` | [`js/`](js/) |
| Go | `github.com/greaber/syq/sdk/go` | [`go/`](go/) |

Package versions are independent of the syq executable version. A wrapper
release may support multiple executable versions, while the future automation
schema will have its own explicit major version.

See [`RELEASING.md`](RELEASING.md) for the one-time registry setup and exact
tag conventions.
