# Python API revision, September 2026

The user authorized a breaking Python API cleanup before SDK adoption on
2026-09-06. This exception applies to the four changes below; it is not a
standing exemption from compatibility checks. The released baseline inspected
for this work is Python SDK 0.4.1 (release preparation merged at `2c80e73`),
paired with syq `v0.4.1`. This supersedes the initial 0.4.0 baseline; 0.4.1
still has the old flattened API.

## Mapping source context

`Mapping` and `AsyncMapping` combine entries with a local source base, optional
root confinement, and source-following policy. `MapStream` and `AsyncMapStream`
are their context-managed producer forms. `.transform()` is lazy and preserves
that context; `None` omits an entry. Lazy async streams snapshot the producer
directory, environment, and timeout so later client mutations cannot detach
the entry stream from its recorded source base. A copy consumes the complete transformed
input before starting its mutating subprocess. Closing a producer or exhausting
it prevents it from being reused as an apparently complete empty mapping.

The context uses absolute, unresolved source spellings, including symlinks and
`..`. A producing `root` becomes a root on the consumer, narrowed to `srcs_in`
when applicable. The consumer resolves and pins it again. This preserves the
confinement policy, not directory identity across processes or a filesystem
snapshot. Contextual mappings reject `from_`, `cwd`, and `root` on `cp`; an
explicit source override must use a plain iterable or manifest instead.

A caller-owned iterable can still be passed directly to `cp` with explicit
source options. Its serialization and the manifest grammar are unchanged.

Migration: replace a generator over a map stream plus `cwd=mapping.cwd` with
`mapping.transform(function)` and omit `cwd`. List materialization discards
context; wrap such entries in `Mapping(entries, cwd=...)` or supply source
options explicitly. Async transforms may await their callbacks.

## SDK exceptions

`SyqError` is the common base of installation, invocation, process, output,
protocol, and operation exceptions. Their existing standard-library base classes
and diagnostic attributes remain. Application exceptions, standard type/value
errors, spawn errors, timeouts, and cancellation are not wrapped. A broad SDK
catch must not accidentally intercept an application's own callback failure.

## Timeout inheritance

On client methods that accept a timeout, omission inherits the client default;
explicit `None` disables the timeout for that call. Numeric values override it.
The public `syq.CLIENT_DEFAULT` sentinel and `syq.Timeout` alias let wrappers
forward inheritance without private imports. Sync and async signatures
match. Mapping streams snapshot the chosen timeout when constructed. The timeout covers the
subprocess, not installation or full mapping materialization.

Migration: callers previously passing `timeout=None` to mean inheritance should
omit that argument. Raw module-level `run` and client constructors still default
to no timeout.

## Results and protocol metadata

Every automation event and terminal result has a frozen `protocol` object with
`schema`, `schema_version`, `seq`, and `type`. The uniform name allows a callback
to inspect the envelope without special-casing terminal results. It also avoids
colliding with the filesystem `metadata` on `FinalStateEvent`.

Copy results have `receipt: ReceiptSummary | None`, containing `status`,
`operations`, `final_states`, `records`, and `provenance`. Ordinary counts and
operation status remain directly on the result. Receiver receipts continue to
have distinct observable totals; grouping fields does not infer source-side
information a receipt cannot attest.

Migration: use `event.protocol.seq` instead of `event.seq`, and
`result.receipt.status` instead of `result.receipt_status`, checking for `None`.
No aliases retain the old flattened fields in this pre-adoption revision.

## Compatibility boundaries

Only Python call semantics and Python object shapes change. The native CLI,
helper pinning and wire protocol, mapping NDJSON, automation NDJSON, enrollment,
signed grants and redemption records, receiver receipts, replay protection,
resume identities, caches, release manifests, package pin, and documentation
URLs remain unchanged. Python objects are process-local and have no promised
pickle/storage format.

The new Python consumer is tested against the unchanged old automation fixtures
and the actual managed syq 0.4.1 binary.
`results=` still writes the native NDJSON shape rather than serializing the new
Python objects. An old Python package continues to use its own embedded pin and
read the same saved files. Both packages can share the existing managed cache
without migration or invalidation; no persisted authority is reset or redefined.
