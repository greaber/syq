# Upstream rsync compatibility tests

This directory is SYQ's executable compatibility ledger for the upstream
rsync test suite. It answers a narrower question than `cargo test`: for rsync
tests that exercise command-line filesystem behavior relevant to SYQ, did SYQ
produce the result we have reviewed and recorded?

Run it from the repository root:

```sh
python3 scripts/rsync-compat.py
```

The first run fetches the commit pinned in `manifest.toml`, prepares rsync's
test helpers under `target/rsync-compat/`, builds SYQ, and runs the applicable
tests. Later runs reuse the prepared suite. Pass `--rsync-src PATH` to use an
already configured checkout at the exact pin. Reports are written to
`target/rsync-compat/reports/`.

Only the classified runnable subset is executed, not all 351 inventoried
tests. A warm non-root Linux run selects 22 tests and takes about 11 seconds on
the development machine; four more tests are selected when run as root. A
first run additionally downloads and prepares the pinned rsync checkout and
may do a cold Rust build. The exact cold time depends mostly on network and
Cargo state.

The source checkout and prepared test helpers are content-addressed and reused
until the rsync pin, helper configuration, or adaptation patches change. Cargo
also performs its normal incremental build. CI caches both sets of artifacts,
so routine jobs normally pay only an incremental SYQ build and the test run.
All adapted suites are copied from one configured base, so adding or changing
a testsuite-only adaptation does not rebuild rsync's C helpers. Fresh runners
still install the rsync build prerequisites. To manage the SYQ build separately,
use `--no-build-syq --syq-bin PATH`.

The harness requires Python 3.11 or newer. Preparing a fresh checkout also
requires Git, a C toolchain, Make, Autoconf, and Automake. The CI workflow
installs the build prerequisites.

## The ledger

`inventory.tsv` names every test at the pinned commit. Updating the pin without
classifying every added or removed test is an error. Its classifications are:

- `conformance`: an unmodified upstream test that measures relevant observable
  behavior. It contributes to the compatibility score.
- `adapted`: still an upstream conformance test, with a patch for an
  implementation-specific fixture detail or to isolate the supported part of
  an aggregate test. It contributes to the score and names its adaptation in
  `manifest.toml`.
- `unsupported`: a user-visible rsync feature SYQ does not implement. It is
  tracked separately from internals and from known failures that we actively
  run.
- `out-of-scope`: rsync protocol, daemon, restricted-wrapper, build, or
  implementation-internal testing. SYQ does not need to pass it.
- `unassessed`: not yet reviewed closely enough to classify. This is visible
  compatibility-audit debt, not an implicit failure or exclusion. The current
  pin has zero tests in this category.

Runnable tests have an expected result per enabled profile. The upstream
runner compares actual results with that manifest: a regression fails, and an
unexpected pass also fails so the ledger must be updated. Requirements and
platform restrictions record the circumstances in which an expectation is
valid.

The reported pass rate covers only the reviewed, runnable conformance tests.
It is a regression measure, not a claim that unsupported rsync features are
compatible; their counts are printed beside it. `LEDGER.md` lists all 351 tests
and is generated with `--ledger-only --update-ledger`; normal runs reject a
stale generated ledger.

The future `strict` profile is already represented, but disabled until SYQ has
the corresponding flag. The harness injects profile arguments through a
generated executable wrapper, so upstream tests do not need to know about the
flag.

## Adaptations

An adaptation is a unified diff stored as
`adaptations/<id>.patch`, referenced by an `adapted` test's `adaptation` field.
The harness applies patches to a fresh cached checkout and includes their
contents in the cache key. Adaptations may change an incidental fixture or
isolate the supported part of an upstream test that combines several features;
they must not change the semantics claimed by the resulting test. For example,
SYQ's partial adaptation discovers the full-length sparse
`.name.syq-part.<job-id>` sidecar instead of rsync's growing destination prefix
while retaining the same interrupted-transfer-and-successful-resume assertions. The
manifest's note must identify any omitted unsupported scenario.

Do not adapt a test merely to make it green. If it exercises rsync internals,
classify it `out-of-scope`; if SYQ lacks the behavior, use `unsupported`; if
the behavior is applicable and differs, run it as an expected failure.
