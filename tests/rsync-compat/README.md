# Upstream rsync behavioral tests

This directory tracks what selected upstream rsync tests tell us about SYQ's
rsync-compatible command surface. It is both a regression suite and a reviewable
map of compatibility work. It is not an overall compatibility score.

Run it from the repository root:

```sh
python3 scripts/rsync-compat.py
```

The manifest currently routes upstream invocations to native `syq`, because the
dedicated command does not exist yet. When `syq rsync` lands, changing
`target.args` from `[]` to `["rsync"]` switches the whole suite without patching
upstream tests or adding a second harness mode.

The first run fetches the commit pinned in `manifest.toml`, prepares rsync's
test helpers under `target/rsync-compat/`, builds SYQ, and runs the applicable
tests. Later runs reuse the prepared suite. Pass `--rsync-src PATH` to use an
already configured checkout at the exact pin. Reports are written as JSON,
Markdown, static HTML, and a raw log under `target/rsync-compat/reports/`.

Only the classified runnable subset is executed, not all 351 inventoried
tests. A warm non-root Linux run selects 22 tests and takes about 11 seconds on
the development machine; four more tests apply when run as root. A first run
also downloads and prepares the pinned rsync checkout and may do a cold Rust
build. The exact cold time depends mostly on network and Cargo state.

The source checkout and prepared helpers are content-addressed and reused until
the rsync pin, helper configuration, or adaptation patches change. Cargo uses
its normal incremental build. CI caches both sets of artifacts and installs
rsync's build prerequisites only on a suite-cache miss. To manage the SYQ build
separately, use `--no-build-syq --syq-bin PATH`.

The upstream runner gives each test a 300-second deadline by default; override
it with `--test-timeout SECONDS`. CI uses 120 seconds per test, caps the entire
job at 30 minutes, and passes `--require-tests` so an accidentally empty Linux
selection cannot look successful. A local run with no applicable tests still
writes a valid N/A report.

The harness requires Python 3.11 or newer. Preparing a fresh checkout also
requires Git, a C toolchain, Make, Autoconf, and Automake.

## Inventory, observations, and product positions

`inventory.tsv` names every test at the pinned commit. Updating the pin without
classifying every added or removed test is an error. Its classifications are:

- `conformance`: a relevant upstream test used without modification.
- `adapted`: a relevant upstream test with a narrow, recorded fixture,
  invocation, or subset adaptation.
- `unsupported`: a user-visible rsync feature the target does not implement.
- `out-of-scope`: rsync protocol, daemon, restricted-wrapper, build, harness,
  or implementation-internal testing.
- `unassessed`: a test not yet reviewed closely enough to classify.

Each runnable manifest entry separates three ideas that should not be collapsed
into one pass percentage:

- `baseline` is the last reviewed raw runner outcome. A change in either
  direction fails CI until someone reviews and records it.
- `position` records what the result means for the product: `compatible`,
  `unimplemented`, `intentional-divergence`, `policy-open`, or
  `test-unresolved`.
- provenance says whether the upstream test is unmodified or carries an
  `invocation`, `fixture`, or `subset` adaptation.

The runner exit status is checked independently of those baselines. An ordinary
test failure is not a harness failure when the runner reports it consistently;
missing, duplicate, or contradictory output is. Markdown and HTML reports show
the observations grouped by behavioral area, their product positions,
provenance, platform/user circumstances, any baseline changes, and a compact
breakdown of unsupported user-facing feature areas. Rsync-internal tests remain
out of the compatibility matrix.

`LEDGER.md` is the generated readable inventory. Update it with
`--ledger-only --update-ledger`; normal runs reject a stale copy.

## Adaptations

An adaptation is a unified diff stored as `adaptations/<id>.patch`, referenced
by an `adapted` test. The harness hashes and applies the exact validated bytes.
It asks Git for both the forward and reverse path sets, so additions, deletions,
traditional multi-file diffs, renames, and copies must all stay under
`testsuite/`.

Adaptations may translate an implementation-specific fixture or isolate a
supported part of an aggregate test. They must not edit rsync sources or its
runner, and they must not quietly change the behavioral claim. The partial test,
for example, looks for SYQ's job-scoped sidecar instead of rsync's partial name;
the manifest labels that fixture adaptation and the current intentional product
divergence explicitly.

Do not adapt a test merely to make it green. Classify rsync internals as
`out-of-scope`, unsupported user behavior as `unsupported`, and runnable
differences according to their actual product position.
