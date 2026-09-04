# Upstream rsync behavioral tests

This directory tracks what selected upstream rsync tests tell us about SYQ's
rsync-compatible command surface. It is both a regression suite and a reviewable
map of compatibility work. It is not an overall compatibility score.

Run it from the repository root:

```sh
python3 scripts/rsync-compat.py
```

To run only the security-classified scenarios, use:

```sh
python3 scripts/rsync-compat.py --area security --report-label security-user
sudo python3 scripts/rsync-compat.py --area security --report-label security-root \
  --no-build-syq --syq-bin "$PWD/target/debug/syq"
sudo chown -R "$(id -u):$(id -g)" target/rsync-compat
```

`--area` is repeatable. The non-root and root runs exercise different cells;
in particular, foreign-owner symlink plants require root to set up. The first
command builds SYQ and prepares the suite as your own user, and the root run
reuses both rather than invoking Cargo as root, which usually cannot find a
rustup toolchain and would leave root-owned build output behind. The root run
still writes its reports under `target/rsync-compat/`, so the last command
hands that directory back to you. This is a focused slice of the applicable
compatibility matrix, not a claim that rsync has a standalone security suite or
that SYQ implements rsync's daemon and wire protocol surfaces.

The manifest routes upstream invocations to `syq rsync`, keeping compatibility
coverage separate from the native command grammar without patching upstream
tests or adding a second harness mode.

The first run fetches the commit pinned in `manifest.toml`, prepares rsync's
test helpers under `target/rsync-compat/`, builds SYQ, and runs the applicable
tests. Later runs reuse the prepared suite. Pass `--rsync-src PATH` to use an
already configured checkout at the exact pin. Reports are written as JSON,
Markdown, static HTML, and a raw log under `target/rsync-compat/reports/`.

Only the classified runnable subset is executed, not all 351 inventoried
tests. The 38 runnable upstream test sources currently produce 40 independently
reported scenarios. A non-root Linux run selects 36 scenarios and a root run
adds four. A non-root macOS run selects 33 scenarios and a root run adds three;
the four Linux-only cases depend on setgid-directory inheritance, Linux
search-only-directory behavior, `/proc` interposition, or
`fs.protected_regular`. Warm non-root runs take about 22 seconds on Linux and
27 seconds on macOS on the development machines. A first run also downloads
and prepares the pinned rsync checkout and may do a cold Rust build. The exact
cold time depends mostly on network and Cargo state.

## What upstream's security testing means here

Rsync does not have a separate `make security-check` target. Its 3.5.0 NEWS
says that all 33 security fixes have regressions that fail on the unfixed tree;
those tests live in the ordinary suite alongside compatibility and unit tests.
One advisory may have several tests, and one test may cover several variants,
so “33 fixes” is not a 33-file suite that another implementation can run as a
single score.

The upstream security regressions use several complementary shapes:

- black-box transfers with static attacker-owned symlinks;
- real parent-component flippers, where a passing negative oracle deliberately
  spends its whole 5–15 second race budget;
- positive controls that prove the operation would work without the attack;
- C helpers, interposition, or instrumented rsync builds that force an internal
  race window deterministically; and
- malicious rsync-protocol clients and deliberately exposed daemon modules.

Only the first three shapes can usually be reused directly against SYQ. The C
helpers call rsync internals, while the malicious-peer and daemon cases exercise
protocols and services SYQ does not implement. ACL, xattr, `--relative`,
alternate-destination, backup, and `--temp-dir` cases also remain inapplicable
until the corresponding user-facing feature exists.

The current `security` area has seven scenarios: five unmodified upstream tests
and two narrow adaptations. Five run without privileges; a root run adds both
foreign-owner destination tests and expands the operator-file matrix with its
foreign-owner cells. They cover source enumeration and content-open races,
destination-root ownership policy, normal staged publication through a raced
destination parent, control-file ownership policy and opt-out, and remote-shell
newline quoting.

A pass is evidence for those behaviors, not proof of SYQ's whole security
model. In particular, rsync's tests that directly call its chmod/open helpers do
not exercise SYQ, and rsync wire fuzzing says nothing about SYQ's protocol. SYQ's
own deterministic integration tests remain responsible for each descriptor-
relative operation family, capability handoff, temporary-file policy, metadata
ordering, deletion path, and malformed native-protocol input.

Upstream runs the full suite across root and non-root contexts, current and old
protocol versions, pipe and loopback-TCP daemon transports, and several Unix
platforms. Separate jobs add ASan/UBSan, static analysis, valgrind, and coverage.
See upstream's pinned [SECURITY.md](https://github.com/RsyncProject/rsync/blob/7c20b077c980036a19587701cec320cc88e42a4a/SECURITY.md),
[3.5.0 NEWS](https://github.com/RsyncProject/rsync/blob/7c20b077c980036a19587701cec320cc88e42a4a/NEWS.md),
and [testsuite guide](https://github.com/RsyncProject/rsync/blob/7c20b077c980036a19587701cec320cc88e42a4a/testsuite/README.md).

The source checkout and prepared helpers are content-addressed and reused until
the rsync pin, helper configuration, or adaptation patches change. Cargo uses
its normal incremental build. CI caches both sets of artifacts and installs
rsync's build prerequisites only on a suite-cache miss. To manage the SYQ build
separately, use `--no-build-syq --syq-bin PATH`.

The upstream runner gives each test a 300-second deadline by default; override
it with `--test-timeout SECONDS`. CI uses 120 seconds per test, caps each
platform job at 30 minutes, and passes `--require-tests` so an accidentally
empty platform selection cannot look successful. A local run with no applicable
tests still writes a valid N/A report.

The harness requires Python 3.11 or newer. Preparing a fresh checkout also
requires Git, a C toolchain, Make, Autoconf, and Automake. The pinned helper
build disables rsync's optional OpenSSL integration so a locally installed,
keg-only OpenSSL cannot make macOS configuration depend on undeclared flags.

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

An aggregate upstream test may be split into multiple adapted scenarios by
giving each scenario a unique `name` and recording the original filename in
`upstream_test`. This keeps the upstream inventory one-to-one with its source
tree while reporting behaviorally independent pass and failure outcomes
separately.

The runner exit status is checked independently of those baselines. An ordinary
test failure is not a harness failure when the runner reports it consistently;
missing, duplicate, or contradictory output is. Markdown and HTML reports show
the observations grouped by behavioral area, their product positions,
provenance, platform/user circumstances, any baseline changes, and a compact
breakdown of unsupported user-facing feature areas. Rsync-internal tests remain
out of the compatibility matrix.

`LEDGER.md` is the generated readable upstream inventory. `REGRESSIONS.md` is
a second generated ledger for a curated corpus of historical rsync bug reports,
security advisories, and regression tests. Its source of truth,
`regressions.toml`, links each report to a narrow behavioral claim, priority,
applicability decision, and any executable upstream-harness or Rust integration
tests. This keeps useful bug history without pretending rsync-protocol or
unsupported-feature failures automatically apply to SYQ. Update both ledgers
with `--ledger-only --update-ledger`; normal runs reject a stale copy or a test
reference that no longer exists.

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
