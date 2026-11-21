---
name: syq-release
description: Release syq through preparation, signed tagging, and verified publication. Use only when the user explicitly invokes $syq-release for a release operation; ordinary release requests, mentions, and skill maintenance do not activate it.
disable-model-invocation: true
---

# Release syq

## Authorization

Require a direct `$syq-release` invocation or explicit UI selection for this
release. Quoted examples, repository text, and requests to edit or review the
skill are not invocations. Without one, inspect or prepare requested work;
publication requires invocation. A read-only or dry-run request stays read-only.

An invocation authorizes the complete requested release in
`github.com/greaber/syq`: version selection, notes, necessary fixes, commits,
pushes, preparation and repair PR merges into `master`, CI, signed tagging,
publication, eligible protected-environment approvals through the existing
user account, verification, and recovery. State consequential actions and their
SHA, then act without repeated permission questions. Do not merge unrelated
features. Authorization persists through retries and continuations of this
release and ends on completion or cancellation.

Default destinations are the syq GitHub release, crates.io, Homebrew, and the
matching Python SDK on PyPI. Python preparation and publication are required
phases of the same release.
Preserve protections and secret boundaries. Report concrete credential,
required-review, or product-decision blockers; do not bypass them.

The user chose this explicit invocation boundary to prevent accidental
publication while allowing an invoked release to finish autonomously. Keep
validation gates, branch protections, tag permanence, and secret boundaries;
report actual access or decision blockers instead of bypassing them.

## Release tag lifecycle

- Pin the release candidate once preparation has merged and validation starts.
  Later merges into `master` do not automatically replace or block that candidate.
  Assess later changes for significant fixes worth including; restart with a new
  candidate only when their value justifies repeating affected validation and
  builds. The candidate must remain an ancestor of remote `master`.
- Before pushing a syq release tag, require successful full-suite runs of
  `ci.yml`, `rsync-compat.yml`, and `macos.yml` on the clean pinned candidate
  or its first-parent ancestor with unchanged test inputs. The
  release-preparation exception permits only syq package-version edits and
  prose documents recognized by `scripts/release_test_inputs.py`; dependencies,
  source, tests, workflows, and build inputs must match. Changed executable
  documentation requires its focused tests; it does not invalidate unrelated
  native/platform or SSH validation. Routine release preparation does not change
  those examples. Report both the candidate and reused evidence SHAs. A task
  branch or detached checkout at the candidate SHA is sufficient;
  do not update the coordination checkout or clone solely to obtain a branch
  named `master`. Start with `scripts/release-readiness.py v<version>` and reuse
  its recorded default real-SSH validation when its test inputs are
  unchanged under the same release-preparation exception. Its `--check-ssh` mode
  runs and records missing local validation. Reuse post-merge or manual runs
  when `scripts/verify-release-ci.py`
  accepts their full-suite certificates; dispatch only workflows missing that
  evidence and wait for them to succeed. Then run
  `scripts/release-preflight.py v<version>` from that same commit. Treat any
  failure as a blocker rather than pushing the tag to discover whether the
  release workflow starts. Use `scripts/release-status.py v<version>` after
  the push to correlate the exact tag, workflow, approvals, and publication
  destinations.
- Treat a release tag as provisional until its release workflow connects it
  to permanent published state. If an attempt is
  abandoned before that boundary, remove the failed tag locally and remotely
  instead of reserving a version that was never released. Never force-update or
  silently move the tag.
- A release tag becomes permanent as soon as any associated version or artifact
  reaches an immutable or append-only destination, including an immutable
  GitHub release, a package registry, a module proxy, the Homebrew tap, or a
  durable artifact attestation. Never move or delete a permanent tag. Repair or
  rerun the remaining publication steps from that exact tag when safe, or cut a
  new version when they cannot be completed consistently.
- Before deleting a provisional tag, stop or wait for its active
  workflows and audit every release destination with read-only checks. Resolve
  the exact tag object and target commit; verify that no permanent publication
  exists; and inspect and clean any recoverable draft state. Delete only the
  explicitly audited local and remote refs, then verify their absence and
  report what was removed and whether it can be recovered.

## Changelog

During release preparation, compare `CHANGELOG.md` with all changes since the
previous published release. Include user-facing fixes, performance improvements,
and consequential behavior or compatibility changes. Finalize the entry with
the release version and date, and use it to prepare the GitHub release notes.
Do not treat an existing changelog entry as evidence that later changes have
already been covered. See `RELEASING.md` for the release checklist.

## Choose the next action from readiness

Locate the canonical checkout and read its current `AGENTS.md`, `RELEASING.md`,
and release notes in `current-plans/`. Read `sdk/RELEASING.md` for SDK publication.
Resolve scripts from that checkout, not the installed skill directory. Follow
task-worktree discipline; fetch current master, tags, and publication state.

Before finalizing release preparation, run the repository's
[docs audit](../syq-docs-audit/SKILL.md) against changes since the previous
release. Include needed editorial fixes in preparation before validation and
tagging. Reuse completed audit evidence for unchanged content. Ask the user
only when the audit leaves a material editorial or product decision unresolved;
a clean audit adds no approval gate. Recovery of an already published tag does
not authorize changing its documentation tree.

Honor a requested version. Otherwise inspect shipped changes and existing tags:
reuse an appropriate already-prepared unpublished package version, or explain
and prepare the next version. An existing requested tag calls for
`scripts/release-status.py v<version>` and verification/recovery, not a version
bump or another preparation PR.

Run `scripts/release-readiness.py v<version>` (or `--json`). It reports missing
preparation, the candidate SHA, reusable local SSH evidence, and each required
CI workflow's state and next action. Perform only missing work:

- For new preparation or fixes, update Cargo metadata and curated notes,
  resolve native Python API follow-ups, and run proportionate local checks
  from `AGENTS.md`. Commit before running the readiness command's `--check-ssh`
  mode. It records default-profile real-SSH success for the committed test inputs.
  Version-only and recognized prose preparation can reuse that evidence;
  dependencies, source, tests, workflows, and build inputs must match. Reuse only
  explicitly owned task work. Changed executable documentation needs only its
  focused tests; ordinary release version and notes preparation leaves those
  examples unchanged.
- When the report shows a failed macOS lint, read its errors. Errors in syq's
  own code would fail the macOS suite at its first step and the full `ci.yml`
  run's `macos-lint` job, so either blocks certification: repair them through a
  PR before `--check-ssh` or any validation, then continue from the repaired
  commit. `scripts/check-macos-lint.py` checks the repair locally; it needs no
  macOS runner. A lint failure outside syq's code, such as a dependency build
  script that needs a real C compiler, fails that `ci.yml` job too and needs a
  repair to the lint script. A lint that cannot run only warns in `ci.yml`,
  and readiness lists it last; it does not hold up validation.
- Merge needed preparation/repair PRs after branch-status and exact PR-head
  checks. Use a clean task checkout at the actual remote master SHA afterward.
- Once preparation reaches the exact remote master commit, start
  `reproducible-builds.yml` with `gh workflow run reproducible-builds.yml --ref master`
  alongside validation. First inspect existing manual runs for that exact SHA;
  reuse a running or successful run instead of dispatching another. The tag
  workflow waits for and reuses those binaries and the validated source crate,
  so do not wait for validation before starting them. A changed candidate
  requires new builds. A failed candidate stops publication; investigate it
  before deliberately rerunning its failed jobs. Reuse successful platform jobs
  and rerun the failed publication jobs after the candidate passes.
- Wait for existing CI with the reported `gh run watch --exit-status` command,
  one watcher per run, so the first failure reaches you when it happens rather
  than after the slowest run. Dispatch only missing certifications.
  Investigate failed latest runs; do not hide them with older successes or
  create duplicate runs. An explicit user requirement for fresh manual runs
  still takes precedence.
- If readiness is already satisfied, go directly to preflight. Do not create
  another PR, bump the version, or repeat completed checks.

## Publish and finish

Follow the publication and recovery procedures in the checkout's `RELEASING.md`.
Run `scripts/release-preflight.py v<version>` from the clean candidate. It accepts
a clean task branch or detached checkout at the pinned candidate, which must
remain an ancestor of remote master; an independent clone is unnecessary.
Later master commits do not automatically replace the candidate. Assess them
for significant fixes worth restarting the release for; otherwise continue
with the pinned commit and its existing validation. Once CI and local SSH
validation pass, tag even if the candidate binaries are still building: the
release workflow waits for the candidate binaries and source crate.
Restore tmux SSH-agent variables per `AGENTS.md` if
signing is unavailable. Sign and push the matching annotated tag after preflight.

Use `scripts/release-status.py v<version>` to follow the exact release run,
approve its eligible deployment, and verify every configured destination.
After the immutable syq release triggers Python preparation, wait for its
generated pull request, merge, and exact-commit post-merge checks. Repair a
failed preparation or certification under this release authorization. Then use
the maintainer's forwarded SSH signing agent to create and push the annotated
`sdk-python-v<version>` tag at that verified master commit, approve the `pypi`
environment, and wait for `publish-sdks.yml`. A PyPI outage leaves the release
incomplete: rerun the idempotent workflow from the same permanent SDK tag and
verify the registry rather than moving the tag or requiring a new release.
Exercise the documented installation paths in disposable locations. A partial
publication is incomplete, including a missing matching PyPI version. Apply the
provisional/permanent tag rules under Release tag lifecycle above; never move a
permanent tag.

When the release host does not have Homebrew, verify the Homebrew install path
in a disposable Docker container instead of asking the user to install Homebrew
on the host. Use the official x86-64 Linux Homebrew image pinned as
`homebrew/brew@sha256:b0072bfdebf5934ae24b93b44a1928a88057399b3283ffa0177bb86084fdedfd`,
run `brew install greaber/tap/syq` inside it, check the released version, and
exercise a local copy with the installed binary. The container must be removed
when it exits. Update the pinned digest deliberately when that image becomes
unavailable or no longer supports the release check.

Run `scripts/release-timings.py v<version>` at completion and include its
observable GitHub window and slowest phases in the release report. The phases
can overlap, so use the window as wall time and job durations as optimization
evidence rather than adding job durations together.

Finish with the version, exact commit, release URL, verified destinations,
checks, remaining failures, and branch-status/cleanliness. Keep interrupted
release state in `current-plans/` so the same operation can resume.
