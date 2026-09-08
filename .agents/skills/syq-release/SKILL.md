---
name: syq-release
description: Release syq through preparation, signed tagging, and verified publication. Use only when the user explicitly invokes $syq-release for a release operation; ordinary release requests, mentions, and skill maintenance do not activate it.
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
phases of the same release; JavaScript and Go SDK releases remain separate.
Preserve protections and secret boundaries. Report concrete credential,
required-review, or product-decision blockers; do not bypass them.

## Choose the next action from readiness

Locate the canonical checkout and read its current `AGENTS.md`, `RELEASING.md`,
and release notes in `current-plans/`. Read `sdk/RELEASING.md` for SDK publication.
Resolve scripts from that checkout, not the installed skill directory. Follow
task-worktree discipline; fetch current master, tags, and publication state.

Honor a requested version. Otherwise inspect shipped changes and existing tags:
reuse an appropriate already-prepared unpublished package version, or explain
and prepare the next version. An existing requested tag calls for
`scripts/release-status.sh v<version>` and verification/recovery, not a version
bump or another preparation PR.

Run `scripts/release-readiness.py v<version>` (or `--json`). It reports missing
preparation, the candidate SHA, reusable local SSH evidence, and each required
CI workflow's state and next action. Perform only missing work:

- For new preparation or fixes, update Cargo metadata and curated notes,
  resolve native Python API follow-ups, and run proportionate local checks
  from `AGENTS.md`. Commit before running the readiness command's `--check-ssh`
  mode. It records default-profile real-SSH success for that entire committed
  tree; an identical-tree merge reuses it. Reuse only explicitly owned task work.
- Merge needed preparation/repair PRs after branch-status and exact PR-head
  checks. Use a clean task checkout at the actual remote master SHA afterward.
- Wait for existing CI with the reported `gh run watch --exit-status` command.
  Dispatch only missing certifications. Investigate failed latest runs; do
  not hide them with older successes or create duplicate runs. An explicit
  user requirement for fresh manual runs still takes precedence.
- If readiness is already satisfied, go directly to preflight. Do not create
  another PR, bump the version, or repeat completed checks.

## Publish and finish

Follow the publication and recovery procedures in the checkout's `RELEASING.md`.
Run `scripts/release-preflight.sh v<version>` from the clean candidate. It accepts
a task branch or detached checkout matching remote master; an independent clone
is unnecessary. If master advances before tagging, reassess the candidate and
rerun readiness/preflight. Restore tmux SSH-agent variables per `AGENTS.md` if
signing is unavailable. Sign and push the matching annotated tag after preflight.

Use `scripts/release-status.sh v<version>` to follow the exact release run,
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
provisional/permanent tag rules in `AGENTS.md`; never move a permanent tag,
including any pushed Go module tag.

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
