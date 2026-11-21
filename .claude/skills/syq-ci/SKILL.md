---
name: syq-ci
description: syq CI mechanics - dispatching suites and the macOS workflow, resolving a failed dispatched check that blocks a PR, acknowledging a failed nightly or post-merge master run after its repair, and running one focused check on a Linux or macOS runner. Use when dispatching CI, when a CI or dispatched check fails, or when a test must run on another platform.
---

# syq CI mechanics

The rules for when to run what are in `AGENTS.md` under Verification. This
skill holds the commands and their details.

## Dispatching suites

```bash
gh workflow run ci.yml --ref <task-branch> -f suites='real-ssh s3'
```

`suites` takes the names listed in `SUITES` in `scripts/ci-scope.py`. Report
such checks as running in your reply; GitHub keeps their results, so the pull
request needs no update when they finish. They keep running if the pull
request merges. A later run with the same `suites` value on the branch cancels
the earlier run of those jobs, so dispatch once the change has settled rather
than after every commit. A check is a job name, and a combined selection names
the `rust` job after all its parts, so to clear a failed check, dispatch the
same `suites` value again or rerun the failed run.

The macOS suite is `gh workflow run macos.yml --ref <task-branch>`. Each run
occupies a macOS runner for half an hour or more. On a task branch it runs SDK
packaging and the release tooling suites only when the branch changes them or
with `-f complete=true`, and a newer dispatch on the same branch cancels the
older run.

## The `dispatched-checks` merge gate

Pull requests do not start automated test workflows. Failed checks dispatched
on the branch fail the pull request's `dispatched-checks` status, which branch
protection requires, so GitHub refuses the merge until a later run of each
failed check passes or its failure is explicitly resolved. Checks still running
do not block. The `merge-despite-failures` label overrides all failures. The
gate cannot tell who caused a failure, so it also blocks on failures that
already happen on `master`. Adding the label is the user's decision.

## Resolving a failed dispatched check

`AGENTS.md` says when you may resolve a failure without asking. Use the job ID
at the end of its GitHub job URL:

```bash
GITHUB_REPOSITORY=greaber/syq scripts/dispatched-checks-status.py <pr> \
  --resolve-job <job-id> --reason 'Why this failure no longer blocks' \
  --replacement <https-url>
```

The reason is one line of at most 140 characters; the replacement URL is
optional. This records a separate GitHub status with the author and time, then
refreshes the gate. It covers only that PR and exact failed job, not other or
future failures. The command needs permission to write commit statuses.
Resolutions do not count as passing tests or release validation; the original
failures remain visible.

## Acknowledging a repaired master run

After repairs merge into `master`, stop repeated reminders for a failed nightly
or post-merge run once all of that run's failures are accounted for by the
repairs and focused checks passed. A full nightly rerun is not required to
acknowledge those repairs. Record the reason and link to the merged repair
(including its validation) or replacement evidence:

```bash
scripts/branch-status.py --address-master-run <run-id> \
  --reason 'Failures addressed by the merged repair; focused checks passed' \
  --fix <https-url>
```

This is authorized as part of completing the repair. It records a separate
GitHub status for that exact run attempt; the original failure remains visible,
and a new failed run or rerun is reported normally. It only suppresses repeated
reminders, without changing PR gates, test conclusions, or release validation.
Do not acknowledge a whole run while some failures still need repair.

## Focused checks on a Linux or macOS runner

A workflow lacking a focused option is not a reason to run its full suite.
For arbitrary checks on a Linux or macOS runner, use the manual focused
runner from a clean, pushed task branch:

```bash
scripts/run-focused-check.py --runner macos --cargo-cache -- \
  cargo nextest run --locked --bin syq --run-ignored all --no-tests fail \
  -- --exact 'module::tests::name'
scripts/run-focused-check.py --runner linux --script target/check.sh
```

The script file is local and need not be committed; it may contain setup and
multiple commands. It runs with Bash `-euo pipefail` in the checked-out
repository. With `--cargo-cache`, the runner also installs the pinned
cargo-nextest. Use pinned setup commands for other tools; the runner does not
install all SDK toolchains or reproduce another workflow's setup
automatically. For a workflow setup regression, reproduce the relevant setup
as well as the failing command. Inputs and logs are public: do not include
secrets.

The helper selects the current remote branch, pins its checkout commit,
prints the SHA and run URL, and watches that exact run through
`gh run watch`; run it in the background when you do not need the result
before replying. Checks run on GitHub-hosted runners; `--ref` explicitly tests
another pushed branch or tag; `--timeout` changes the default 15-minute limit.
Only enable `--cargo-cache` for checks needing Rust builds.
No builds or test suites run implicitly, and these checks do not certify a
full suite for release. Add reusable focused checks when repeated use
justifies them rather than adding a permanent option for every repair.

For an exact Rust test on another platform, pass `--run-ignored all` and
`--no-tests fail` as in the first example: the test runs even where it is
marked ignored, and the check fails when the name does not exist on that
platform. Replace `--bin syq` with `--test <target>` for an integration test.
