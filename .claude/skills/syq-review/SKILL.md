---
name: syq-review
description: How to review a syq pull request - which commit to review, how to report scope the task did not call for, how to weigh and group findings, and what not to run. Use whenever you review or re-review a syq PR, including as a reviewer started by scripts/agent-coordination.py.
---

# Reviewing syq pull requests

Your report goes to the agent that requested the review, which decides what
to change and what to tell the user. The user does not read pull requests or
review reports. Probe hard for problems: that is the job. You are not
expected to be obeyed, and a change that addresses none of your suggestions
can still be right.

## Scope the task did not call for

A pull request description and its commit messages are the implementing
agent's own account of the work. They show what the agent intended; they are
not evidence that the user asked for or agreed to it.

When reviewing, separate what the task called for from what the PR adds
beyond it: new workflows or triggers, recurring CI or hosting cost, new
policy or defaults, broadened guarantees, or behavior in unrelated areas.
Report each such addition at the top of the review, stating its cost or
consequence, even when the PR explains it and even when the implementation is
sound. Do not file it as a deliberate choice that needs no action. The
requesting agent must take it to the user, who decides whether the expansion
stays; "the PR says it is intentional" is not that decision.

## Review reports

- Group items by the action they need: scope beyond the task, defects worth
  fixing before merge, suggestions and observations, and fine as is. Lead
  with what needs action and keep confirmations brief and last.
- For each finding, give the concrete situation that triggers it, how likely
  that is, and what goes wrong. Without a realistic situation it is an
  observation, not a defect. Do not overstate a finding to get it acted on,
  and do not propose a fix larger than the problem.
- Label each finding as introduced by the PR or pre-existing. Only findings
  the PR introduced are for the implementing agent. Report pre-existing
  issues separately, and do not carry them into later review passes;
  otherwise each pass widens the change into code the task never touched.
- In a later round, check the changes made since your last round and the
  findings the implementer agreed to fix. Raise a new finding on code that
  has not changed since you reviewed it only when it is serious: wrong
  results, data loss, or a security hole. Do not repeat a finding the
  implementer declined with a reason, unless the reason is wrong; then say
  why once.
- Mention performance opportunities you notice, whether or not they block the
  PR or fall within its scope, with the mechanism and a way to measure the
  gain. Startup latency and throughput are core to the product.
- Do not flag a missing `CHANGELOG.md` entry on an ordinary PR. The changelog
  is brought up to date during release preparation.
- Do not run test suites, lints or CI during a review; the implementing
  agent and CI own them. Take CI state from `scripts/pr-checks.py` (without
  `--check`), not from the description. Note results whose SHA is older than
  the reviewed SHA when later commits could change them, and report failed
  checks. Checks still running do not block merge. If a check that matters
  for the change has not run, say which and why, and leave dispatching it to
  the implementing agent. Run code only to examine behavior that no existing
  test covers, such as a focused reproduction of a suspected defect in a
  disposable directory, and build only as that needs. If an existing test
  looks wrong, report it rather than running it.

## PR review freshness

- For any GitHub PR review or re-review, never assume the current checkout
  `HEAD` is the latest PR code. Resolve the PR's `headRefName`, `headRefOid`,
  and head-repository identity (owner and repository) first. Treat the GitHub
  `headRefOid` as authoritative unless a fresher local commit is verified as
  described below.
- In this repo's multi-worktree review workflow, also resolve the local branch
  ref for the PR's `headRefName`. A detached review worktree can stay pinned
  to an old commit even when the branch ref has moved.
- A matching branch name is not proof that a local ref belongs to the PR,
  especially for fork PRs. Treat a local ref as PR code only when its worktree
  ownership is explicit and its repository identity and ancestry relative to
  `headRefOid` have been verified.
- If the local ref is missing, behind the GitHub head, divergent from it, or
  cannot be tied unambiguously to the PR's head repository, review the GitHub
  `headRefOid`. Fetch that exact head into a dedicated review ref or worktree
  when necessary, without overwriting an unrelated local branch, and report
  the discrepancy.
- If local and GitHub refs match, review that SHA. If the local ref is ahead,
  use it only when the worktree belongs to the task and the GitHub
  `headRefOid` is its ancestor; tell the user that GitHub is stale and either
  review the unpushed local tip explicitly or wait for it to be pushed.
- Skip a repeated review only when the chosen target SHA matches the last SHA
  that this same agent reviewed for this PR in its own conversation history
  (including preserved context when resuming that conversation). Report that
  the PR is unchanged since this agent's review and name the SHA. An explicit
  user request to review it again overrides this shortcut.
- Use only that agent's own conversation history to establish its previous
  review. Do not use GitHub reviews, comments, review decisions, shared review
  notes, or another agent's review history to decide to skip. Agents may share
  a GitHub account, and multiple agents must be able to review the same commit
  independently. If this agent has no record of its own prior review, proceed
  with the review.
- Always state the exact reviewed SHA and whether it came from the local
  branch tip or the GitHub PR head.
