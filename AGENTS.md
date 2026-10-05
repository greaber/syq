# Agent guidance

## Worktrees

Start any task that may change the repository in a task-specific git worktree,
before investigating or editing code for that task. Treat the primary checkout
as a coordination checkout on `master`; do not introduce working-tree changes
there. Do not edit tracked files, create commits, or switch branches there. If
it is already dirty, preserve and report the existing changes: inherited
dirtiness does not block creating or using a separate task worktree, and is not
permission to clean, reset, or stash them. Apart from administering branches
and worktrees, only writes to gitignored files are normally allowed there.

`master` means the branch on GitHub. The coordination checkout's local
`master` and its files change only when the user occasionally pulls by hand,
so they are often stale. Do not use them to answer questions about `master`,
as a base for new work, or for comparisons, and leave pulling to the user.
Run `git fetch origin master` and read `origin/master` instead, for example
with `git show origin/master:<path>`, `git log origin/master`, or a detached
worktree for broader reading.

Check `git status` and `git worktree list` before choosing a worktree. A branch
and worktree should correspond 1:1 with a task or pull request. Also check the
primary checkout's `current-plans/` for plans or handoff notes that cover the
topic. The normal setup from the primary checkout is:

```bash
git fetch origin master
git worktree add --no-track .worktrees/<task> -b <task> origin/master
ln -s ../../current-plans .worktrees/<task>/current-plans
cd .worktrees/<task>
```

`--no-track` keeps `origin/master` from becoming the task branch's upstream.
Keep `current-plans/` shared by symlinking it from task worktrees as shown
above; do not copy it. This keeps short-lived planning state visible across
conversations and worktrees.

Use plain git commands as shown above. Do not use the `EnterWorktree` or
`ExitWorktree` tools; they are denied in `.claude/settings.json`.

Continue in an existing worktree only when you created it for the current task
or the user explicitly identified it as the target. Never infer ownership from
a plausible branch name. Before every file edit or write, confirm that
`git rev-parse --show-toplevel` points at the task worktree.

Do not rely on the shell's working directory carrying over between tool
commands; some agent runtimes reset it to the primary checkout, and parallel
commands can share it. Begin each command that touches a worktree with an
explicit `cd` into it, and do not modify two worktrees from parallel commands.

## SSH from long-lived tmux sessions

A long-lived tmux server can retain the working SSH-agent forwarding
environment while a newly attached shell has stale or missing `SSH_*`
variables. Before concluding that a cluster host is inaccessible or that
SSH authentication is broken, restore those variables in the same shell
that will run `ssh`:

```bash
_syq_tmux_env="$(tmux show-env -s)" &&
  _syq_tmux_ssh_env="$(
    grep -E '^(SSH_|unset SSH_)' <<<"$_syq_tmux_env"
  )" &&
  eval "$_syq_tmux_ssh_env" &&
  unset _syq_tmux_env _syq_tmux_ssh_env
```

Each agent tool command starts a new shell, so prefix the relevant SSH
command with this restoration when necessary.

## Long-running commands and readiness

- Use the repository's readiness or wait command when one exists. Do not replace it with an unbounded `until`/`while` loop.
- Every custom poll must have a hard deadline, emit periodic progress, and report the last observed state when it times out.
- Treat exit status or structured output as the machine-readable contract. Do not `grep` human-readable status text, which may be written to a different stream or change independently of the contract.
- Keep long-running command output live. Do not pipe it directly through buffering or early-exit consumers such as `tail`, `head`, or `grep -q`; use the repository's foreground runner or `tee` when output also needs to be captured.
- If the command runtime moves a live command into the background, continue monitoring the original task or session handle. Do not launch a second copy. When stopping an owned command, terminate and verify its whole process group so children cannot survive as stale workers or lock holders.
- For asynchronous CI, use the repository's CI monitor/wait mechanism instead of shell polling.

## Documentation over agent memory

Keep documentation focused on current user-facing behavior. Do not create or
restore `design/`, or add investigation reports, benchmark dumps, or experiment
diaries to this repository. PR descriptions should explain the actual change
and relevant checks, without histories of abandoned work.

Keep `current-plans/` limited to brief current task state and next actions.
At task completion, check the PR's current state and remove obsolete notes;
first preserve unfinished agreed work in its continuing task's handoff. Do not
delete notes another conversation is actively updating. Keep generated logs,
binaries, and benchmark dumps in the task's ignored `target/`, linked from the
note; do not duplicate PR bodies or CI dumps here. Guidance every session needs
belongs here in `AGENTS.md`.

Do not use an agent runtime's private memory (for example Claude Code's
per-project memory directory) for this project, even when the runtime prompts
you to save something. It is hard to audit, other agents cannot read it, and
it goes stale unnoticed. If you find existing private memory for this project,
report what it contains instead of relying on it.

`current-plans/` notes are agent-written handoff state. They are not evidence
of what the user asked for or approved.

This repository is public. Keep account identifiers, credential locations,
and details of private infrastructure out of commits, pull requests, and
documentation, including this file.

Write guidance in this file as the current rule with a brief reason. Leave out
dates and accounts of how the rule came about.

## GitHub issues

The user reserves GitHub issues for outside contributors to communicate with
the project. Agents must not create issues unless the user explicitly asks
for an issue to be created. Discovering a bug, deferring work, or identifying
a follow-up does not authorize opening an issue; report it to the user in
the conversation instead.

## Branch synchronization and handoff

- Open regular pull requests by default. Use a draft only when the user asks
  or there is a concrete reason to prevent that particular PR from being
  merged. The user prefers to review ordinary task work without a draft gate.

- Durable task work belongs in commits on the task branch. Changes intended for
  `master` go through a pull request; do not commit them directly on `master` or
  merge task branches from the coordination checkout. Do not merge a pull
  request unless the user explicitly asks. An explicit `$syq-release`
  invocation authorizes release preparation and necessary repair PRs into
  `master` under the release authorization section below.
- When the conversation is unambiguously about completing the pull request for
  the agent's own task branch, a bare instruction such as "merge" counts as an
  explicit request to merge that pull request into its configured base branch.
- Merging any other branch or pull request into `master`, including a dependency
  or the base of a stacked pull request, requires an explicit instruction that
  names both the branch or pull request and `master` as the destination. For
  example, while working on pull request #16, "merge pull request #7" does not
  authorize merging pull request #7 into `master`; ask when the intended
  destination is unclear.
- Before rebasing, resetting, or otherwise synchronizing a task branch with
  advancing `master`, require its worktree to be clean, including staged and
  untracked changes. Prefer a checkpoint commit on the task branch. Never use
  reset to discard task work. Fetch first and synchronize with `origin/master`,
  not local `master`.
- If a safety stash is genuinely necessary to make the worktree clean, give it
  a task-specific name and include untracked files. Restore it after the
  synchronization, verify the resulting worktree, and drop it after the
  corresponding work is committed. Report any retained stash and why it is
  still needed in the handoff.
- When reporting work, state the branch and exact short commit SHA, whether
  the worktree is clean, which checks passed or failed, and which are still
  running. Passing tests are not a precondition for reporting a change,
  opening a pull request, or asking for review: report a known failure with
  the work rather than holding the work back. Before merge, fix failures the
  change causes, unless the user decides to merge anyway. A failure that
  already happens on `master` does not block the work; name the `master` run
  that shows it. See Verification for how much to run before replying.
- List the checks you ran locally in the pull request description as a table
  with one row per check: the exact command or test name, the short SHA it ran
  at, and its result. Add a row only once the check has finished, so no row
  needs a later update. The table records what ran where. A new commit does
  not by itself call for rerunning checks; keep each row's SHA as the commit
  the check actually ran at.
- Leave CI checks out of the description. GitHub records them, and the
  scripts below report their current results; a result written into the
  description goes stale when nobody is left to update it. When the reason for
  dispatching a particular suite is not obvious, say why in the prose.
- Run `scripts/branch-status.py` from the task worktree before opening a pull
  request, before asking for review, and before merging, and include its output
  in the report. It fetches `origin/master` and prints the branch SHA,
  cleanliness, and position relative to it, the pull request's GitHub head and
  check results, and the latest post-merge and nightly `ci`, `rsync-compat`,
  and `macos` runs on `master`. Post-merge runs select checks by changed
  paths, so a green one does not show that an earlier failure was fixed; the
  nightly run executes the full suite when test inputs changed. The script
  lists a red post-merge or nightly `master` run, and failures left by
  recently merged branches, as notes without failing; report unresolved notes
  even when the current task did not cause them. Do not repeat master failures
  marked `addressed`; the linked repair has already been reported. A new failed
  run or rerun needs attention again. A failed check in a run
  dispatched on this branch makes it exit 1 until a later run of that check
  passes or that exact failed job is explicitly resolved as described below.
  It lists the latest result of each check dispatched on the branch
  and the runs still unfinished; report CI state from this output.
  `scripts/pr-checks.py <number>` lists the same for any pull request, open or
  merged, from any checkout. `--check` also runs the Rust baseline below, and
  `--json` prints the same facts for scripting.
- Pull requests do not start automated test workflows. The same failed
  dispatched checks fail the pull request's `dispatched-checks` status, which
  branch protection requires, so GitHub refuses the merge until a later run of
  each failed check passes or its failure is explicitly resolved. Checks still
  running do not block. Resolve individual mistaken or superseded checks using
  the command under Verification; their original failures remain visible.
  The `merge-despite-failures` label overrides all failures. The gate cannot tell
  who caused a failure, so it also blocks on failures that already happen on
  `master`. Adding the label is the user's decision: when a requested merge is
  blocked, report each failure, say whether `master` shows it too, and ask.
- Before removing a worktree or branch, require a clean worktree, no retained
  task-related stash, and no commits that still need integration. An ancestry
  result such as `git branch --merged` says nothing about uncommitted files.

## Release authorization

Releases require the user to explicitly invoke `$syq-release` or select that
skill in the UI. The skill is committed at
[`.agents/skills/syq-release/SKILL.md`](.agents/skills/syq-release/SKILL.md)
with implicit invocation disabled. An ordinary “cut a release” request,
release-related code, a merge instruction, or a request to create/edit the
skill does not activate it. Without an invocation, agents may inspect release
state and prepare requested changes, but must not create or push release tags,
publish packages or releases, or approve publication deployments. Do not work
around the gate by using release commands directly.

Invoking the skill authorizes the complete requested release: preparation,
required fixes, commits, pushes, merging release preparation and necessary
repair PRs into `master`, CI, signed tagging, publication, eligible environment
approvals, verification, and recovery within the tag-lifecycle rules. Do not
ask for further user approvals for these steps. This is a scoped exception to
the general PR merge rule, not permission to merge unrelated feature work.
Authorization continues through retries and resumed turns for the same release
and ends when it completes or is cancelled. Another release requires another
invocation. Read-only or dry-run invocations stay within their stated scope.

During release preparation, compare `CHANGELOG.md` with all changes since the
previous published release. Include user-facing fixes, performance improvements,
and consequential behavior or compatibility changes. Finalize the entry with
the release version and date, and use it to prepare the GitHub release notes.
Do not treat an existing changelog entry as evidence that later changes have
already been covered. See `RELEASING.md` for the release checklist.

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
  those examples. Report both the candidate and reused evidence SHAs. A task branch or
  detached checkout at the candidate SHA is sufficient;
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

## Always report the commit you are talking about

- Any status report about branch or PR work states the short SHA it refers
  to: what you just pushed, what CI ran against, what you are about to
  change. "PR #123 is green" is not actionable; "PR #123 is green at
  `ab12cd3`" is.
- This pairs with the reviewer-side rule below. When the working agent and
  the reviewing agent both name a SHA, the reader can tell at a glance
  whose turn it is: same SHA means the review covers the current work,
  different SHAs mean one of them is behind and needs to act.
- State the SHA even when nothing changed — "unchanged at `ab12cd3`" is
  the fact the reader needs to route the next step.

## Acting on review feedback

Assess every finding and observation on its merits. "Pre-existing", "out of
scope", "nonblocking", and "optional" describe context, not importance; none
is a reason to dismiss a point without consideration. Keep defects, suggestions,
and observations distinct, and discuss their value rather than treating every
comment as a change request. A worthwhile observation may belong in this PR,
in separate work, or need no change; decide that explicitly. Respect an explicit
user decision to exclude a topic, but do not infer exclusion from reviewer labels.

Reconsider the underlying requirements as part of this assessment, using the
principles below. Fix directly only independently confirmed, worthwhile problems
with simple, straightforward fixes, no tradeoffs that would benefit from
discussion, and no unresolved question about the requirements. For anything else,
discuss the evidence, value, alternatives, and requirements with the user
before implementing that finding.

The user may forward review from a reviewer without having understood it or even
without having read it. Just because a point appears in a review pasted directly by
the user does not mean that the user agrees with it. Similarly, the reviewer is just
another agent, and the reviewer's job is to find possible issues with the work. Many
issues raised by the reviewer might actually best be addressed by doing nothing even
though the reviewer was not wrong about how the code works.

## Reviewing scope the user did not request

A pull request description and its commit messages are the implementing
agent's own account of the work. They show what the agent intended; they are
not evidence that the user asked for or agreed to it. The user often has not
seen the change before the review.

When reviewing, separate what the task called for from what the PR adds
beyond it: new workflows or triggers, recurring CI or hosting cost, new
policy or defaults, broadened guarantees, or behavior in unrelated areas.
Report each such addition at the top of the review as a decision for the
user, stating its cost or consequence, even when the PR explains it and even
when the implementation is sound. Do not file it as a deliberate choice that
needs no action. The user decides whether the expansion stays; "the PR says
it is intentional" is not that decision.

## Review reports

- Group items by the action they need: worth addressing before merge,
  decisions for the user with a recommendation, and fine as is. Say whether
  each item is a problem, a good thing, or neutral. Lead with what needs
  action and keep confirmations brief and last.
- Label each finding as introduced by the PR or pre-existing. Only findings
  the PR introduced are for the implementing agent. Report pre-existing
  issues to the user separately, and do not carry them into later review
  passes; otherwise each pass widens the change into code the task never
  touched.
- Mention performance opportunities you notice, whether or not they block the
  PR or fall within its scope, with the mechanism and a way to measure the
  gain. Startup latency and throughput are core to the product.
- Do not flag a missing `CHANGELOG.md` entry on an ordinary PR. The changelog
  is brought up to date during release preparation.
- Do not repeat checks the pull request lists as passed, or CI checks that
  `scripts/pr-checks.py` shows as passed or unfinished; the implementing agent
  owns those. Take CI state from that script, not from the description. Note
  results whose SHA is older than the reviewed SHA when later commits could
  change them, and report failed checks. Checks still running do not block
  merge. If a check that matters for the change has not run, say which and
  why; dispatch it in CI when that is practical.

## PR review freshness

- For any GitHub PR review or re-review, never assume the current checkout `HEAD` is the latest PR code. Resolve the PR's `headRefName`, `headRefOid`, and head-repository identity (owner and repository) first. Treat the GitHub `headRefOid` as authoritative unless a fresher local commit is verified as described below.
- In this repo's multi-worktree review workflow, also resolve the local branch ref for the PR's `headRefName`. A detached review worktree can stay pinned to an old commit even when the branch ref has moved.
- A matching branch name is not proof that a local ref belongs to the PR, especially for fork PRs. Treat a local ref as PR code only when its worktree ownership is explicit and its repository identity and ancestry relative to `headRefOid` have been verified.
- If the local ref is missing, behind the GitHub head, divergent from it, or cannot be tied unambiguously to the PR's head repository, review the GitHub `headRefOid`. Fetch that exact head into a dedicated review ref or worktree when necessary, without overwriting an unrelated local branch, and report the discrepancy.
- If local and GitHub refs match, review that SHA. If the local ref is ahead, use it only when the worktree belongs to the task and the GitHub `headRefOid` is its ancestor; tell the user that GitHub is stale and either review the unpushed local tip explicitly or wait for it to be pushed.
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
- Always state the exact reviewed SHA and whether it came from the local branch tip or the GitHub PR head.

## Working on syq

- [`PRINCIPLES.md`](PRINCIPLES.md) records the user's core product principles.
  Check a design against it before implementing, and raise any conflict first.
  Only the user decides its contents; propose a change in a pull request and
  say so at the top.
- `README.md` and the documents under `docs/` are the user-facing contract;
  `README.md` is a brief front door and `docs/` is the source of the
  documentation site published with GitHub Pages (mdBook, configured by
  `book.toml`; every page must be listed in `docs/SUMMARY.md`;
  `scripts/check-doc-links.py` checks links). `docs/reference.md` carries the
  detailed behavior. Write these documents directly and conversationally, in
  plain words; a reader should not need project jargon such as "retained" or
  "the ordinary engine" to follow them. The code is authoritative for
  everything else.
- Routinely reconsider whether requirements are actually required and how much
  they matter; no special reason or failure is needed to ask. Distinguish the
  user's goals from assumptions, design choices, and incidental safeguards.
  A casual request or a check intended to catch common user mistakes must not
  silently become a guarantee covering every possible case.
- Weigh a scenario's likelihood and consequences against the complexity,
  maintenance cost, and disadvantages of preventing it. The fact that a case
  can occur does not by itself establish that it needs prevention; a rare case
  can still matter greatly when its consequences are serious. When a small
  safeguard starts requiring substantial machinery, discuss whether to narrow
  it, accept a limitation, change the requirement, or choose another design.
  Bring consequential choices to the user before implementing them; do not
  silently expand the scope or drop agreed behavior.
- Prefer one clear implementation. Add fallbacks or compatibility paths only
  for a concrete scenario or consumer that needs them.
- Write repository tooling (CI scope, release, status, and test scripts) in
  Python using only the standard library, run with the interpreter pinned by
  `scripts/setup.sh`. CI and the release workflows use that interpreter too,
  so the tooling needs no separate compatibility floor for older Python
  releases. The exception is `tests/real-ssh/*.py`: those scripts run inside
  the Debian test containers and must work with that image's `python3`. Use
  portable shell only for code that runs on users' machines or arbitrary
  hosts (the generated installer and `scripts/try-benchmark.sh`), code that
  must run before pinned tools exist (`scripts/setup.sh`), the real-SSH
  container scripts, and thin wrappers that only run other commands, such as
  the release runners' Nix and build steps. CI and release tooling is too
  complex to maintain well in Bash, so do not spend effort on Bash 3.2
  compatibility for development scripts.
- Keep CLI behavior, help text, `README.md`, `docs/`, and integration tests in
  sync. A behavior change lands in `docs/reference.md` (or the topical
  document that owns it), not in a new README section.
- `README.md` and `docs/` are written for users. They describe what the code
  on `master` does. Plans, roadmap items, design directions, internal status,
  unreleased or unvetted components, and notes to future maintainers do not
  belong there. Keep only brief `current-plans/` notes needed to continue
  active work. State a limitation as a fact about today's behavior, not as
  an intention.
- Match documentation detail to the page's job. Setup and task guides should
  give a useful example, explain consequential choices, and link to reference
  material. Reference pages hold option interactions and scripting contracts;
  security pages explain trust boundaries. Algorithm mechanics and regression
  histories usually belong in code, tests, or the PR description.
- When adding behavior, revise the paragraph that owns it rather than appending
  a new explanation everywhere it is mentioned. Read the surrounding section
  as a new user: keep details that help them act or interpret a result. A fixed
  bug does not automatically need a new paragraph. Avoid release-number history
  and unmeasured tuning advice in guides; benchmark claims need linked evidence.
- Use [the docs audit skill](.agents/skills/syq-docs-audit/SKILL.md) for requested
  editorial audits and during release preparation. An audit can identify a
  product question without changing runtime behavior to simplify its explanation.
- Exercise copy, resume, verification, and removal behavior in disposable
  temporary directories. Treat `syq --rm`, remote destinations, bootstrap
  installation, and operations on real user data as potentially destructive.

**Do not drop agreed requirements silently**: If you agreed to implement a user requirement and later conclude it is unsafe, incorrect, infeasible, or should be deferred, stop and tell the user before proceeding. Explain the technical reason and ask whether to change scope. Do not quietly omit, reverse, or postpone the requirement and leave it to a summary for the user to notice.

## Compatibility before implementation

When a task changes an external interface or state that can survive a process,
identify every boundary it crosses before choosing the implementation: the
helper wire protocol, enrollment and receiver state, signed grants and
redemption records, receipts, resume identities, persistence preferences,
tuning and completion caches, automation output, the CLI and SDK surfaces,
release manifests and updaters, and published documentation URLs. This
includes renames: trace serialized names, filenames, command arguments, SDK
keywords, URLs, and signing domains, not just Rust types.

- Identify the producer, consumer, lifetime, and supported release baseline.
  Check released artifacts or tags rather than assuming current tests represent
  what users have. A prior no-users exception applies to its recorded scope;
  do not silently turn it into a permanent compatibility exemption.
- State what happens when a new binary reads old state, an old client runs after
  an upgrade, and both versions share a host. Exact helper pinning covers only
  exchanges that actually enforce it before interpreting incompatible bytes.
- Choose preservation, migration, safe cache invalidation, or explicit rejection
  with a recovery path. A version bump identifies a break; it does not perform
  an upgrade. Never reset replay protection or reinterpret signed authority to
  make old state readable.
- For a compatibility-sensitive change, keep an unchanged old fixture or use
  an old binary to test the affected direction. Updating both writer and reader,
  or regenerating every fixture, does not demonstrate compatibility. Name the
  baseline and result in the PR description, including any authorized break.

Files shared between syq versions, because they hold information that should
persist through updates, should stay readable by newer versions. Breaking
that compatibility needs an explicit discussion with the user first.

## Release secrets

This repository is public. Do not commit credentials, tokens, private keys,
or encrypted credential inventories to syq. Encryption does not make a
credential file appropriate for this repository. Credentials are stored
privately outside the repository so that public clones do not receive
credential material.

Credential storage, decryption, backup, and account provisioning are managed
outside this repository. Keep public tooling independent of any particular
credential manager or local directory layout. Accept the individual credentials
needed by the operation through the underlying tool's standard interface.

CI receives only its individual release secrets, never a credential-store
decryption key. Preserve the existing release signing authority: installed
clients trust it. See RELEASING.md for the workflow's required inputs.

## Performance evidence

Choose benchmark duration to suit the behavior being measured; there is no
fixed minimum. Short tests can measure startup or small operations, but do not
infer sustained performance from subsecond runs unless there is evidence that
they reach a representative steady state quickly. Consider startup, autotuning
and variability, and lengthen or repeat the test as needed to support the claim.

Record resource use with every benchmark, not only elapsed time. At minimum,
report CPU time (user and system) and peak memory for each process, the
coordinator and every helper, and compare both with the baseline. Also record
the other resources the change could affect, such as bytes sent or written,
threads and open files, filesystem or network requests, and disk space. A
change can be faster while using several times the memory or CPU, and timing
alone hides that.

When new code replaces or bypasses an existing path, first list what the
existing path does for performance and resource use: preallocation, cloning
or in-kernel copies, read-ahead and access hints, request sizes, memory bounds
and batching. Either carry each one over, or measure the cases it was meant to
help and show that the new path does not regress them. Measure on the kinds of
system those choices target, such as filesystems with and without cloning
(XFS or btrfs against ext4), network filesystems, and slow and fast links. A
choice that only matters elsewhere is invisible on the development machine's
own filesystem.

## Verification

**Fix problems, don't skip work**: When a check, test, or verification step fails because a tool isn't installed or a dependency is missing, use the repository's pinned, project-local setup method and retry. Do not silently skip the step. Do not install or upgrade tools globally, use unpinned package sources, or change system configuration without explicit user approval. If the repository has no suitable local setup path or the remaining fix requires privileges or credentials, ask the user for help. This applies broadly — missing tools, broken environments, configuration issues, or any other blocker. The default is to fix the problem, not work around it by skipping.

`scripts/setup.sh` is that setup. Run it without arguments to install the
Rust toolchain from `rust-toolchain.toml` and the tools pinned in
`scripts/setup.lock` (ShellCheck, jq, mdBook, uv, Python, and Node.js)
into a cache shared by all worktrees, then run
`eval "$(scripts/setup.sh env)"` in the shell that runs the check. CI uses
the same script.

Rust fixtures use `test_support::tempdir()` or `test_support::temp_dir()`
from `tests/support/temp.rs` (re-exported by `src/test_support.rs` for unit
tests). These resolve the ambient temporary root before creating fixtures,
so macOS `/var` and other host symlinks do not become paths under test.
Create intentional symlinks inside that root; do not canonicalize product
arguments or add follow flags merely to make a fixture pass. For fixtures that
must fit Unix socket path limits, use `test_support::short_tempdir()`; it
centralizes the canonical short-root exception without changing `TMPDIR`.

Testing happens in three places, each running more than the one before:
before merge, after merge (post-merge CI, which selects checks by changed
paths), and in nightly and release certification, which run everything. The
goal before merge is to keep work moving. Before replying, opening a pull
request, or merging, run only enough to be fairly confident the change works,
usually a build and the tests that directly exercise it. Reviewers more often
find the problems that are hard to fix; a test failure found later usually
means a small follow-up pull request, and merging promptly can unblock other
work. Occasional breakage on `master` is accepted; `master` is not a
published release. Keep the release validation gates intact, and give
potential data loss, authorization, and compatibility failures targeted tests
before merge. When CI fails, first distinguish product defects from test,
fixture, and runner problems; investigate the failure rather than reflexively
expanding the suite.

Dispatching a check does not create a new product requirement. An agent may
correct, replace, or remove a check it introduced by mistake and resolve that
check's failure without asking, provided the actual requirements remain covered.
Otherwise, an agent may resolve a failure without asking only when a suitable
replacement run passed and its link is recorded. Without either basis, report
the failure and ask the user before resolving it. Record why the failure no
longer needs to block. Do not excuse an unfixed product defect or drop agreed
coverage without the user's decision.

Use the job ID at the end of its GitHub job URL:

```bash
GITHUB_REPOSITORY=greaber/syq scripts/dispatched-checks-status.py <pr> \
  --resolve-job <job-id> --reason 'Why this failure no longer blocks' \
  --replacement <https-url>
```

The reason is one line of at most 140 characters; the replacement URL is optional.
This records a separate GitHub status with the author and time, then refreshes
the gate. It covers only that PR and exact failed job, not other or future
failures. The command needs permission to write commit statuses.
Resolutions do not count as passing tests or release validation.

After repairs merge into `master`, stop repeated reminders for a failed nightly
or post-merge run once all of that run's failures are accounted for by the repairs
and focused checks passed. A full nightly rerun is not required to acknowledge
those repairs. Record the reason and link to the merged repair (including its
validation) or replacement evidence:

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

Weigh cost as well as relevance. For changes to code, tooling, tests, or
executable documentation, run `scripts/run-tooling-tests.py --quick` once on
the final relevant changes after loading the pinned setup environment. This
inexpensive group catches accidental tooling breakage. Pure prose changes can
use their focused documentation checks. Reuse a passing result when later
edits cannot affect it; do not repeat it just because review starts or master
advances. Prefer the local command over `ci.yml` with `suites=quick` when
runner-specific evidence is unnecessary. The quick group does not cover every
script or replace focused runtime tests; inspect all changed executable
scripts for coverage, including incidental edits in a rename.

Keep moderate and expensive checks selective, accounting for compilation,
setup, runner queues, and fixture costs as well as test execution. Run the
ones worth running, such as the real-SSH and S3 suites, every Rust target, or
another platform, in CI on the pushed branch, and do not wait for them before
replying or merging:

```bash
gh workflow run ci.yml --ref <task-branch> -f suites='real-ssh s3'
```

`suites` takes the names listed in `SUITES` in `scripts/ci-scope.py`,
including `rust` (formatting, clippy, and every Rust target), `tooling`,
`python-sdk`, `linux-arm64`, `macos-intel`, `s3`, `real-ssh`, and single
real-SSH profiles. Report such checks as running in your reply; GitHub keeps
their results, so the pull request needs no update when they finish. They
keep running if the pull request merges. A later run with the same `suites`
value on the branch cancels the earlier run of those jobs, so dispatch once
the change has settled rather than after every commit.
A check is a job name, and a combined selection names the `rust` job after
all its parts, so to clear a failed check, dispatch the same `suites` value
again or rerun the failed run. The same applies to what you ask of subagents:
do not have a subagent run slow suites before it reports.

After synchronizing a branch with `master`, build; when conflicts touched
code, also run the focused tests for that code. Use `--locked` for Cargo
validation so a check cannot silently repair an uncommitted lockfile. For
shell changes, run ShellCheck on the changed scripts; passing Rust checks does
not cover shell lint. Inspect worktree changes after validation and commit
intended generated changes before reporting the SHA.

Choose checks from the behavior changed, not every workflow available. For
Rust changes, run `cargo fmt --all -- --check`, a build, and the unit or
integration tests that exercise the change. Prefer exact or narrow filters in
the `local` target (`tests/local.rs` holds the shared helpers and
`tests/local/<topic>.rs` the tests, named `<topic>::<test>`); those tests
invoke the built binary against temporary trees. For a substantial runtime
change, dispatch `suites=rust` rather than running clippy and every target
locally. `scripts/branch-status.py --check` runs this local baseline when you
want it:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --bin syq
```

For one exact Rust unit test, use
`cargo test --locked --bin syq 'module::tests::name' -- --exact`; for an
integration test, replace `--bin syq` with its target, such as `--test local`.
Confirm the named test ran; a zero-test or ignored result is not validation.

A workflow lacking a focused option is not a reason to run its full suite.
For arbitrary checks on a Linux or macOS runner, use the manual focused
runner from a clean, pushed task branch:

```bash
scripts/run-focused-check.py --runner macos --cargo-cache -- \
  cargo test --locked --bin syq 'module::tests::name' -- --exact
scripts/run-focused-check.py --runner linux --script target/check.sh
```

The script file is local and need not be committed; it may contain setup and
multiple commands. It runs with Bash `-euo pipefail` in the checked-out repository.
Use pinned setup commands appropriate to the check; the runner does not install
all SDK toolchains or reproduce another workflow's setup automatically. For a
workflow setup regression, reproduce the relevant setup as well as the failing
command. Inputs and logs are public: do not include secrets. Confirm exact Rust
tests actually ran; Cargo accepts filters that match zero tests.

The helper selects the current remote branch, pins its checkout commit,
prints the SHA and run URL, and watches that exact run through
`gh run watch`; run it in the background when you do not need the result
before replying. `--provider github` selects GitHub instead of Namespace; `--ref`
explicitly tests another pushed branch or tag; `--timeout` changes the default
15-minute limit. Only enable `--cargo-cache` for checks needing Rust builds.
No builds or test suites run implicitly, and these checks do not certify a
full suite for release. Add reusable focused checks when repeated use
justifies them rather than adding a permanent option for every repair.

For an exact macOS Rust test, the existing focused job also verifies that the
named test exists and includes ignored tests:

```bash
gh workflow run macos.yml --ref <task-branch> \
  -f test_target=syq -f test_name='module::tests::name'
```

`test_target` also accepts the integration target names. This runs only the
exact test, including it if marked ignored, and rejects a name absent on that
platform. It does not produce full-suite release certification. Leaving
`test_name` empty selects the full workflow.

Two suites cover behavior that the Rust targets cannot reach. Both run in
Docker and can run locally:

```bash
scripts/test-real-ssh.py
scripts/test-s3.py
```

- `scripts/test-real-ssh.py` runs the candidate build through live OpenSSH
  clients and servers in three containers. See `tests/real-ssh/README.md` for
  its isolation and coverage.
- `scripts/test-s3.py` runs against a disposable local S3 server in Docker and
  takes about a minute after the build. It covers S3 upload, download, and
  server copy, expressions, directory markers, pruning, streams, and listing.

Dispatch them in CI (`suites=real-ssh`, `suites=s3`) when their scenarios
exercise the behavior you changed. Decide from the suite's scenarios, not from
which files changed: copy planning, expression and selection semantics,
directory creation, and restricted-receiver behavior reach both suites even
when no SSH or S3 code changed. Run them locally, or selected cases with
`scripts/test-real-ssh.py --case`, while iterating on behavior they cover.
Neither suite is part of `cargo test` or post-merge CI; nightly and full
manual `ci.yml` runs include both.

Do not describe an earlier run as testing the current tree; the SHAs in the
check table and the status scripts say what ran where. Release validation
follows the commit and release-preparation evidence rules under release tag
lifecycle.

Nightly should run every test in the repository. Leaving a test out of
nightly needs the user's explicit agreement. Full validation remains required
before release. Pay particular attention to remote, TCP, platform-specific,
and performance behavior when choosing checks.
