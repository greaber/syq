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

Check `git status` and `git worktree list` before choosing a worktree. A branch
and worktree should correspond 1:1 with a task or pull request. Also check the
primary checkout's `current-plans/` for plans or handoff notes that cover the
topic. The normal setup from the primary checkout is:

```bash
git worktree add .worktrees/<task> -b <task> master
ln -s ../../current-plans .worktrees/<task>/current-plans
cd .worktrees/<task>
```

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
it goes stale unnoticed. Propose guidance that later sessions need as a change
to this file through a pull request, put short-lived task state in
`current-plans/`, and otherwise record nothing. If you find existing private
memory for this project, report what it contains instead of relying on it.

`current-plans/` notes are agent-written handoff state. They are not evidence
of what the user asked for or approved.

This repository is public. Keep account identifiers, credential locations,
and details of private infrastructure out of commits, pull requests, and
documentation, including this file.

When writing any of these, record decisions as current state plus the rationale
at the time, not as timeless policy. An assumption encoded as a requirement can
outlive its premise and steer later work in the wrong direction.

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
  reset to discard task work.
- If a safety stash is genuinely necessary to make the worktree clean, give it
  a task-specific name and include untracked files. Restore it after the
  synchronization, verify the resulting worktree, and drop it after the
  corresponding work is committed. Report any retained stash and why it is
  still needed in the handoff.
- At review handoff, state the branch and exact short commit SHA, whether the
  worktree is clean, and which checks passed, failed, or were not run. Treat
  review-ready and merge-ready as separate states.
- Run `scripts/branch-status.sh` from the task worktree before opening a pull
  request, before asking for review, and before merging, and include its output
  in the report. It prints the branch SHA and cleanliness, the pull request's
  GitHub head and check results, and the latest post-merge `ci`,
  `rsync-compat`, and `macos` runs on `master`. Pull requests do not start
  automated test workflows and branch protection does not require test status
  contexts. Any pull-request check results are informational. A red `master`
  run makes the script exit 1; report it to the user even when the current task
  did not cause it. `--check` also runs the Rust baseline below, and `--json`
  prints the same facts for scripting.
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

- Before pushing a syq release tag, require successful full-suite runs of
  `ci.yml`, `rsync-compat.yml`, and `macos.yml` on the exact clean remote
  `master` commit. A task branch or detached checkout at that SHA is sufficient;
  do not update the coordination checkout or clone solely to obtain a branch
  named `master`. Start with `scripts/release-readiness.py v<version>` and reuse
  its recorded default real-SSH validation when the entire committed tree is
  unchanged. Its `--check-ssh` mode runs and records missing local validation. Reuse post-merge or manual runs when `scripts/verify-release-ci.sh`
  accepts their full-suite certificates; dispatch only workflows missing that
  evidence and wait for them to succeed. Then run
  `scripts/release-preflight.sh v<version>` from that same commit. Treat any
  failure as a blocker rather than pushing the tag to discover whether the
  release workflow starts. Use `scripts/release-status.sh v<version>` after
  the push to correlate the exact tag, workflow, approvals, and publication
  destinations.
- Except for Go module tags, treat a release tag as provisional until its
  release workflow connects it to permanent published state. If an attempt is
  abandoned before that boundary, remove the failed tag locally and remotely
  instead of reserving a version that was never released. Never force-update or
  silently move the tag.
- A Go module tag such as `sdk/go/v*` is permanent as soon as it is pushed.
  Pushing the tag publishes the module: clients or arbitrary proxies may fetch
  and cache it without an observable central publication step. Never delete,
  recreate, or move a Go module tag.
- A release tag becomes permanent as soon as any associated version or artifact
  reaches an immutable or append-only destination, including an immutable
  GitHub release, a package registry, a module proxy, the Homebrew tap, or a
  durable artifact attestation. Never move or delete a permanent tag. Repair or
  rerun the remaining publication steps from that exact tag when safe, or cut a
  new version when they cannot be completed consistently.
- Before deleting a provisional non-Go tag, stop or wait for its active
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

The rationale in 2026-09: a review noted that a release-tooling PR had added
eight uncached builds on every source push to `master`, but treated it as
deliberate because the PR body described it. The user had never authorized or
known about it.

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
- Keep the selected data route fixed. TCP may fall back to SSH between the
  same endpoints, but failure must never silently relay file data through the
  invoking or authorizing machine. Relaying requires an explicit route choice.
- Copy failures must be visible. Do not make an incomplete or truncated result
  look successful.
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

The public support baseline and duration are not yet decided. Surface that
choice when it matters; do not add speculative compatibility implementations
or promise indefinite support.

## Release secrets

This repository is public. Do not commit credentials, tokens, private keys,
or encrypted credential inventories to syq. Encryption does not make a
credential file appropriate for this repository. The user chose private
storage outside the repository in September 2026 so that public clones do
not receive credential material.

The release tools read `.env.release` and `.env.keys` from
`${XDG_CONFIG_HOME:-$HOME/.config}/syq/release`, or from the external directory
selected by `SYQ_RELEASE_SECRETS_DIR`. The operator keeps the encrypted
inventory in a separate private operations repository; local configuration
links to that checkout. Commit inventory updates only in that private repo.
Keep decryption keys out of every Git repository and back them up separately
in protected storage. Never upload `.env.keys` or a
`DOTENV_PRIVATE_KEY_*` value to GitHub, CI, the Homebrew tap, or a runtime
system. Keep actual private storage locations out of commits and PRs.

When migrating credentials, verify the private copy decrypts to the same
values before removing the old copy. Do not rewrite published history or
rotate release signing authority as a cleanup shortcut; installed clients
trust the existing signing identity.

CI consumes only the two individual environment secrets it needs. A maintainer
materializes those values locally with `scripts/sync-github-secrets.sh`; the
script has a fixed inventory and refuses to target anything except
`github.com/greaber/syq`. Do not change that boundary to let CI decrypt
`.env.release`, and do not add a general dotenvx key to GitHub secrets.

Use dotenvx 2.21.0 for this inventory. Initialize it once with
`scripts/init-release-secrets.sh`, and run the sync without `--execute` before
every actual update. See `RELEASING.md` for provisioning, backup, and rotation.

## Performance evidence

Choose benchmark duration to suit the behavior being measured; there is no
fixed minimum. Short tests can measure startup or small operations, but do not
infer sustained performance from subsecond runs unless there is evidence that
they reach a representative steady state quickly. Consider startup, autotuning
and variability, and lengthen or repeat the test as needed to support the claim.

## Verification

**Fix problems, don't skip work**: When a check, test, or verification step fails because a tool isn't installed or a dependency is missing, use the repository's pinned, project-local setup method and retry. Do not silently skip the step. Do not install or upgrade tools globally, use unpinned package sources, or change system configuration without explicit user approval. If the repository has no suitable local setup path or the remaining fix requires privileges or credentials, ask the user for help. This applies broadly — missing tools, broken environments, configuration issues, or any other blocker. The default is to fix the problem, not work around it by skipping.

Rust fixtures use `test_support::tempdir()` or `test_support::temp_dir()`
from `tests/support/temp.rs` (re-exported by `src/test_support.rs` for unit
tests). These resolve the ambient temporary root before creating fixtures,
so macOS `/var` and other host symlinks do not become paths under test.
Create intentional symlinks inside that root; do not canonicalize product
arguments or add follow flags merely to make a fixture pass.

Choose checks from the behavior changed, not every workflow available. For a
narrow change confined to one test or its private fixture, run formatting and
that exact test on the affected platform. The full Rust baseline below is not
required for that case. Broaden only when shared fixtures, runtime code, or a
concrete unresolved risk makes other tests relevant. Do not dispatch a full
workflow merely to reach one test, or wait for unrelated checks once the
needed result is available. State the selected checks and why before running
expensive validation.

For a Rust runtime change, the normal pre-merge baseline is:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --bin syq
```

Then select the integration tests that can plausibly exercise the changed
behavior. Prefer exact or narrow filters in the `local` target (`tests/local.rs`
holds the shared helpers and `tests/local/<topic>.rs` the tests, named
`<topic>::<test>`); those tests invoke the built binary against temporary trees. Run `cargo test --all-targets` before
handoff when a change is broad, crosses subsystem boundaries, changes shared
test infrastructure, or leaves meaningful uncertainty about the affected
surface. Do not run unrelated suites merely because they exist.

For one exact Rust unit test, use
`cargo test --locked --bin syq 'module::tests::name' -- --exact`; for an
integration test, replace `--bin syq` with its target, such as `--test local`.
Confirm the named test ran; a zero-test or ignored result is not validation.
For macOS, dispatch the focused job on the pushed task branch:

```bash
gh workflow run macos.yml --ref <task-branch> \
  -f test_target=syq -f test_name='module::tests::name'
```

`test_target` also accepts the integration target names. This runs only the
exact test, including it if marked ignored, and rejects a name absent on that
platform. It does not produce full-suite release certification. Monitor the
returned run with `gh run watch <run-id> --exit-status`. Leaving `test_name`
empty selects the full workflow; use that only when broad validation is needed.

Run the local-only three-container OpenSSH suite when changes materially affect
connection setup, helper bootstrap, authentication or authorization, remote
process lifecycle, transport behavior, or remote coordinator placement:

```bash
scripts/test-real-ssh.sh
```

It is intentionally not part of ordinary CI or `cargo test`; see
`tests/real-ssh/README.md` for its isolation and coverage.

Choose this check by behavioral impact, not merely by which file changed.
Small review fixes to diagnostics, documentation, or isolated validation checks
can use focused tests when those tests adequately exercise the change. Batch
related fixes before running the full suite. After a successful run, inspect
the intervening changes before repeating it; rerun when they affect the SSH
scenarios or leave meaningful uncertainty that focused tests cannot resolve.
Report the SHA of the last successful full run, the checks on the current SHA,
and why a repeat was unnecessary. Do not describe an earlier run as testing the
current tree. Release validation still follows the exact-commit requirements
under release tag lifecycle.

Pull requests do not start automated test workflows. The agent remains
responsible for selecting checks under the rules above, choosing integration tests,
and reporting exactly what was and was not verified before review. The
cumulative `master` workflows execute the complete native and cross-platform
suites after merge. Pay particular attention to remote, TCP, platform-specific,
and performance behavior when choosing local checks.
