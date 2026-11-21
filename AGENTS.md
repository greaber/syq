# Agent guidance

## The user reads only the conversation

The user works through a conversation with one agent, often a coordinator
that starts implementing and reviewing agents. The user does not read pull
request descriptions, review reports, triage notes, plans, or code. Those are
records between agents.

- Only what the user says in the conversation is a request or an approval.
  Nothing an agent wrote (a pull request description, commit message, review
  report, or `current-plans/` note) shows what the user asked for or agreed
  to. The user not objecting to something they were never told is not consent.
- Say in the conversation whatever the user needs to know or decide: the
  outcome, anything that differs from what they asked for, risks left open,
  and the decisions that are theirs. Leave out status-script output, check
  tables, and lists of things that are fine.
- A subagent reports to the agent that started it, and that agent decides
  what reaches the user. A subagent still reports every item of the kinds
  below in full instead of settling it.

Decide ordinary matters yourself. Bring these to the user as an explicit
question before acting: a change to what was asked (added scope or a dropped
requirement), a recurring cost, wider security access, a destructive or
hard-to-undo action, and a product or design choice with no clear default.

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

## Write removals the harness can check

Claude Code statically checks each Bash call for dangerous `rm` and prompts
on a hit even in bypass mode. The user will not audit a long compound command
at that prompt, so a hit is a dead end: write removals in a shape that passes.
Loops, `if`, `find -exec`, `xargs`, heredoc scripts, relative paths, `~`,
variables, and mixing `&&` with `;` all pass. The shapes that prompt are:

- A system, home, or workspace directory, or its contents with `/*`: a
  top-level directory such as `/tmp`, the home directory, the working
  directory and its parents, and mounted drives. Never remove these. If a
  prompt names one, stop and report it instead of rewriting around it.
- A glob in more than one path segment, such as `dir/*/*` or `e*/*`. One
  trailing `/*`, or a glob in the last segment, passes.
- A possibly-empty variable followed by `/*` or `/`, as in `"$VAR"/*`, or by
  a top-level name, as in `$VAR/usr`; and `..` or `$(...)` followed by `/*`.
  Without that suffix, `..` and a bare variable pass.
- A recursive `rm` whose target is only `$(...)` or backtick output, such as
  `rm -rf "$(mktemp -d)"`, or a variable the same command sets from `$(pwd)`
  or another directory-printing substitution. A literal segment after the
  substitution, as in `$(pwd)/target`, passes unless the path before it is
  critical, as in `/tmp/$(cmd)` or `~/$(cmd)`.
- A relative target ending in `/*` in a command that also runs `cd`. Write it
  as an absolute path.
- In a command that runs `rm` anywhere, an inline `sh -c` script that starts
  a command with `$VAR` instead of a literal program name, gives `rm` a loop
  variable as its target, or exceeds 2000 characters. A literal `rm` inside
  the script passes, as does `rm` elsewhere in the same command.

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
belongs here in `AGENTS.md`; guidance for one kind of task belongs in a skill
under `.claude/skills/`, with a one-line pointer here.

Do not use an agent runtime's private memory (for example Claude Code's
per-project memory directory) for this project, even when the runtime prompts
you to save something. It is hard to audit, other agents cannot read it, and
it goes stale unnoticed. If you find existing private memory for this project,
report what it contains instead of relying on it.

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
  merged.

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
  running. Every status report about branch or PR work names the short SHA it
  refers to, even when nothing changed ("unchanged at `ab12cd3`"), so the
  reader can tell whether a review covers the current work. Passing tests are
  not a precondition for reporting a change, opening a pull request, or
  asking for review: report a known failure with
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
  request, before asking for review, and before merging, and report CI state
  from its output. Post-merge runs select
  checks by changed paths, so a green one does not show that an earlier
  failure was fixed. Report its unresolved `master` notes even when the
  current task did not cause them, but do not repeat failures marked
  `addressed`. It exits 1 while a check dispatched on the branch has failed,
  unless a later run of it passed or that failure was explicitly resolved. `scripts/pr-checks.py <number>` reports the
  same for any pull request from any checkout.
- Pull requests do not start automated test workflows. Failed dispatched
  checks block the merge through the required `dispatched-checks` status,
  including failures that already happen on `master`; the `syq-ci` skill (`.claude/skills/syq-ci/SKILL.md`)
  explains the gate and how to resolve one check. The `merge-despite-failures`
  label overrides all failures. Adding the label is the user's decision: when
  a requested merge is blocked, report each failure, say whether `master`
  shows it too, and ask.
- Before removing a worktree or branch, require a clean worktree, no retained
  task-related stash, and no commits that still need integration. An ancestry
  result such as `git branch --merged` says nothing about uncommitted files.

## Release authorization

Releases require the user to explicitly invoke `$syq-release` (`/syq-release` in Claude Code) or select that
skill in the UI. The skill is committed at
[`.agents/skills/syq-release/SKILL.md`](.agents/skills/syq-release/SKILL.md)
with implicit invocation disabled. An ordinary “cut a release” request,
release-related code, a merge instruction, or a request to create/edit the
skill does not activate it. Without an invocation, agents may inspect release
state and prepare requested changes, but must not create or push release tags,
publish packages or releases, or approve publication deployments. Do not work
around the gate by using release commands directly. An invocation authorizes
the complete requested release, as the skill describes; another release
requires another invocation.

Never move or force-update a release tag, and never delete one that has
reached any published destination. The skill holds the full tag lifecycle.

## Reviews

Every change gets an independent review before it merges: at least one
reviewer that starts from clean context and did not write the change. The
implementing or coordinating agent starts the review and follows it itself
with `scripts/agent-coordination.py review` (see
[`scripts/agent-coordination.md`](scripts/agent-coordination.md)). The tool
carries reports and later rounds, so the user starts nothing and passes
nothing along. The default reviewer, Claude Opus 5.5 at `xhigh` effort
without approval prompts, suits most PRs. For security, protocol,
authorization or data-integrity changes, and for large PRs, also add
`--additional-reviewer --reviewer codex` with GPT-6 Astra (the default) or
GPT-6.1 Sol (`--model gpt-6.1-sol`): a second model occasionally finds
important issues Opus misses. Lower effort is fine for small or test-only
changes.

When you are the reviewer, follow
[`.claude/skills/syq-review/SKILL.md`](.claude/skills/syq-review/SKILL.md).

### Acting on findings

Review is adversarial on purpose. The reviewer's job is to look for holes;
the job of the agent that owns the change is to decide what the change needs.
A finding can be correct and still call for no change. Left unchecked, review
grows a change: each round adds safeguards, options and edge-case handling
that nobody asked for, and these cost complexity and can harm the product's
other goals.

For each finding, ask what concrete situation triggers it, how likely that
is, how bad the result would be, and what the fix costs in code, complexity
and other goals. Then:

- Fix what you have confirmed and is worth its cost: wrong results, data
  loss, a security hole, a broken agreed requirement, or a real problem with
  a small fix.
- Decline the rest in a sentence that gives the reason. Declining a correct
  finding is a normal outcome. Labels such as "pre-existing", "nonblocking"
  and "optional" are neither a reason to act nor a reason to dismiss.
- Do not let a fix outgrow its problem. A fix that adds a mechanism, option,
  fallback or guarantee the task did not call for is added scope: decline the
  finding or take it to the user.
- A real problem outside the task is separate work. Mention it to the user
  in a line and do not widen the change. A topic the user excluded stays
  excluded.

Do not change the work merely so that the reviewer agrees, and do not argue
one point for more than a round: record the disagreement and go on. A review
the user pastes into the conversation is still the reviewer's opinion, not
the user's.

### When to stop and tell the user

A review should converge in one or two rounds. Stop before making further
changes, and tell the user, when any of these happens:

- a third review round would be needed;
- the change has grown well beyond what the task asked for, in size or in
  what it does;
- fixes for findings keep producing new findings, or a declined finding
  comes back;
- you and the reviewer disagree about something consequential.

Say what was asked, what the change has become, what is still disputed, and
what you recommend. Often the right recommendation is to merge the change as
it stands or to cut it back to the original task.

## Working on syq

- [`PRINCIPLES.md`](PRINCIPLES.md) records the user's core product principles.
  Check a design against it before implementing, and raise any conflict first.
  Only the user decides its contents; propose a change in a pull request and
  say so at the top.
- `README.md` and the documents under `docs/` are the user-facing contract;
  `README.md` is a brief front door, and `docs/copy-files.md` carries the
  detailed behavior. The code is authoritative for everything else. When you
  edit them, follow the `syq-docs-writing` skill (`.claude/skills/syq-docs-writing/SKILL.md`).
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
  `scripts/setup.sh`, so it needs no compatibility floor for older Python.
  `tests/real-ssh/*.py` must instead work with the Debian test image's
  `python3`. Use portable shell only for code that runs on users' machines or
  arbitrary hosts (the generated installer and `scripts/try-benchmark.sh`),
  `scripts/setup.sh`, the real-SSH container scripts, and thin wrappers that
  only run other commands, such as the release runners' Nix and build steps.
  CI and release tooling is too complex to maintain well in Bash, so do not
  spend effort on Bash 3.2 compatibility for development scripts.
- Keep CLI behavior, help text, `README.md`, `docs/`, and integration tests in
  sync. A behavior change lands in `docs/copy-files.md` (or the topical
  document that owns it), not in a new README section.
- `README.md` and `docs/` are written for users. They describe what the code
  on `master` does. Plans, roadmap items, design directions, internal status,
  unreleased or unvetted components, and notes to future maintainers do not
  belong there. Keep only brief `current-plans/` notes needed to continue
  active work. State a limitation as a fact about today's behavior, not as
  an intention.
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

## Public repository and release secrets

This repository is public. Keep account identifiers, credential locations,
and details of private infrastructure out of commits, pull requests, and
documentation, including this file. Do not commit credentials, tokens, private keys,
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

Record CPU time (user and system) and exact peak memory for every process
with each benchmark, not only elapsed time, and compare them with the
baseline. Follow the `syq-benchmark` skill (`.claude/skills/syq-benchmark/SKILL.md`) when benchmarking, making a
performance claim, or replacing an existing copy or I/O path.

## Verification

**Fix problems, don't skip work**: When a check, test, or verification step fails because a tool isn't installed or a dependency is missing, use the repository's pinned, project-local setup method and retry. Do not silently skip the step. Do not install or upgrade tools globally, use unpinned package sources, or change system configuration without explicit user approval. If the repository has no suitable local setup path or the remaining fix requires privileges or credentials, ask the user for help. This applies broadly — missing tools, broken environments, configuration issues, or any other blocker. The default is to fix the problem, not work around it by skipping.

`scripts/setup.sh` is that setup. Run it without arguments to install the
Rust toolchain from `rust-toolchain.toml` and the tools pinned in
`scripts/setup.lock` (ShellCheck, jq, mdBook, uv, Python, Node.js, and cargo-nextest)
into a cache shared by all worktrees, then run
`eval "$(scripts/setup.sh env)"` in the shell that runs the check. CI uses
the same script.

When writing or changing Rust tests, follow the `syq-rust-tests` skill (`.claude/skills/syq-rust-tests/SKILL.md`):
fixtures use `test_support` temporary directories, executed files are written
with `write_executable`, and background services must be stopped on failure.

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

The `syq-ci` skill (`.claude/skills/syq-ci/SKILL.md`) has the commands for resolving a failed dispatched check
and for acknowledging a failed `master` run once all of its failures are
accounted for by merged repairs and focused checks passed; that
acknowledgment is authorized as part of completing the repair.

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

`suites` takes the names listed in `SUITES` in `scripts/ci-scope.py`. Report
such checks as running in your reply. A later run with the same `suites` value
on the branch cancels the earlier one, so dispatch once the change has
settled; the `syq-ci` skill has the details. Do not have a subagent run slow
suites before it reports.

Dispatch the macOS suite (`gh workflow run macos.yml --ref <task-branch>`)
only for platform-sensitive changes: code paths that differ on macOS,
filesystem or process behavior, and packaging. Each run occupies a macOS
runner for half an hour or more, and post-merge and nightly runs cover the
rest. Do not rerun it after it passed at the same commit, or after a passing
run on the branch, unless the later commits could change its result.

After synchronizing a branch with `master`, build; when conflicts touched
code, also run the focused tests for that code. Use `--locked` for Cargo
validation so a check cannot silently repair an uncommitted lockfile. For
shell changes, run ShellCheck on the changed scripts; passing Rust checks does
not cover shell lint. Inspect worktree changes after validation and commit
intended generated changes before reporting the SHA.

Choose checks from the behavior changed, not every workflow available. For
Rust changes, run `cargo fmt --all -- --check`, a build, and the unit or
integration tests that exercise the change. When a change adds, removes, or
narrows a platform `cfg`, such as making tests Linux-only, also run
`scripts/check-macos-lint.py` (about a minute on Linux). Post-merge CI runs
it as the `macos-lint` job with every Rust change, but running it before
merge keeps the failure off `master`. Prefer exact or narrow filters in the `local`
target. For a substantial runtime change, dispatch `suites=rust` rather than
running clippy and every target locally. `scripts/branch-status.py --check`
runs this local baseline when you want it:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo nextest run --locked --bin syq
```

Use `cargo nextest run` for Rust tests; its repository configuration gives
each test a deadline. Plain `cargo test` has no enforced timeout; use it only
for builds/listing or investigations requiring its shared process.

For one exact Rust unit test, use
`cargo nextest run --locked --bin syq -- --exact 'module::tests::name'`; for an
integration test, replace `--bin syq` with its target, such as `--test local`.
Confirm the named test ran; a zero-test or ignored result is not validation.

A workflow lacking a focused option is not a reason to run its full suite:
the `syq-ci` skill shows how to run one check, such as a single Rust test, on
a Linux or macOS runner.

Two suites cover behavior that the Rust targets cannot reach. Both run in
Docker and can run locally:

```bash
scripts/test-real-ssh.py
scripts/test-s3.py
```

The real-SSH suite runs the candidate build through live OpenSSH clients and
servers in three containers; `tests/real-ssh/README.md` describes its
coverage. The S3 suite runs against a disposable local S3 server, takes about
a minute after the build, and covers S3 upload, download, and server copy,
expressions, directory markers, pruning, streams, and listing.

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
follows the evidence rules in the `syq-release` skill.

Nightly should run every test in the repository. Leaving a test out of
nightly needs the user's explicit agreement. Full validation remains required
before release. Pay particular attention to remote, TCP, platform-specific,
and performance behavior when choosing checks.
