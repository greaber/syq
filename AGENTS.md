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

Prefer durable, committed documentation over private memory. Facts worth
keeping (behavior, measured performance, design rationale, and invariants) go
in the appropriate committed documentation; guidance every session needs goes
here in `AGENTS.md`. Plans and handoff notes that change too fast for git or do
not belong to a branch go in `current-plans/` (gitignored by design; check it
before starting work on a topic it covers). Use memory only for what fits none
of those.

When writing any of these, record decisions as current state plus the rationale
at the time, not as timeless policy. An assumption encoded as a requirement can
outlive its premise and steer later work in the wrong direction.

## Branch synchronization and handoff

- Durable task work belongs in commits on the task branch. Changes intended for
  `master` go through a pull request; do not commit them directly on `master` or
  merge task branches from the coordination checkout. Do not merge a pull
  request unless the user explicitly asks.
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
- Before removing a worktree or branch, require a clean worktree, no retained
  task-related stash, and no commits that still need integration. An ancestry
  result such as `git branch --merged` says nothing about uncommitted files.

## Release tag lifecycle

- Before pushing a syq release tag, run
  `scripts/release-preflight.sh v<version>` from the exact clean, synchronized
  `master` commit. Treat any failure as a blocker rather than pushing the tag
  to discover whether the release workflow starts. Use
  `scripts/release-status.sh v<version>` after the push to correlate the exact
  tag, workflow, approvals, and publication destinations.
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

## PR review freshness

- For any GitHub PR review or re-review, never assume the current checkout `HEAD` is the latest PR code. Resolve the PR's `headRefName`, `headRefOid`, and head-repository identity (owner and repository) first. Treat the GitHub `headRefOid` as authoritative unless a fresher local commit is verified as described below.
- In this repo's multi-worktree review workflow, also resolve the local branch ref for the PR's `headRefName`. A detached review worktree can stay pinned to an old commit even when the branch ref has moved.
- A matching branch name is not proof that a local ref belongs to the PR, especially for fork PRs. Treat a local ref as PR code only when its worktree ownership is explicit and its repository identity and ancestry relative to `headRefOid` have been verified.
- If the local ref is missing, behind the GitHub head, divergent from it, or cannot be tied unambiguously to the PR's head repository, review the GitHub `headRefOid`. Fetch that exact head into a dedicated review ref or worktree when necessary, without overwriting an unrelated local branch, and report the discrepancy.
- If local and GitHub refs match, review that SHA. If the local ref is ahead, use it only when the worktree belongs to the task and the GitHub `headRefOid` is its ancestor; tell the user that GitHub is stale and either review the unpushed local tip explicitly or wait for it to be pushed.
- If the chosen review target SHA matches the last SHA already reviewed, stop immediately and report that the PR is unchanged instead of producing another review.
- Always state the exact reviewed SHA and whether it came from the local branch tip or the GitHub PR head.

## Working on syq

- `README.md` is the user-facing contract; the code is authoritative for
  everything else.
- Distinguish explicit requirements from assumptions and design choices. If a
  supposed requirement creates substantial complexity, question the premise
  and look for a simpler interpretation. Ask the user when the answer would
  materially change the product.
- Prefer one clear implementation. Add fallbacks or compatibility paths only
  for a concrete scenario or consumer that needs them.
- Keep CLI behavior, help text, `README.md`, and integration tests in sync.
- Copy failures must be visible. Do not make an incomplete or truncated result
  look successful.
- Exercise copy, resume, verification, and removal behavior in disposable
  temporary directories. Treat `syq --rm`, remote destinations, bootstrap
  installation, and operations on real user data as potentially destructive.

**Do not drop agreed requirements silently**: If you agreed to implement a user requirement and later conclude it is unsafe, incorrect, infeasible, or should be deferred, stop and tell the user before proceeding. Explain the technical reason and ask whether to change scope. Do not quietly omit, reverse, or postpone the requirement and leave it to a summary for the user to notice.

## Release secrets

Once provisioned, `.env.release` is the committed dotenvx-encrypted source of
truth for release credentials. `.env.keys` is its gitignored decryption
authority and must remain on developer-controlled machines and in protected
backup storage. Never upload `.env.keys` or a `DOTENV_PRIVATE_KEY_*` value to
GitHub, CI, the Homebrew tap, or a runtime system.

CI consumes only the two individual environment secrets it needs. A maintainer
materializes those values locally with `scripts/sync-github-secrets.sh`; the
script has a fixed inventory and refuses to target anything except
`github.com/greaber/syq`. Do not change that boundary to let CI decrypt
`.env.release`, and do not add a general dotenvx key to GitHub secrets.

Use dotenvx 2.21.0 for this inventory. Initialize it once with
`scripts/init-release-secrets.sh`, and run the sync without `--execute` before
every actual update. See `RELEASING.md` for provisioning, backup, and rotation.

## Verification

**Fix problems, don't skip work**: When a check, test, or verification step fails because a tool isn't installed or a dependency is missing, use the repository's pinned, project-local setup method and retry. Do not silently skip the step. Do not install or upgrade tools globally, use unpinned package sources, or change system configuration without explicit user approval. If the repository has no suitable local setup path or the remaining fix requires privileges or credentials, ask the user for help. This applies broadly — missing tools, broken environments, configuration issues, or any other blocker. The default is to fix the problem, not work around it by skipping.

Run checks proportionate to the change. For a Rust change, the normal
pre-merge baseline is:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --bin syq
```

Then select the integration tests that can plausibly exercise the changed
behavior. Prefer exact or narrow filters in `tests/local.rs`; those tests invoke
the built binary against temporary trees. Run `cargo test --all-targets` before
handoff when a change is broad, crosses subsystem boundaries, changes shared
test infrastructure, or leaves meaningful uncertainty about the affected
surface. Do not run unrelated suites merely because they exist.

Pull-request CI intentionally mirrors this policy: it runs formatting, clippy,
and native unit tests for Rust changes, plus a directly affected SDK, rsync, or
executable-documentation suite. The agent remains responsible for choosing and
reporting focused integration tests before review. The cumulative `master` CI
run executes the complete native and cross-platform suites after merge, so a
green pull request is not evidence that every repository test ran on that head.
State exactly what was and was not verified, especially for remote, TCP,
platform-specific, or performance behavior.
