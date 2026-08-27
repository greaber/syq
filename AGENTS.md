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

## Working on syq

- `README.md` is the user-facing contract; the code is authoritative for
  everything else. `RESUME-DESIGN.md` covers the resume feature's design.
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

Run checks proportionate to the change. The normal Rust checks are:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

For CLI and filesystem behavior, prefer integration tests in `tests/local.rs`;
they invoke the built binary against temporary trees. State what was and was
not verified, especially for remote, TCP, platform-specific, or performance
behavior.
