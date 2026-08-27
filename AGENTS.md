# Agent guidance

## Worktrees

Start any task that may change the repository in a task-specific git worktree,
before investigating or editing code for that task. Treat the primary checkout
as a coordination checkout: it must stay on `master` with a clean working tree.
Do not edit tracked files, create commits, or switch branches there, and do not
disturb changes already present. Fast-forwarding `master` after a remote merge
and administering branches and worktrees are the only normal exceptions.

Check `git status` and `git worktree list` before choosing a worktree. A branch
and worktree should correspond 1:1 with a task or pull request; the normal setup
from the primary checkout is:

```bash
git worktree add .worktrees/<task> -b <task> master
cd .worktrees/<task>
```

Use plain git commands as shown above. Do not use the `EnterWorktree` or
`ExitWorktree` tools; they are denied in `.claude/settings.json`.

Continue in an existing worktree only when you created it for the current task
or the user explicitly identified it as the target. Never infer ownership from
a plausible branch name. Before every file edit or write, confirm that
`git rev-parse --show-toplevel` points at the task worktree.

## Branch synchronization and handoff

- Durable task work belongs in commits on the task branch. Changes intended for
  `master` go through a pull request; do not commit them directly on `master` or
  merge task branches from the coordination checkout. Do not merge a pull
  request unless the user explicitly asks.
- An active worktree may be dirty while work is in progress, but do not rebase,
  reset, or otherwise synchronize its branch with advancing `master` while its
  only unique state is uncommitted. Prefer a checkpoint commit on the task
  branch, then synchronize the committed branch.
- If a safety stash is genuinely necessary, give it a task-specific name and
  include untracked files. Restore it once, verify the resulting worktree, and
  drop it after the corresponding work is committed. Report any retained stash
  and why it is still needed in the handoff.
- At review handoff, state the branch and exact short commit SHA, whether the
  worktree is clean, and which checks passed, failed, or were not run. Treat
  review-ready and merge-ready as separate states.
- Before removing a worktree or branch, require a clean worktree, no retained
  task-related stash, and no commits that still need integration. An ancestry
  result such as `git branch --merged` says nothing about uncommitted files.

## Working on PCP

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
  temporary directories. Treat `pcp --rm`, remote destinations, bootstrap
  installation, and operations on real user data as potentially destructive.

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
