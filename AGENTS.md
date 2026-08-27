# Agent guidance

## Worktrees

Start any task that may change the repository in a task-specific git worktree,
before investigating or editing code for that task. Treat the primary checkout
as a coordination checkout: keep it on `master`, do not edit tracked files
there, and do not disturb changes already present.

Check `git status` and `git worktree list` before choosing a worktree. Use one
branch and one worktree per task; the normal setup from the primary checkout is:

```bash
git worktree add .worktrees/<task> -b <task> master
cd .worktrees/<task>
```

Continue in an existing worktree only when you created it for the current task
or the user explicitly identified it as the target. Never infer ownership from
a plausible branch name. Before editing, confirm that
`git rev-parse --show-toplevel` points at the task worktree.

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
