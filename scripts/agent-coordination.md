# Agent coordination

`python3 scripts/agent-coordination.py` coordinates sessions on one machine
through shared files. It needs Python 3.9 or later on Linux or macOS. Reviews
also need Git, `gh`, tmux, and the selected `claude` or `codex` executable.
It does not install tools, change their permission settings, or inject terminal
input. Reviewers receive access to the selected state directory with `--add-dir`.
Run it from your task worktree. If that branch predates the tool, invoke the
script by absolute path from a checkout that contains it. Keep that checkout
available while its reviewer requests are active; their prompts record its path.

The default state directory is `agent-coordination/` inside the common Git
directory (usually `.git/agent-coordination`), shared by all its worktrees.
It stays out of commits and survives `cargo clean`. This keeps publications
and review history separate from brief `current-plans/` handoff notes. Use `--state-dir PATH`
or `SYQ_COORDINATION_DIR` to select another **local** directory. Keep real host
names, session identifiers, and reports in that private state, not in commits.
Do not put the state on network storage or edit its JSON while commands run.
A file lock serializes updates; Markdown publications are separate files.
State has a version, and an incompatible version is rejected rather than reset.

Commands print JSON. Exit 0 means the operation succeeded, 2 means an error or
wait timeout, 3 means a resource request is queued, and 130 means interrupted.
Check the returned `status`; publishing a request is not the same as receiving
a resource or completing a review. Waits print progress to stderr and have a
deadline. There is no daemon to keep running.

## Resource access

Reservations are opt-in. Ordinary builds and tests, including review validation,
do not need a claim or a resource-status check. A benchmark request does not
require other agents to stop work or give its owner a quiet machine. Prefer
continuing useful work and acknowledging possible measurement interference over
blocking unrelated tasks.

When particular benchmarkers want to avoid overlapping comparisons, they can
agree on a named resource and take turns using it. The claim coordinates those
participants only. Check their existing arrangements before moving that queue
into the registry; a new, empty registry is not evidence that a server is unused.

```sh
python3 scripts/agent-coordination.py resource define benchmark-comparison \
  --description 'Optional turn-taking between participating benchmark runs'
python3 scripts/agent-coordination.py resource acquire benchmark-comparison \
  --agent benchmark-task --wait 60
# Once held, run the comparison agreed with the other participants.
python3 scripts/agent-coordination.py resource release CLAIM_ID --agent benchmark-task
```

Use a stable, distinct agent name for your task/session. Exclusive claims are
the default; `--mode shared` also allows several participating users at once.
These are mechanisms for an arrangement you choose, not mandatory rules for
builds, tests, benchmarks, or remote access.

Without `--wait`, acquire returns a ticket immediately (exit 3 when queued).
You can do other work and later use `resource wait CLAIM_ID --agent NAME
--timeout 60`. Ask for all needed resources in one command, e.g. `resource
acquire source-server destination-server --agent NAME --wait 60`; acquisition
is all-or-nothing. Conflicting requests are served in arrival order. Shared
requests may run together, but cannot jump ahead of an earlier exclusive waiter.
Unrelated resources can proceed independently.

`resource status` lists definitions, owners, and waiters. `resource cancel`
withdraws a queued request; it refuses to cancel a held claim. A **wait timeout
preserves the ticket and its queue position**. Call wait again with the same
ticket; do not acquire a replacement. A claim can become held after a timeout,
so inspect it and release it if no longer needed. Signal-based interruption
withdraws the unused claim, including a grant racing with cancellation. Do not
use wait again on a claim you are already using.
Release only after your commands and their children have stopped. Claims are
cooperative reservations, not OS-enforced access controls.

Signal-based interruption (SIGINT, SIGTERM, SIGHUP) withdraws a waiting claim.
A runtime may stop its turn without signalling the waiting process; after
Escape, inspect the ticket rather than assuming it was cancelled. The command
still has its deadline.

Claims do not expire: a dead agent can leave live remote jobs. If an agent is
killed without cleanup, check its work before explicitly releasing its ticket
using its recorded agent name. The name prevents accidental cross-task releases;
it is not authentication. Never remove another owner's claim merely because it
looks old.

## Topic publications

Topics are useful when coordination needs an explanation rather than a lock.
`topic list` shows existing topics and their subscribers, so an agent can
discover which sessions are interested without messaging everyone.

```sh
python3 scripts/agent-coordination.py topic subscribe transfer-experiments --agent implementation
python3 scripts/agent-coordination.py topic publish transfer-experiments --agent reviewer \
  --title 'Comparison ready' --body-file target/comparison.md
python3 scripts/agent-coordination.py topic read transfer-experiments --agent implementation
python3 scripts/agent-coordination.py topic ack transfer-experiments 1 --agent implementation
```

Read returns paths to unread Markdown publications; it does not acknowledge
them. Subscriptions initially include the existing publications. Acknowledge
the highest sequence you have handled, and unsubscribe when no longer interested.
Resource releases also publish a short update on `resource.RESOURCE_NAME`.

File reads and waits work with both Claude Code and Codex. Optionally register
a **saved** Codex session and add `--notify` to publication or review start:

```sh
python3 scripts/agent-coordination.py agent register implementation \
  --codex-thread SESSION_ID --remote ws://127.0.0.1:PORT
```

Omit `--remote` only when your sessions use Codex's default local app-server.
This requires an existing reachable server; the tool does not migrate sessions
or start a daemon. `codex queue` in 0.155.1 was tested to start an idle session,
queue behind an active turn, and preserve unsent terminal text. Escape left
pending messages queued. Delivery is a hint, not confirmation that an agent read
or acted on a publication; failures are returned alongside the published result.
Notifications go only to subscribers with registered endpoints (or the requesting
review agent), never every running session. No native Claude push adapter is
included; use the shared reads/waits. Do not use `--notify` when the requester is
already waiting for the same report: it would queue a redundant later turn.

## Review and triage

Run the project’s required validation and `scripts/branch-status.sh` before each
review handoff and report its output, including unrelated red master checks.
From a clean, pushed task branch with an open PR, provide a short task brief
under `target/` or `current-plans/`. Include the user's actual requirements,
constraints, exclusions, and unresolved questions. Label your own assumptions.
The PR description by itself is not evidence of what the user requested.

```sh
python3 scripts/agent-coordination.py review start --pr 123 --agent implementation \
  --reviewer claude --mode triage --brief target/task-brief.md
```

Choose `--reviewer codex` for a Codex reviewer. The tool resolves the GitHub PR
head and repository identity, checks that your clean task branch matches it,
fetches the head/base commits, and creates one detached worktree for the review
request plus a tmux reviewer window. Later rounds advance that same worktree
without clearing `target/`, so builds can reuse their existing artifacts. The
worktree name includes the PR number and request ID, and stays stable as the SHA
changes. A dirty checkout is preserved and must be resolved before advancing.
The window runs an ordinary interactive reviewer with an initial prompt; no
keystrokes are injected. You can attach and discuss its findings. The reviewer
reads the project’s existing `AGENTS.md`; no standing resource policy is added.

Each review round has its own prompt, immutable report, and triage Markdown.
Reviewers finish their commands before submitting: publication allows the next
round to advance the shared checkout. Old reviewer conversations remain available,
but must check HEAD and use their recorded SHA when discussing older code.
The reviewer publishes by running the `review submit` command in its prompt,
including the round number, reviewed SHA, and verdict (`clean`, `findings`, or
`blocked`). A terminal answer or a process exiting successfully is not enough.
If the reviewer exits without submitting, status becomes `failed`.

The requesting agent stays in the original conversation:

```sh
python3 scripts/agent-coordination.py review wait REVIEW_ID --timeout 60
# Read the returned report path and independently assess the findings.
python3 scripts/agent-coordination.py review triage REVIEW_ID --agent implementation \
  --sha REVIEWED_SHA --action discuss --body-file target/triage.md
```

`review list` finds existing requests and their owners.
Interrupting or timing out a review wait does not stop the reviewer. Check
`review status REVIEW_ID` or wait again. The returned `next_action` tells the
requesting agent how to continue. Mode determines what you are asking it to do:

| Mode | Requesting agent's work |
| --- | --- |
| `collect` | Leave the report available; no automatic triage. |
| `triage` (default) | Wait, assess each finding, and discuss the assessment with the user. |
| `auto` | Wait, assess, fix confirmed straightforward defects in scope, validate, commit/push, and request another review. |

In auto mode, the **implementing agent drives the loop** by following the
returned instructions. This is not a separate background fixer; the original
conversation keeps its task context. It works with either implementing runtime
because a wait returns a tool result. If that conversation stops, it will not
continue autonomously until resumed. A request alone does not ensure its agent
keeps following the loop.

Record decisions with `review triage`: `--action complete` requires the current
clean GitHub head to equal the reviewed SHA; `--action discuss` pauses for the
user. In auto mode, `--action revise` starts the next round after the fixes are
committed and pushed. In the other modes it records `needs_revision`; use
`review next REVIEW_ID --agent NAME` explicitly after making agreed changes.
Use `--unresolved FINDING_ID ...` to record persistent issues. Repeating an
unresolved identifier stops the loop for discussion. A report marked blocked
also requires discussion. Reviewer suggestions are not new user requirements.

Auto mode is opt-in and defaults to at most three rounds (`--max-rounds N`).
An unchanged SHA stops for lack of progress. Failed attempts without a published
report can be retried with `review next`; an explicit request to review an
already reviewed SHA again uses `review next --allow-unchanged`. Semantic repetition still needs the
implementer's judgment and stable finding IDs; the tool does not decide whether
a finding is valid. Disagreements, requirements changes, or consequential
tradeoffs must go to the user rather than cycling until the reviewer agrees.
Previous reports/dispositions stay available, while reviewers are instructed to
inspect the new code independently first. Review completion never grants merge
permission. These are workflow instructions, not a sandbox around the agents.

`review stop-loop REVIEW_ID --agent NAME` prevents continuation without killing
an interactive reviewer or its jobs. An outstanding reviewer may still submit
its report, but that submission does not restart the loop. The request’s worktree and reviewer
windows are retained for discussion; inspect cleanliness and running processes
before removing them with normal Git/tmux commands.

## Checks

```sh
python3 scripts/test-agent-coordination.py
```

Tests use disposable state and repositories, exercise concurrent claims and
interrupts, and substitute agent/provider commands. They do not send messages to
real agents, run model inference, access servers, or build Rust.
