# Agent coordination

`python3 scripts/agent-coordination.py` coordinates sessions on one machine
through shared files. It needs Python 3.9 or later on Linux or macOS. Reviews
also need Git, `gh`, and the selected `claude` or `codex` executable. It does
not install tools. It runs reviewers in the background with permission prompts
turned off, at `xhigh` effort by default; see
[Reviewer settings](#reviewer-settings). Reviewers receive access to the
selected state directory with `--add-dir`.
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
so inspect it and release it if no longer needed. Do not use wait again on a
claim you are already using.
Release only after your commands and their children have stopped. Claims are
cooperative reservations, not OS-enforced access controls.

Signal-based interruption (SIGINT, SIGTERM, SIGHUP) withdraws the unused claim,
including a grant racing with cancellation.
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
discover which sessions are interested without messaging everyone. Subscribe or
publish to create a topic; read, wait, ack, and unsubscribe reject unknown names.

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

A subscribed agent can wait for an update without notification delivery:

```sh
python3 scripts/agent-coordination.py topic wait transfer-experiments --agent implementation --timeout 60
```

The wait returns unread events and leaves them unread until `topic ack`. A
timeout or interruption preserves the subscription and cursor; wait again when
ready. This works for general coordination with either runtime. It does not
wake an agent that has stopped checking updates.

## Review and triage

Run the project’s required validation and `scripts/branch-status.py` before each
review handoff and report its output, including unrelated red master checks.
From a clean, pushed task branch with an open PR, provide a short task brief
under `target/` or `current-plans/`. Include the user's actual requirements,
constraints, exclusions, and unresolved questions. Label your own assumptions.
The PR description by itself is not evidence of what the user requested.

```sh
python3 scripts/agent-coordination.py review start --pr 123 --agent implementation \
  --mode triage --brief target/task-brief.md
```

Claude is the default reviewer; choose `--reviewer codex` for a Codex reviewer.
[Reviewer settings](#reviewer-settings) lists the model, effort, and permission
flags each one uses. The tool resolves the GitHub PR head and repository
identity, checks that your clean task branch matches it, fetches the head/base
commits using matching configured repository URLs, and creates one worktree and
one reviewer session per request. Later rounds advance that worktree without
clearing `target/`, so builds can reuse artifacts. The worktree name includes
the PR number and request ID, and stays stable as the SHA changes. A fork base
without a configured remote uses its GitHub HTTPS URL. A dirty checkout is
preserved and must be resolved before advancing. The reviewer reads the
project’s existing `AGENTS.md`; no standing resource policy is added.

Each round runs one non-interactive reviewer process in the background,
detached from the command that started it. The first round starts the
reviewer's session and later rounds resume it, so the reviewer keeps its
context; nobody can answer its questions while it runs. Its output goes to
`reviewer.log` next to the round's prompt in the state directory. `review status
REVIEW_ID` shows the process ID (`pid`), whether it is still `running`, and the
`log` path. The process starts from the command that launched it, so it runs in
that command's sandbox, if any, but it does not inherit the requesting agent's
own Claude Code or Codex session variables.

Each review round has its own prompt, immutable report, and triage Markdown.
The reviewer publishes by running the `review submit` command in its prompt,
including the round number, reviewed SHA, and verdict (`clean`, `findings`, or
`blocked`), and then ends its turn, which ends the process. A final answer or a
process exiting successfully is not enough. Submitting hands the checkout back
to the implementer, so reviewers finish their commands first. When the next
round is requested while the previous process is still finishing, the tool waits
up to a minute for it to exit.

If the process exits or dies without submitting, the status becomes `failed`
and `next_action` names the log. `review resume REVIEW_ID --agent NAME` reruns
that round in the same session, and `review next` starts a new round at the
current PR head; both refuse while a reviewer process is running. Codex reports
its session ID when it starts, and the tool records it. If none was recorded, a
rerun starts a new Codex session unless you supply the exact ID with `--session`.
A request started by an earlier, interactive version of this tool can still
submit its report and be triaged; exit that interactive reviewer in its tmux
pane before starting another round. Use the same tool version for all
participants in a review request.

To request an independent second reviewer, run another `review start` with
`--additional-reviewer`, choosing Claude (the default) or Codex with
`--reviewer`. It gets its own session, process, worktree, reports, round limit,
and reviewer settings, all reused across its own rounds. Each request is triaged
separately; there is no automatic agreement rule between reviewers. Use collect
or triage mode when you want to compare their reports before deciding on fixes.

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

Auto mode is opt-in and defaults to at most three published review rounds
(`--max-rounds N`). Attempts that fail without publishing a report do not count;
attempt numbers still increase to keep their records distinct. At the completed
round limit, start a new request if you want further review.
An unchanged SHA stops for lack of progress. Failed attempts without a published
report can be retried with `review next`; an explicit request to review an
already reviewed SHA again uses `review next --allow-unchanged`. Semantic repetition still needs the
implementer's judgment and stable finding IDs; the tool does not decide whether
a finding is valid. Disagreements, requirements changes, or consequential
tradeoffs must go to the user rather than cycling until the reviewer agrees.
Previous reports/dispositions stay available, while reviewers are instructed to
inspect the new code independently first. Review completion never grants merge
permission. These are workflow instructions, not a sandbox around the agents.

`review stop-loop REVIEW_ID --agent NAME` prevents continuation without stopping
a running reviewer process. That reviewer may still submit its report, but the
submission does not restart the loop. The request’s worktree is retained; check
that its reviewer is no longer `running` and that the worktree is clean before
removing it with `git worktree remove`.

### Reviewer settings

Both reviewers run at `xhigh` effort with permission prompts turned off:

| Reviewer | Model | Effort and permission flags |
| --- | --- | --- |
| `claude` | `--model claude-opus-5-5` | `--effort xhigh --dangerously-skip-permissions` |
| `codex` | `--model gpt-6-astra` | `-c 'model_reasoning_effort="xhigh"' --dangerously-bypass-approvals-and-sandbox` |

Claude runs as `claude -p --output-format stream-json --verbose`, with
`--session-id` in the first round and `--resume` afterwards. Codex runs as
`codex exec --json`, and later as `codex exec resume SESSION_ID`. The reviewer
therefore runs any command it chooses as your user, without asking and, for
Codex, without a sandbox. Start reviews only where you would run that tool the
same way yourself.

`--model MODEL` and `--effort LEVEL` override the defaults; lower effort suits
small or test-only changes. For Codex, `--model gpt-6.1-sol` selects GPT-6.1
Sol instead of GPT-6 Astra:

```sh
python3 scripts/agent-coordination.py review start --pr 123 --agent implementation \
  --reviewer codex --model gpt-6.1-sol --effort high --additional-reviewer \
  --brief target/task-brief.md
```

To add any other argument, repeat `--reviewer-option` once per argument; for
example, `--reviewer-option=--append-system-prompt --reviewer-option='Focus on
the wire protocol.'` adds to a Claude reviewer's system prompt. Each value is
one argument, with no shell interpretation; write a value that starts with `-`
as `--reviewer-option=VALUE`. The request records these settings and uses them
for every reviewer process it runs, including later rounds and reruns.

## Checks

```sh
python3 tests/tooling/test-agent-coordination.py
```

Tests use disposable state and repositories, exercise concurrent claims and
interrupts, and substitute agent/provider commands. They do not send messages to
real agents, run model inference, access servers, or build Rust.
