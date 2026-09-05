# Coordinated local-source copies

This describes PR #105's implementation after synchronization with master
`fed326b` on 2026-09-05. It records the implementation and its maintenance
obligations; it is not a decision to include the feature in a release.

Each destination runs the existing transfer engine. The coordinator in
`src/fanout.rs` shares source scan entries, waits for every destination's
read-only plan, combines progress and results, and propagates fatal failures.
File contents, verification, resume, publication, and pruning still go through
the existing engine. The feature adds no wire messages or receiver grants.
Restricting the source to local paths avoids adding a multi-destination remote
credential model.

## Boundaries to preserve

- Every destination must finish planning before any destination mutates. The
  small-copy optimization explicitly declines coordinated runs because its
  single request includes publication. A future path that publishes early
  must participate in the barrier or make the same exclusion. The mixed
  eligibility regression tests success and refusal without leaving a member
  waiting at the barrier.
- Each member gets a terminal result even when a peer fails. Human diagnostics
  are best effort; a closed stdout or stderr must not lose machine results or
  change the copy's exit status. SIGINT and SIGTERM retain their usual signal
  exit behavior and do not promise a sealed results stream.
- Cancellation must reach transports as well as scheduler state. A member's
  remote specs share a cancellation token, and newly opened SSH child groups
  and TCP sockets register with it. Backoff and bandwidth waits wake on abort.
  New transport setup paths need the same ownership rule.
- The token owns only process groups it created. Registration is serialized
  with child creation; reaping is serialized with cancellation. Exit is
  inspected with `waitid(WNOWAIT)` so descendants can be stopped before the
  leader's PID becomes reusable. The existing signal-cleanup handler cancels
  these tokens before invoking the signal's default action.
- Persistent SSH masters belong to their persistence scope. Coordinated copies
  reuse those masters but open their own helper sessions: a session borrowed
  from the session pool is owned by another process and cannot use the same
  cancellation mechanism. Both real-SSH profiles check that masters remain
  usable across successive coordinated copies.

This is not a transaction after preflight. Completed work remains after a
fatal failure; a retry converges using the usual placement and resume rules.
Individual file failures and deletion-limit refusals retain their documented
23/25 exit statuses and do not cancel peers. A fatal exit 1 does.

Cancellation interrupts the registered transports. It does not establish a
universal deadline for synchronous local filesystem calls or the updater's
local release-asset fetch. Those keep the existing engine's behavior. Setup
checks prevent a cancelled remote bootstrap from starting an upload fallback.
The regression that motivated this work specifically covers a stalled SSH
handshake, including a shell child holding its pipes open.

## Validation

The local regressions cover closed stderr, mixed small-copy eligibility,
preflight cancellation with a stalled helper and child cleanup, existing
fan-out semantics, and the new cancellation primitive's process/socket races.
`tests/real-ssh/fanout.py` exercises two isolated OpenSSH destinations over SSH
and required encrypted TCP, persistent master reuse, preflight refusal,
interrupted active copies, a fatal peer during live transfer, terminal results,
cleanup, and checksum-verified retries. The capacity failure uses an existing
debug fault with a bounded barrier so it occurs after the other target has
actually transferred bytes.

The Rust baseline and all targets passed at `f3422e4`: 437 unit tests, 399 local
integration tests, 3 output tests, and 7 update tests. The Rust implementation
is unchanged at `71c98b2`; that commit adds the persistent-master SSH scenario.
Both real-SSH profiles passed at `71c98b2`. All 88 Python tests, the native API
inventory, documentation links, and the pinned mdBook build passed too.

Linux validation does not establish macOS runtime behavior. Master `fed326b`
has independent failures in two session-pool integration tests and a small-copy
staging test whose temporary path crosses macOS's `/var` symlink. Those failures
are visible in run [33935564035](https://github.com/greaber/syq/actions/runs/33935564035),
which does not contain this PR. The launch decision still needs to account for
that platform state and a review of the updated PR.

## Scaling measurements

Measured the release build `v0.2.0+dev.71c98b2dfacb` on Linux/ext4, on an AMD
EPYC 9454P machine with 96 logical CPUs. The benchmark uses actual syq helper
protocols through a local fake SSH command, isolated temporary homes, and fresh
destinations. It compares one coordinated command with simultaneous independent
commands. It verifies every resulting file outside the timed interval.

The large-tree case has 50,000 files of 1 KiB in 500 directories and two workers
per target. Values below are **coordinated / independent**, with one measured
pair at each size. Each mode has the same aggregate worker count.

| Targets | Wall time, s | First mutation, s | Client peak RSS, MiB | Helper sessions, each |
| --- | --- | --- | --- | --- |
| 2 | 4.10 / 3.91 | 0.365 / 0.245 | 173 / 153 | 6 |
| 4 | 4.41 / 4.10 | 0.365 / 0.269 | 338 / 305 | 12 |
| 8 | 5.28 / 5.15 | 0.389 / 0.314 | 668 / 609 | 24 |

The coordinated case used about 10–14% more client RSS and started destination
mutation 75–120 ms later. Its wall time was 3–7% longer in these samples. Memory
still grows with the number of destination plans: eight targets took about
668 MiB in the client alone. The shared scan does not make planning memory
independent of the destination count.

A second campaign used 10,000 files and default per-target tuning. Both modes
opened 18, 36, and 72 helper sessions at two, four, and eight targets respectively.
At eight targets the coordinated command took 1.20 s versus 1.06 s, and client
RSS was 266 MiB versus 331 MiB. These results reinforce the distinction between
an explicit aggregate worker budget and the independent defaults; the number
of control and data sessions grows with the target count in either mode.

RSS is sampled every 20 ms, includes only the client process(es), and sums RSS
across independent clients; shared pages can therefore be counted more than
once in that sum. It excludes remote helpers, SSH masters, filesystem cache,
and the Python harness. First mutation means creation of the first destination
root, not first file completion. Caches were not evicted. These are local
coordination measurements on one machine, not SSH latency/throughput estimates
or a statistical performance guarantee.

The conclusion at measurement time is that the coordination overhead is
moderate compared with running the same independent copies. The feature is not
a general speed optimization. Its useful guarantees are one source selection,
an all-target planning boundary, and one set of results. Large target counts
still require memory for each destination's work and wait for the slowest
preflight.

Raw samples: [fanout-2026-09-05.jsonl](measurements/fanout-2026-09-05.jsonl).
Reproduce with the checked-in harness (increase repetitions for comparisons):

```sh
cargo build --release --locked
python3 scripts/bench-fanout.py --files 50000 --targets 2 4 8 --repetitions 3
python3 scripts/bench-fanout.py --files 10000 --targets 2 4 8 --workers-per-target 0 --repetitions 3
```
