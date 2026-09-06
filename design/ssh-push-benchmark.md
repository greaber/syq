# Historical Mac to j5 SSH push investigation (persist mode)

**The runtime proposal described here was withdrawn at `4a9372e` after the
[primary persistence-off comparison](ssh-push-benchmark-cold.md) did not show an
improvement.** This note preserves the earlier experiments and their original
interpretation; references to the final change below describe that proposal.

2026-09-06. Grant's interactive quick benchmark reported these means over
three trials: a 64 MiB file, syq 29.269 seconds versus rsync 22.397; 1,024
files of 8 KiB, syq 9.640 versus rsync 6.172.

**Benchmark profile: syq persist mode with an untimed connection warmup;
rsync opens a fresh SSH connection for each timed trial.** These results
describe repeated copies with syq persistence enabled. They do not establish
that syq beats rsync when both start without an existing SSH connection.

The investigation found avoidable SSH startup work for small trees, plus
large variations in the network and an SSH keepalive policy that terminated
control connections during TCP transfers. The final change reduces small-tree
startup. It leaves the range split threshold, pipeline depth and streaming
selection unchanged. The measurements do not establish a consistent large-file
win over rsync.

## Method and versions

The sender is an Apple M4 Pro Mac running macOS 26.5.2, OpenSSH 10.2p1 and
rsync 3.4.1. Installed syq reports `v0.4.0` (release commit `f4aee996`). The task
starts at `7d5062d`; its transfer, connection and tuning code matches that
release. SSH persistence was already enabled on the Mac. The original mini
benchmark script does not explicitly enable it; it inherits that setting, and
its untimed 14-byte setup copy can warm an enabled persistent connection.

The comparison uses a dense random 64 MiB file and 1,024 random 8 KiB files,
reused across all tools. Every destination starts empty. Syq uses
`cp --preserve=permissions --srcs-in SOURCE --to j5 --into-existing DEST --stats`;
rsync uses `-rpt SOURCE/ j5:DEST/`. Source creation, destination creation,
helper warmup and SHA-256 verification are outside the timer. Every completed
copy is verified. Failed copies are recorded as failures, without a speed.

The candidate Mac and Linux helpers are release-profile builds at `57abd37`;
the experimental streaming builds are at `f629e09`. Each family has its own
temporary persistence scope, an untimed connection warmup and an explicit
matching helper path, including the released baseline. Rsync has no connection
warmup or connection reuse between timed trials. Its SSH login is timed; syq
can reuse its authenticated control login and helpers from setup. Additional
syq data logins and recovery from a lost connection are timed. This difference
in startup costs must accompany any comparison of the elapsed times. XDG
configuration and cache locations are isolated from the user's settings. The repeated comparisons rotate tool
order. Compilation and large downloads do not run alongside timed copies.

[The trial records](ssh-push-benchmark-results.csv) preserve 80 trials, including
five failures, across six comparison phases and the interrupted route change.
The CSV labels each row with `ssh_connection_policy` (`persist-mode` for syq,
`fresh-per-trial` for rsync) and `untimed_connection_warmup`. These fields record
the configured procedure, not a guarantee that a warmed connection survived
until the trial; timeout recovery is described below. Persistence applies to
the SSH control connection even when the payload uses TCP. Early diagnostic
runs described below are separate from that table. The last two phases also capture SSH debug logs and run helpers through wrappers that
record process exits; the wrappers forward the same helper protocol unchanged.

## Network and disconnects

Initial SSH traffic used NordVPN's `utun12` interface. Syq's advertised TCP
addresses were unreachable, causing SSH fallback. The one-second route probe
window overlaps some planning, but its remaining delay still costs time.
`--no-tcp` avoids it when SSH is selected deliberately.

During the investigation the SSH route changed to `en0`; the agent did not
change network configuration. Syq's TCP path through the peer's Tailscale
address also became reachable. A streaming-branch range copy lost its control
connection around that transition. Results before and after it remain separate.
A later Tailscale status snapshot showed a direct peer address. The Tailscale
data path and public SSH path still need not have identical performance.

The sender's effective SSH settings were `ServerAliveInterval 3` and
`ServerAliveCountMax 2`, with `LogLevel QUIET`. SSH debug logs captured
`Timeout, server ... not responding.` for both the released binary and the
candidate. Losing the control helper removed its descriptor broker and closed
its TCP workers. Syq reported those transfers as failures. Helper exit logs
showed normal exits after losing their input, rather than a Rust panic.

This also affected later measurements: after a master died, the next copy
needed a new control login. The first repeated candidate small-tree trial
includes that recovery. Another successful small-tree trial took 60.406 seconds
(30.32 seconds sending and 27.84 waiting for acknowledgements). It remains in
the results; the cause of that long stall was not established.

A final comparison applied `ServerAliveInterval=15` and
`ServerAliveCountMax=3` to both tools through a temporary SSH wrapper. One
released-binary TCP trial still timed out. A longer timeout therefore does not
by itself make this TCP route reliable. Forced SSH is the more useful starting
point for further tuning of this machine. No SSH or network configuration was
changed permanently.

## Small-file startup change

Previously, persistence reused the control login but refused all data-worker
reuse of that login. An initial instrumented small-file copy had control ready
in 0.02 seconds, then waited 3.03–5.70 seconds for six data logins. It took
14.251 seconds overall, versus 6.850 for rsync.

The final runtime change, narrowed at `dff47fc`, does two things for fresh
small-file SSH copies totaling at most 16 MiB:

- Start one active worker when connection count is automatic. The existing
  tuner may keep a spare ready and grow when enough work remains. Explicit
  worker counts remain explicit.
- Allow data channels to reuse a persistent login for these bounded copies.
  A refused shared channel still retries with an independent login. Larger
  trees retain independent data connections when persistence is enabled.

The bound limits how much payload one copy adds to a login shared with other
commands. It is a scheduling choice, not a receiver quota or a guarantee that
shared channels always win. Existing per-copy multiplexing without persistence
is unchanged.

In the final three-round comparison, both tools used the longer SSH keepalive
setting. Syq used **persist mode with an untimed warmup** and `--no-tcp`;
rsync opened a **fresh SSH connection per trial**:

| Small-tree variant | Mean seconds | Min | Max | Completed |
| --- | ---: | ---: | ---: | ---: |
| Released syq, persist mode, explicit `-j 1` | 12.037 | 9.657 | 14.041 | 3 |
| Candidate syq, persist mode, automatic count | 7.314 | 6.828 | 8.063 | 3 |
| rsync, fresh SSH connection | 8.059 | 7.559 | 8.435 | 3 |

The released `-j 1` row includes control recovery after the failed TCP trial;
it is not an estimate of purely warm startup. Candidate data-worker startup was
about 0.6–0.7 seconds. With persist mode enabled and its initial connection
warmup untimed, the candidate took less time than fresh-connection rsync in two of three trials,
and averaged about 9% less time. That result includes the benefit of connection
reuse; it is not evidence of an advantage with fresh connections for both tools.
The earlier 60-second stall and the small sample size rule out an unconditional performance claim. These measurements
use `57abd37`; the later narrowing only restores large-file range splitting,
which does not affect this small-file path.

The final mini-script smoke test used the same asymmetric startup profile with
the narrowed runtime at `1f6a12c`, forced SSH and the longer keepalive setting.
These are one trial each, with every completed copy checked using POSIX cksum:

| Workload | syq, persist mode with untimed warmup | rsync, fresh SSH connection |
| --- | ---: | ---: |
| 64 MiB file | 25.771 s | 26.612 s |
| 1,024 files of 8 KiB | 7.971 s | 9.051 s |

## Large files, pipeline depth and streaming

The first 64 MiB SSH trace used one worker for all 16 blocks while the others
stayed idle. Stealing requires twice the 32 MiB split minimum still unread;
after the first 4 MiB request, only 60 MiB remains. Workers that authenticate
later cannot help. If multiple workers become ready before reading begins,
the old threshold can already allow two of them to share the file.

The initial candidate lowered the remote split minimum to 8 MiB. This allowed
more workers to help, and some exploratory SSH trials improved substantially.
The repeated results did not support changing the default. All syq rows below
use persist mode with an untimed connection warmup; rsync starts a fresh SSH
connection for each trial:

| 64 MiB, original keepalive settings | Mean seconds | Min | Max | Completed |
| --- | ---: | ---: | ---: | ---: |
| Released syq, persist mode, forced SSH | 25.873 | 25.059 | 27.495 | 3 |
| Candidate syq, persist mode, 8 MiB splitting, forced SSH | 27.735 | 23.376 | 33.930 | 3 |
| Streaming syq, persist mode, 1 MiB blocks, one SSH worker | 33.280 | 24.206 | 39.870 | 3 |
| Ranges syq, persist mode, 1 MiB requests, depth 16, one SSH worker | 28.886 | 28.034 | 30.230 | 3 |
| rsync, fresh SSH connection | 26.165 | 22.684 | 29.302 | 3 |

The final longer-keepalive TCP comparison also favored the old split threshold:
the candidate completed in 28.839, 31.941 and 37.224 seconds; the release
completed in 21.474 and 26.378 seconds, with one additional failed trial.
Consequently `dff47fc` restores the original 32 MiB default everywhere.
`split-min-size=8M` remains available as an explicit experiment.

Single-trial exploration also tested 256 KiB and 4 MiB requests/streaming
blocks, pipeline depths 4 and 64, and four streaming workers. Increasing depth
to 64 was not better. The debug traces mostly show time blocked writing to SSH,
with almost identical wire byte counts for ranges and streaming. No pipeline
or streaming default change is justified by these measurements.

To compare the existing controls explicitly, fix the transport and connection
count. For example, on the streaming branch compare
`--no-tcp -j 1 --tuning-options copy-path=ranges,request-size=1M,pipeline-depth=16`
with `--no-tcp -j 1 --tuning-options copy-path=streaming,request-size=1M`.
Streaming does not accept a pipeline-depth override. Use matching development
helpers and verify every destination; do not mix different routes or cold
control recovery into an unlabeled mean.

## Compatibility and validation

The final change affects SSH channel selection and initial worker count. It
changes no helper messages, anchor tickets, signed authority, receipts, resume
identities, persistence preferences, completion records or connection-count
cache formats. No signing domains, filenames, SDK keywords, CLI options,
updater manifests or documentation URLs change. Old and new commands can use
the same persisted formats; managed helpers still require exact build identities.
No migration or cache invalidation is needed. Existing fixtures remain unchanged.
This does not establish an indefinite support baseline for future changes.

Connection tests cover the persistent payload boundary, nonpersistent reuse
and disabling reuse after refusal. The new integration test checks automatic
versus explicit worker counts, every copied file and recovery after shared
channel refusal. The real-SSH lab adds a persistent small-tree copy with every
file verified. Both normal and `MaxSessions=1` lab profiles exercise the change.

Validation includes formatting, clippy with all targets/features and warnings
as errors, unit tests and all integration targets. Full-suite runs use isolated
XDG configuration/cache locations and four test threads: an initial ambient
run inherited the user's persistence policy and failed invocation-count
expectations, and a timing-sensitive pool retry missed its window under load.
Those checks passed on the isolated rerun. Final check results and exact commit
are recorded in the pull request.
