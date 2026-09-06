# Existing-directory remote setup

The coordinator pipelines three existing requests when pushing into an existing
remote container: `CheckOperatorDirectory`, `DestinationFilesystemInfo`, and
`AnchorDestination`. This replaces three request/response turns with one.
The initial destination stat supplies the device/inode pair the receiver must
match before issuing its anchor ticket. The receiver executes the requests in
order; selection and capacity inspection read metadata, and anchoring registers
a descriptor without changing destination files. All three replies are consumed
even when a check fails, keeping reusable streams aligned.

Same-machine copies retain their ancestry checks before anchoring. Exact
placement retains its parent-based setup, and restricted receivers retain their
existing authorization path. Verification and `--existing` also keep their
existing setup. Filesystem-counter failures remain advisory; anchoring failures
remain fatal. Namespace and capacity refusal still precede file publication.

For a buffered small-file tree in a confirmed-empty remote destination, TCP
workers start after the source population is known, while capacity assessment
and destination planning finish. The starting count uses the same file/byte
batch limits as normal scheduling. No file jobs are released before the
preflights pass; planning failure aborts the idle workers. This overlap excludes
same-machine copies, dry runs, verification, in-place copying, checksumming,
update/ignore-existing, forced ranges, and bandwidth-limited copies.

## Overlapping route probes with buffered planning

For buffered planning into an existing destination, the coordinator settles
pending TCP address probes after the source scan and sidecar namespace checks.
Those checks use the control connection and do not mutate the destination.
The complete probe window and bandwidth-based address selection are unchanged;
only the point at which the coordinator joins the probe thread moves.
Transport selection, the tuning cache lookup, and initial connection counts
still settle before any worker starts or the buffered plan is replayed.
Unreachable ordinary TCP routes still fall back to SSH.

Initially missing destination trees retain their earlier worker startup during
scanning. Unbuffered planning retains its previous setup order, since it can
release work while scanning. Signed receivers settle TCP before destination
creation because their one-time grants cannot be replayed for SSH fallback.
Detached copies also retain their earlier setup order so readiness notification
does not wait for a potentially long source scan. No extra scan or buffering
is introduced to obtain the overlap.

The regression test records coordinator setup events separately from helper
stderr. It checks scan-before-transport ordering for an empty existing remote
directory, the previous ordering for missing destinations, forced SSH and
detached copies, successful fallback when advertised TCP is unreachable, and
an empty destination when a required TCP probe fails after scanning.

## Compatibility

No messages, state formats, resume identities, CLI options, or output fields
change. These setup requests and resume identities retain their v0.3.2 representation. Managed
helpers still require exact build identities before reading framed requests.
The compatibility probe deliberately speaks the v0.3.2 client's identity to
replay the new request order against the unchanged official v0.3.2 receiver;
it does not permit mixed-build production connections:

```sh
SYQ_V032_BINARY=/absolute/path/to/verified-v0.3.2-syq \
  cargo test --bin syq existing_destination_setup_replays_on_v032_receiver -- --ignored
```

The probe checks successful selection, capacity inspection and anchoring without
creating files. Normal tests also check replaced-inode refusal and reply draining
when each setup response fails. The explicit old-artifact test is ignored in the
ordinary suite because it requires a separately obtained released executable.

## Exploratory measurement, 2026-09-06

Baseline: clean master `588bc5f`. Candidate: the runtime changes described above,
built as `v0.3.2+dev.588bc5f8e255.dirty.482487edd17b`. Both used the pinned
release profile and `RUSTFLAGS='-C target-feature=+crt-static'` for compatibility
with the remote system. Tests, documentation, and an exclusion of local/same-host
early worker startup were finalized afterward; that exclusion does not affect
the measured remote push.

From the development host to SSH alias `j5`, copy 1,024 deterministic random
8 KiB files into a new empty directory for each trial:

```sh
syq cp --preserve=permissions --srcs-in SOURCE --to j5 --into-existing DEST --stats
# SSH data variant adds --no-tcp.
```

Helper installation was excluded. Three rounds reversed baseline/candidate
order on the middle round. Source data and OS caches stayed warm. Both variants
used eight workers and engineering timing output. Every completed destination
was checked outside timing with `rsync -rcn`. These are buffered-copy elapsed
times, not durable disk throughput. Builds/tests ran on the development host
during portions of the experiment; these are exploratory results, not a
publication benchmark.

| Transport | Baseline seconds | Candidate seconds | Mean baseline → candidate |
|---|---|---|---|
| SSH | 11.451, 11.050, 10.977 | 10.341, 10.377, 10.484 | 11.159 → 10.401 |
| Encrypted TCP | 10.849, 10.377, 10.545 | 10.113, 10.584, 10.250 | 10.590 → 10.316 |

The SSH improvement is consistent across these trials. The smaller TCP mean
improvement overlaps with run-to-run variation. RTT was about 260 ms. In the
last SSH pair, control connections were ready at 4.83/4.80 seconds; destination
preflight finished at 5.85/5.31 seconds, showing the two removed round trips.

In the last TCP pair, candidate preflight finished at 5.63 seconds, but address
probing delayed transport readiness until 6.12 seconds, matching the baseline.
Workers connected during subsequent candidate planning; the baseline waited
until planning completed to start them. The probing wait limits how much of
the reduced setup latency reaches the TCP elapsed result.

## Probe-overlap measurement, 2026-09-06

A follow-up compares clean `e6dc071` (the setup and early-worker changes above)
with clean `9e73649` (buffered planning overlaps route probes). Both use the
same static release build flags, 1,024-file source, copy command, stats/debug
output and verification method above. Each binary receives an untimed full-copy
warmup to install its exact helper; three measured rounds reverse case order
in the middle round. This task's builds and test suites finished before timing.
The source and OS caches remain warm, the machines and public route are shared,
and copies do not request durable disk writes. Every destination passed the
checksum comparison, and the disposable remote root was removed afterward.

| Transport | Baseline seconds | Candidate seconds | Mean baseline → candidate |
|---|---|---|---|
| Encrypted TCP | 10.251, 10.263, 10.303 | 10.019, 10.204, 10.437 | 10.272 → 10.220 |
| SSH control comparison | 10.522, 11.112, 10.965 | 11.111, 10.639, 10.903 | 10.866 → 10.884 |

The total TCP difference is only 0.052 seconds (0.5%), well within the observed
variation; these trials do not establish an end-to-end speedup. The internal
stages do show the intended overlap consistently. Time from control connection
readiness to completed payload planning was 2.36/2.39/2.33 seconds before and
2.09/2.10/2.12 seconds afterward: roughly one 260 ms round trip is covered by
the probe window. Remaining planning after transport readiness shrinks from
1.09/1.11/1.06 to 0.81/0.82/0.84 seconds. TCP worker authentication still overlaps
the later destination checks, and each trial starts eight workers.

This workload's scan covers only part of the roughly half-second probe wait
remaining after destination preflight. The bounded probe window still finishes
about one second after it starts. SSH connection setup and payload processing
remain larger costs; a wider performance claim needs controlled latency and
more repetitions rather than extrapolating from the stage improvement.
