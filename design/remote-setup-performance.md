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
