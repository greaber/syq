# Performance measurements and tuning rationale

This note preserves measurement provenance and implementation detail that was
removed from the user-facing speed guide on 2026-09-05. The measurements are
historical observations, not new benchmark runs. The tuning description is a
snapshot of `master` at `87c63e7`; the code in `src/tune.rs` and
`src/transfer.rs` defines current behavior.

## Path-safety measurements, 2026-09-04

The descriptor-rooted implementation was measured separately on 2026-09-04,
comparing the pre-confinement revision `0382c06` with a build of the Linux
`openat2` implementation later committed as `e4de953` on top of master
`37ab73a` (benchmarked binary SHA-256 prefix `4e2687350003`). Each campaign
used 32 connections, checksum verification, a 100,000-file mixed-depth tree
holding 100 MiB, and both tool orderings. File pages were evicted where
possible, but dentry and inode caches remained warm.

On local ext4, the rooted build took 3.27–3.32 s median by ordering versus
2.17–2.22 s before confinement, a 47–53% increase on a deliberately short,
metadata-heavy workload. A shallow 100,000-file tree increased by 12–18%, and
the sub-second no-change case showed no stable difference. The absolute
mixed-tree cost was about 1.1 seconds per 100,000 files.

On a same-datacenter NFSv4 mount, five local-to-NFS fresh-copy samples had
combined medians of 46.45 s rooted and 44.05 s before confinement; the sample
ranges overlapped widely (41.19–50.96 s and 38.43–52.58 s). The NFS-to-local
campaign had the same 8.93 s combined median for both builds. A destination
no-change campaign did not expose a rooted penalty. NFS metadata probes varied
from 552 to 1,264 files/s during these runs, so the measurements rule out a
large consistent regression in this setup rather than a small one. They are
not a performance guarantee for other servers, mount options, cache states, or
tree shapes.

## Small-file SSH connection reuse

On a long path (262 ms), a fresh 2,000-file / 8 MiB tree over
`--syq-no-tcp` took 11.29 s in two verified runs after fresh-small-file workers
began reusing the authenticated control connection, versus 16.85 s with eight
independently authenticated worker connections. Larger and mixed workloads
still use independent SSH connections so they keep multi-flow throughput.

This measurement is preserved from the speed guide at `87c63e7`. Reuse applies
to new files no larger than one transfer block under the default SSH command,
with no nonzero bandwidth limit. The comparison above was recorded before
this documentation follow-up; it was not rerun for it.

## Sequential NFS writer comparison

The speed guide at `87c63e7` recorded a fresh 4 GiB `/raid` to asynchronous NFS
copy taking 21.44 seconds with 32 range writers. With one sequential writer
on the destination, the median was 9.93 seconds versus 10.94 seconds for `cp`
(two interleaved runs). The reverse NFS-to-local copy reached 1.13 GiB/s with
parallel range reads. These are historical measurements, not a promise for
other mounts; an explicit fixed worker count above one disables the sequential
fallback described by the comparison.

## Connection-tuning measurements and rationale

Useful progress (the high-water mark of logically completed bytes, plus a small
credit per completed file so small-file trees count) is sampled every 2.5 s.
Recovery can retract uncertain bytes, and retransmitting those same bytes does
not inflate the rate the auto-tuner measures. A count has been *measured*
only once two
consecutive samples agree within 10 %, so a burst that gets throttled or a link
still ramping up is waited out (up to 20 s) rather than credited to the last
change. The first probe is a 1.3× step up (8→10, not 8→16). A step up is kept
only when the smaller count is more than 5 % below the best recent measurement;
a step down is kept when it stays within 5 %. Thus acceptance directly follows
the objective: the smallest measured count within 5 % of the best observed
speed, from 1 through 64. A successful move keeps exploring in the same
direction. A failed move returns to the last good count and records a bound, so
later probes refine untested integers: if 10→13 helps and 13→17 is flat, syq
stays at 13 and can later try 11 rather than immediately falling back to 10.

In steady state, evidence in the upward and downward directions ages and backs
off independently. A direction is first eligible again after 6 stable
measurements (about 30 seconds at minimum); repeated failures double only that
direction's delay, up to 4 minutes at the minimum sampling rate. When both
directions are equally informative, syq deterministically probes up first:
most connection/throughput curves are concave or saturating, so an extra
connection usually loses less transfer speed than removing a useful one. This
is a starting assumption, not a rule: measured collapse aborts a probe early,
and independent backoff lets downward evidence win.

Upward candidates connect in the background while the current workers keep
copying; their stable rate refreshes the comparison baseline, while connection
setup time itself is not scored. A probe starts only when the activity remaining
at the observed rate is estimated to last through a complete measurement, so a
slow path is not rejected by a fixed byte threshold and a very fast tail is not
mistaken for evidence. After a decision, surplus connections and their reader
threads are closed instead of keeping the largest pool ever tried. At one
active connection syq keeps exactly one ready spare so the important 1→2 probe
remains cheap. A dropped data connection is reopened with bounded exponential
backoff; ranges whose acknowledgement or final rename into place is uncertain
are safely requeued. Transfers shorter than a measurement or two just run with the
starting count. The progress line shows the current count
(`16 conn`), and `--stats` reports the path it took
(`connections: auto: settled at 16 (path 16, peak 16)`).

Counts are persisted only for copies with a remote endpoint. Local filesystem
paths, including mounted NFS, do not produce a cache key. Failed, short,
fixed-count, and mixed-transport runs do not update the cache.
