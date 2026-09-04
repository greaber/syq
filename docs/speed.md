# Speed

Syq was born of frustration with how slow existing tools are on modern
hardware and networks. This document lists what makes syq fast in rough order
of importance, collects the measurements recorded so far, says when
parallelism does not help, and explains the controls you can adjust. The
[How it works](reference.md#how-it-works) section of the reference explains
the partial file, the queue, and the final rename into place that these
mechanisms sit on; [Server setup](server-tuning.md) covers optional changes to
the host itself. Measure before changing anything: `--stats` reports the
connection count the auto-tuner (syq's automatic connection-count tuning)
finished on and the kernel's TCP counters, `-vv` reports the planned route,
and `SYQ_DEBUG=1` reports where every worker spent its time. Option names in
this document are the native spellings (the ones `syq cp`, `rm`, and `map`
use); under
`syq rsync`, syq-specific options carry a `--syq-` prefix (`--syq-connections`,
`--syq-no-tcp`, `--syq-tcp-plain`, and so on; see the [compatibility options
table](reference.md#compatibility-options)).

## What makes syq fast

1. **Parallelism at every stage.** The scan is a parallel walk on each side,
   streamed in batches. Files go onto a largest-first queue, and a worker that
   runs dry steals the back half of the biggest remaining range, so a single
   huge file stays parallel to its last byte. Deletion and native `rm` run in
   parallel too. Without `-j`, the auto-tuner adjusts the connection count
   while the copy runs and ends on the smallest count within 5 % of the best
   measured rate (one worker is a valid answer for a spinning disk). Copies
   with a remote endpoint remember that count per path and transport for the
   next run; local copies, including mounted NFS paths, do not. See
   [How many connections](#how-many-connections).
2. **A TCP data path beside ssh.** OpenSSH caps each channel at a 2 MB window,
   which is roughly 2 MB per round trip (about 7 MB/s at 265 ms), and caps each
   process at a few hundred MB/s of cipher work. Syq keeps ssh for
   authentication and control and moves data over separate TCP connections
   carrying AES-256-GCM records keyed through the ssh session. It advertises
   every IPv4 and IPv6 address the remote has, prefers the fastest that
   answers, and spreads connections across NICs of comparable speed. If no port is reachable it says
   so once and falls back to ssh data connections. The restricted receiver
   requires encrypted TCP and fails instead of falling back. See [TCP data
   connections](#tcp-data-connections).
3. **Kernel and server-side copies on one machine.** On Linux, same-machine
   copies use `copy_file_range`, which becomes a reflink where the filesystem
   supports it or an in-kernel copy otherwise, and on NFS 4.2 makes the server copy the
   file without moving bytes through the client. See [Same-machine
   copies](#same-machine-copies-copy_file_range-and-nfs).
4. **Block-level resume with no state file.** The partial file *is* the state.
   On a rerun, both sides hash the partial or the differing destination file in
   blocks and only mismatching blocks move, so appends and in-place changes are
   cheap and an interrupted copy resumes where it stopped. Files whose size and
   mtime match are skipped outright. See [Resume](reference.md#resume).
5. **Small-file pipelining and setup overlap.** Small files travel as
   pipelined whole-file requests in batches instead of one round trip per
   file. Workers connect while the source is still being scanned, address
   probes run while the control connection prepares the destination, and a
   transfer of only new small files over default ssh, with no bandwidth limit,
   reuses the authenticated control connection instead of paying a handshake
   per worker.
6. **Compression without expanding data.** Remote transfers
   try zstd level 1 on each piece of data they send, sending the compressed
   form only when it is smaller, so archives, media, and encrypted data are not expanded on the
   wire. `--no-compress` skips the attempt when CPU is scarcer than bandwidth.
7. **ssh used well when ssh must carry data.** Syq asks for `aes128-gcm` first,
   which on AES-NI hardware is faster per stream than OpenSSH's default
   ChaCha20; it gives large-file data workers independent connections so they
   can use separate cipher processes; it brings up control connections first
   and up to 32 handshakes at a time; and it halves its concurrency when sshd's
   `MaxStartups` sheds a connection. `syq persist on` keeps one authenticated
   control connection per host alive for five minutes between commands, so a
   series of small copies pays for authentication (and a hardware-token touch)
   once.
8. **Metadata round trips avoided or amortized.** Parallel stat and I/O hide the
   per-operation latency of NFS, FUSE, and object-backed filesystems. Syq also
   reuses syscall results instead of repeating type and identity checks, caches
   filesystem traits and component limits, skips metadata updates whose values
   already match, and lets partial files on NFS grow as data is written rather
   than preallocating them. Writing each file to a partial file and renaming it
   into place still costs a rename per file, and syq deliberately does not
   `fsync` transfer data.
9. **One authentication for direct remote-to-remote transfers.** A direct
   copy is one between two remote hosts that does not relay through your
   machine. The default restricted path (hostA talks to the command-restricted
   receiver, a forced command on hostB that syq installs when you enroll a
   destination) authenticates hostB once with the enrollment key and then runs
   token-authenticated TCP workers; `--peer-auth broker`, which instead
   forwards the constrained agent broker (a temporary stand-in for your ssh
   agent that holds no keys and passes on only signing requests for this copy)
   to hostA, pays an agent round trip per ssh connection.

Two things are *not* on this list. Congestion control is not selected
automatically: `--tcp-congestion ALGO` is an explicit per-socket experiment
for both ends of syq's TCP data sockets, and otherwise every socket inherits
its host's default (see [Server setup](server-tuning.md)). And rsync's
rolling-checksum delta transfer is not implemented; see [When rsync is
faster](#when-rsync-or-cp-is-faster).

## Measurements so far

These figures come from development machines rather than a controlled
benchmark suite, and most compare against `cp` rather than rsync. Use [syq-bench](https://github.com/greaber/syq-bench) to measure
your own workloads against rsync and cp.

| Workload | syq | Comparison |
|---|---|---|
| One 8 GB file, `/raid` → `/raid`, same machine | 24.8 GB/s | `cp` 2.5 GB/s |
| One 8 GB file, NFS → NFS, same machine (server-side copy) | 3.3 GB/s | `cp` 0.4 GB/s |
| Read one 4 GB file from a 20 Gbit NFSv4.2 mount, `-j8` | 858 MiB/s | `cp` ~400 MB/s |
| Write 20,000 small files to that NFS mount | 28 s | `cp -r` 72 s |
| One 4 GiB file, local disk → asynchronous NFS mount | 9.93 s median | `cp` 10.94 s median |
| One 4 GiB file, NFS → local disk | 1.13 GiB/s | |
| Remove 20,000 files on NFS, `-j32` | 2.5 s | `rm -rf` 9.7 s |
| 1 Gbit, Germany → Japan (265 ms), ssh data connections | ~110 MB/s auto-tuned | a fixed 8 connections: 44 MB/s |
| Same path, TCP data connections | line rate, ending at 8–13 connections | |
| 262 ms path, fresh 2,000-file / 8 MiB tree over `--no-tcp` | 11.29 s | 16.85 s with independent worker handshakes |
| 20 Gbit LAN, two 160-core hosts, `-j8` into tmpfs | 1.2–1.3 GiB/s | one ssh stream 450–550 MB/s |

### Cost of path safety

Syq keeps open directory handles so a renamed path cannot redirect a copy.
On a deliberately short, metadata-heavy local ext4 workload, this added about
1.1 seconds per 100,000 files: a 47–53% increase. A shallow tree increased by
12–18%. NFS measurements showed no large consistent penalty, but varied too
much to rule out a small one. These results depend on the filesystem, tree,
and cache state; the [measurement note](https://github.com/greaber/syq/blob/master/design/performance.md#path-safety-measurements-2026-09-04)
records the builds, method, and sample ranges.

## When rsync or cp is faster

- **A single spinning disk.** Parallel reads of one file there mean seeks. Use
  `--connections 1`; the auto-tuner can also end at one
  worker, but a short job may finish before it measures the slowdown.
- **Delta transfer against a shifted old copy.** When the destination holds an
  old version of a file, rsync's rolling checksum matches blocks at any byte
  offset, so an insertion near the start of a large file costs rsync only
  hashes. Syq compares blocks at the same offsets: appends and in-place
  modifications are handled with the same economy, but everything after an
  insertion is resent. Delta transfer also makes the destination side read its
  whole old copy, which on a network filesystem can cost more than it saves. Most
  large files are never modified in place; measure your own workload.
- **Short copies.** Connection setup and the auto-tuner's probes need a
  transfer long enough to pay for them. Each independent ssh connection costs
  a handshake, about 0.3 s on a LAN and seconds across continents. Small-file
  jobs that share the control connection avoid worker handshakes. Syq starts
  at a remembered or default count and opens more only when they help.
- **When the disk is the limit.** On a 20 Gbit LAN with `-j8`, syq reached
  1.2–1.3 GiB/s into tmpfs, while writes to the destination's ext4 NVMe capped
  everything, rsync included, at about 600 MB/s. Check the disk before blaming
  the network.

## Trading safety for speed

These options buy speed by giving something up; the default is the safe side.

- `--tcp-plain` skips encryption of the data connections (control stays in
  ssh). Only on a network whose trust boundary you understand.
- `--inplace` writes directly into destination files instead of writing a
  partial file and renaming it into place, saving the space and time of a
  second copy. Readers can see a partially updated file, and an interruption
  leaves the final file unfinished.
- `--no-compress` saves the compression attempt on a very fast LAN.
- `--connections N` fixes the connection count and disables the auto-tuner;
  `--bwlimit` caps throughput to be polite on a shared link.

The following sections explain the connection and filesystem controls.

## When parallelism helps

- **ssh CPU**: one ssh process tops out at a few hundred MB/s of cipher/MAC
  work. N processes scale roughly linearly. Multiplexed channels over one
  connection wouldn't help (same TCP stream, same single encrypting process),
  so large-file data workers get independent SSH connections. A job made
  only of new files no larger than one block, with no bandwidth limit, shares
  the control connection instead: its bottleneck is latency. An explicit
  `--rsh` owns the connection policy.
- **WAN**: several TCP flows beat one against per-flow window and loss limits.
- **High-latency filesystems** (NFS, FUSE, object-backed): many small files
  are latency-bound; parallel stat and I/O hide it. The scan is parallel too.
- **NVMe / RAID** on either side.
- **Not** a single spinning disk: parallel reads of one file there mean seeks.
  Fix the worker count at one (`syq cp --connections 1`, or
  `syq rsync --syq-connections 1`).

## How many connections

Without `--connections`, syq adjusts the worker count while a copy runs. For a
remote path it has measured, it starts with the count it last finished on.
Otherwise it starts with 16 over TCP, 8 over ssh, or, for local copies, 16 when
the process has at most two CPUs available and 32 otherwise. A job made only
of new small files, with no bandwidth limit, starts no more workers than it
has batches. A single local file starts with one worker when the kernel or
sequential destination writer can copy it directly; finding a partial file or
an unsupported shortcut restores the normal local starting count.

The auto-tuner looks for the smallest count from 1 through 64 whose measured
rate is within 5% of the best it has seen. It makes modest changes, waits for
the rate to stabilize, and keeps a change only when the measurement justifies
it. New connections open while existing workers keep copying; surplus
connections close after a decision. Short transfers may finish before a
comparison is possible. The progress line shows the current count (`16 conn`),
and `--stats` reports its path (`connections: auto: settled at 16 (path 16, peak 16)`).

Successful copies with a remote endpoint remember their count by directional
path and transport in `$XDG_CACHE_HOME/syq/tuning.json` (normally
`~/.cache/syq/tuning.json`). Set `SYQ_TUNING_CACHE` to another path, or to an
empty value to disable the cache. Local copies, including mounted NFS paths,
never use it. Dry runs, verification, fixed-count runs, short runs that compare
no counts, failed copies, and copies that fall back from TCP to ssh after
workers start do not update it. A stale entry costs the next run a probe or two.

On a 265 ms path from Germany to Japan, TCP data connections reached 1 Gbit
line rate at 8–13 connections. Over ssh, tuning reached about 110 MB/s around
30 seconds after connecting, compared with 44 MB/s for a fixed eight workers.
The [engineering note](https://github.com/greaber/syq/blob/master/design/performance.md)
has the detailed tuning rules and the small-file SSH comparison.

`-j N`/`--connections N` (`--syq-connections N` under `syq rsync`) fixes the
count and disables tuning. One worker can help on a spinning disk; use
`--bwlimit` when the goal is to cap throughput on a shared link.

## TCP data connections

SSH's per-channel window and cipher CPU can limit throughput on long or fast
links. By default, syq uses SSH for authentication and control and separate
TCP sockets for file data. The remote listens on one port from `--tcp-ports`
(default 47600–47699); AES-256-GCM encrypts the data with a secret exchanged
through SSH. `--tcp-plain` skips encryption on trusted networks; `--no-tcp`
sends the data through SSH. If no TCP route is reachable, syq reports that once
(silenced by `-q`) and falls back to SSH. A restricted remote-to-remote copy
requires encrypted TCP and fails instead of falling back.

The listener accepts IPv4 and IPv6. Syq considers the address your SSH session
arrived on, private-network addresses, public addresses, and overlay addresses
such as Tailscale, preferring faster interfaces within each group. It excludes
link-local IPv6 and virtual interfaces such as Docker bridges, and also tries
the SSH hostname for hosts behind NAT or port forwarding. It probes candidates
in parallel for one second each and uses the best that answers. When several
interfaces of comparable speed answer, it spreads connections across paths
within 2x of the fastest, so a slow path does not drag down the transfer.

On Linux, `--tcp-congestion ALGO` selects the algorithm for both ends of every
TCP data connection. It changes only those sockets, without modifying sysctls
or loading modules. The algorithm must be registered on both hosts and
allowed for the syq process. If either kernel rejects it, the copy fails with
the host and error. If the TCP route is unreachable, the usual SSH fallback
reports that the algorithm is no longer in use. The restricted receiver
refuses this option because its signed grant does not carry that setting.
See [Server setup](server-tuning.md) for prerequisites and firewall examples.

With `--stats`, syq reports the kernel's socket counters from both ends:
congestion-control algorithm, retransmissions, RTT, congestion window,
delivery rate, window-limited time, and ECN marks. Unsupported fields are
labeled unavailable; SSH data connections expose none of these counters to syq.

Use `-vv` to inspect the planned route: helper identity and platform,
candidate addresses and their reachability, the chosen TCP or SSH transport,
and the initial connection count. Under `--dry-run`, the same probes run but
no authenticated data connection opens. A remote-to-remote report is relative
to the coordinator, normally the source host; `--coordinate-at dst` reverses
the direction. If both endpoints name the same host, the report describes a
local filesystem route there.

## Defaults chosen for network filesystems

Small files are read and written in pipelined batches. Unless you choose
`--inplace`, each file is written to a partial file and renamed into place.
That costs a rename per file on NFS but avoids exposing an incomplete file
under its final name.
`--inplace` is the explicit space/safety tradeoff.

## Same-machine copies (copy_file_range and NFS)

On Linux, when source and destination are on the same machine, syq tries
`copy_file_range(2)` instead of streaming bytes through userspace: the kernel
does a reflink or a straight in-kernel copy, and on NFS 4.2 the *server* copies
the file internally (no client round trip). Measured: a single 8 GB file
/raid→/raid at 24.8 GB/s vs 2.5 GB/s for `cp`; NFS→NFS at 3.3 GB/s vs 0.4.
If the kernel cannot offload a cross-mount copy from a recognized local disk
filesystem into an asynchronous NFS mount (the default, without the `sync`
mount option), syq automatically uses one sequential reader/writer on the
destination side for that file. That avoids both per-inode NFS
write contention and needless transport framing and hashing. NFS-to-NFS copies,
other source filesystem types, synchronous NFS destinations, an explicit fixed
worker count above one, and unsupported non-NFS destinations keep the
parallel, hash-resumable streaming path.
`--hash`, any existing partial file, and a nonzero `--bwlimit` disable that
destination-side shortcut.
Small new bandwidth-limited files that fit in one paced transfer block still
use the pipelined whole-file request described in the
[How it works](reference.md#how-it-works) section.

## NFS

Local↔NFS copies are a local-to-local syq run
(`syq cp /raid/x --into /mnt/nfs`)
and benefit from parallelism across files and on reads: measured on a 20 Gbit
NFSv4.2 mount, reads of one 4 GB file reached 858 MiB/s with eight workers vs ~400 MB/s
for `cp`, and 20,000 small files were written in 28 s vs 72 s for `cp -r`.
Writes from a recognized local disk filesystem into one asynchronous NFS inode
are instead written one at a time on the destination side, automatically,
when the kernel cannot copy them itself.
On a fresh 4 GiB `/raid`→NFS copy, that writer reached a 9.93 s median,
versus 10.94 s for `cp` (two interleaved runs). Synchronous destinations and
NFS sources keep the adaptive parallel path; the reciprocal NFS→`/raid` copy
reached 1.13 GiB/s with parallel range reads.
Separate files still run concurrently and have reached ~650 MB/s in aggregate.
Mounting with `nconnect=8` (NFS 4.1+; needs an unmount/mount, not a remount) can
add headroom for those concurrent files and other NFS traffic.
