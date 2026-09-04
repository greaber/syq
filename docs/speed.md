# Speed

Syq was born of frustration with how slow existing tools are on modern
hardware and networks. This document lists what makes syq fast in rough order
of importance, collects the measurements recorded so far, says when
parallelism does not help, and then documents each mechanism in detail. The
[transfer engine](reference.md#how-it-works) section of the reference explains
the sidecar, queue, and publication model these mechanisms sit on; [Server
tuning](server-tuning.md) covers optional host changes. Measure before tuning:
`--stats` reports where the auto-tuner settled and the kernel's TCP counters,
`-vv` reports the planned route, and `SYQ_DEBUG=1` reports where every worker
spent its time. Option names in this document are the native spellings; under
`syq rsync`, syq-specific options carry a `--syq-` prefix (`--syq-connections`,
`--syq-no-tcp`, `--syq-tcp-plain`, and so on; see the [compatibility options
table](reference.md#compatibility-options)).

## What makes syq fast

1. **Parallelism at every stage.** The scan is a parallel walk on each side,
   streamed in batches. Files go onto a largest-first queue, and a worker that
   runs dry steals the back half of the biggest remaining range, so a single
   huge file stays parallel to its last byte. Deletion and native `rm` run in
   parallel too. Without `-j`, an auto-tuner adjusts the connection count while
   the copy runs, settling on the smallest count within 5 % of the best
   measured rate (one worker is a valid answer for a spinning disk), and, for
   copies with a remote endpoint, remembers that count per host path and
   transport as the next run's starting point. Same-machine copies, including
   copies into a mounted NFS path, are not remembered. See
   [How many connections](#how-many-connections).
2. **A TCP data path beside ssh.** OpenSSH caps each channel at a 2 MB window,
   which is roughly 2 MB per round trip (about 7 MB/s at 265 ms), and caps each
   process at a few hundred MB/s of cipher work. Syq keeps ssh for
   authentication and control and moves data over separate TCP connections
   carrying AES-256-GCM records keyed through the ssh session. It advertises
   every IPv4 and IPv6 address the remote has, prefers the fastest that
   answers, and spreads connections across NICs of comparable speed. If no port is reachable it says
   so once and falls back to ssh data connections, except on a
   command-restricted remote-to-remote transfer, whose receiver requires
   encrypted TCP and fails instead. See [TCP data
   connections](#tcp-data-connections).
3. **Kernel and server-side copies on one machine.** Same-machine copies use
   `copy_file_range`, which becomes a reflink where the filesystem supports it
   or an in-kernel copy otherwise, and on NFS 4.2 makes the server copy the
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
   transfer of nothing but fresh small files over ssh, without `--bwlimit`,
   reuses the authenticated control connection instead of paying a handshake
   per worker.
6. **Compression that costs nothing when it cannot help.** Remote transfers
   use zstd level 1 per protocol frame, sending the compressed form only when it
   is smaller, so archives, media, and encrypted data are not expanded on the
   wire. `--no-compress` skips the attempt when CPU is scarcer than bandwidth.
7. **ssh used well when ssh must carry data.** Syq asks for `aes128-gcm` first,
   which on AES-NI hardware is faster per stream than OpenSSH's default
   ChaCha20; it disables connection multiplexing on purpose, since multiplexed
   channels share one cipher process; it brings up control connections first
   and up to 32 handshakes at a time; and it halves its concurrency when sshd's
   `MaxStartups` sheds a connection. `syq persist on` keeps one authenticated
   control connection per host alive for five minutes between commands, so a
   series of small copies pays for authentication (and a hardware-token touch)
   once.
8. **Metadata round trips avoided or amortized.** Parallel stat and I/O hide the
   per-operation latency of NFS, FUSE, and object-backed filesystems. Syq also
   reuses syscall results instead of repeating type and identity checks, caches
   filesystem traits and component limits, skips metadata updates whose values
   already match, and lets NFS sidecars grow from data writes rather than
   preallocating them. Staged publication still costs a rename per file, and syq
   deliberately does not `fsync` transfer data.
9. **One authentication for direct remote-to-remote transfers.** The default
   restricted path authenticates hostB once with the enrollment key and then
   runs token-authenticated TCP workers; `--agent-broker-only` instead pays an
   agent round trip per ssh connection.

Two things are *not* on this list. Congestion control is not selected
automatically: `--tcp-congestion ALGO` is an explicit per-socket experiment
for both ends of syq's direct TCP sockets, and otherwise every socket inherits
its host's default (see [Server tuning](server-tuning.md)). And rsync's
rolling-checksum delta transfer is not implemented; see [When rsync is
faster](#when-rsync-or-cp-is-faster).

## Measurements so far

These figures come from the development machines named in the sections below,
not from a controlled benchmark suite, and most compare against `cp` rather
than rsync. Use [syq-bench](https://github.com/greaber/syq-bench) to measure
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
| Same path, TCP data connections | line rate, settling at 8–13 connections | |
| 20 Gbit LAN, two 160-core hosts, `-j8` into tmpfs | 1.2–1.3 GiB/s | one ssh stream 450–550 MB/s |

## When rsync or cp is faster

- **A single spinning disk.** Parallel reads of one file there mean seeks. Use
  `--connections 1`; the auto-tuner can also settle at one
  worker, but a short job may finish before it measures the slowdown.
- **Delta transfer against a shifted old copy.** When the receiver holds an
  old version of a file, rsync's rolling checksum matches blocks at any byte
  offset, so an insertion near the start of a large file costs rsync only
  hashes. Syq compares blocks at the same offsets: appends and in-place
  modifications are handled with the same economy, but everything after an
  insertion is resent. Delta transfer also makes the receiver read its whole
  old copy, which on a network filesystem can cost more than it saves. Most
  large files are never modified in place; measure your own workload.
- **Short copies.** Connection setup (one ssh handshake per connection, about
  0.3 s on a LAN and seconds across continents) and tuning need a transfer long
  enough to amortize them. Syq starts at a remembered or sensible count and
  only opens more once they have been shown to pay.
- **When the disk is the limit.** On a 20 Gbit LAN with `-j8`, syq reached
  1.2–1.3 GiB/s into tmpfs, while writes to the destination's ext4 NVMe capped
  everything, rsync included, at about 600 MB/s. Check the disk before blaming
  the network.

## Trading safety for speed

These options buy speed by giving something up; the default is the safe side.

- `--tcp-plain` skips encryption of the data connections (control stays in
  ssh). Only on a network whose trust boundary you understand.
- `--inplace` writes directly into destination files instead of staging and
  renaming, saving the space and time of a second copy, at the cost of atomic
  publication and safe interruption.
- `--no-compress` saves the compression attempt on a very fast LAN.
- `--connections N` fixes the connection count and disables tuning;
  `--bwlimit` caps throughput to be polite on a shared link.

The rest of this document describes each mechanism in detail.

## When parallelism helps

- **ssh CPU**: one ssh process tops out at a few hundred MB/s of cipher/MAC
  work. N processes scale roughly linearly. Multiplexed channels over one
  connection wouldn't help — same TCP stream, same single encrypting process —
  so syq gives its large-file data connections their own ssh process
  (`-o ControlMaster=no -o ControlPath=none`) on purpose. The one exception is
  a job made only of fresh files no larger than one block, without
  `--bwlimit`, where the workers share the already-authenticated control
  connection instead; those are
  latency-bound, not cipher-bound.
- **WAN**: several TCP flows beat one against per-flow window and loss limits.
- **High-latency filesystems** (NFS, FUSE, object-backed): many small files
  are latency-bound; parallel stat and I/O hide it. The scan is parallel too.
- **NVMe / RAID** on either side.
- **Not** a single spinning disk: parallel reads of one file there mean seeks.
  Fix the worker count at one (`syq cp --connections 1`, or
  `syq rsync --syq-connections 1`).

## How many connections

Without an explicit connection count, syq tunes the number of workers while a
copy runs instead of guessing. It starts at the count that settled last time on
the same data path and transport. On a path it has not measured, it starts with
16 over TCP data connections, 8 over ssh, or, when both ends are local, 16 on a
process limited to one or two CPUs and 32 otherwise. A job of nothing but new small
files, without `--bwlimit`, starts no more workers than it has batches, and a single file copied on
one machine starts with one worker when the kernel or the receiver can copy it
directly, since extra loopback connections cannot help.

The tuner looks for the smallest count, from 1 through 64, whose measured rate
is within 5 % of the best it has seen. It changes the count in modest steps,
waits for the rate to stabilize before crediting a change, keeps a step only
when the measurement justifies it, and probes upward first because an extra
connection usually costs less than removing a useful one. Candidate
connections open in the background while the settled workers keep copying,
and surplus connections are closed once a decision is made. Transfers shorter
than a measurement or two just run with the starting count. The progress line
shows the current count (`16 conn`), and `--stats` reports the path it took
(`connections: auto: settled at 16 (path 16, peak 16)`).

Settled counts are remembered per directional endpoint path and transport in
`$XDG_CACHE_HOME/syq/tuning-v1.json` (normally `~/.cache/syq/tuning-v1.json`;
set `SYQ_TUNING_CACHE` to override it, or to an empty value to disable it).
Only a copy that finished with tuning enabled, has a remote endpoint, ran long
enough to compare counts, and did not fall back from TCP to ssh midway updates
it; a stale entry costs the next run a probe or two.

Measured from a 1 Gbit box in Germany to a host in Japan (265 ms): over TCP
data connections it settles around 8–13 at line rate; over ssh data
connections (where each stream is capped by OpenSSH's 2 MB window) it
reaches line rate (~110 MB/s, where a fixed eight workers managed 44) about 30 s
after the connections are up.

Native `-j N`/`--connections N`, or compatibility
`--syq-connections N`, fixes the count and disables tuning. Use it when you
know better—for example, one worker for a spinning disk that must not be read
in parallel—or to be polite on a shared link.

## TCP data connections

ssh caps every stream at a few hundred MB/s of cipher CPU, and its 2 MB
per-channel flow-control window caps a stream at roughly `2 MB / RTT` on long
links (≈7 MB/s at 265 ms). So by default syq keeps ssh for authentication and
control only and moves the data over separate TCP connections: the remote
opens a listener on a port from `--tcp-ports` (default 47600-47699), and the
data connections are plain TCP sockets carrying AES-256-GCM records keyed by a
secret exchanged over the ssh session. `--tcp-plain` skips the encryption on
trusted networks; `--no-tcp` sends data over the ssh connection instead. If
the port can't be reached — a firewall, typically — syq says so once (silenced
by `-q`) and falls back to ssh data connections, so the default is always
safe. The one exception is a command-restricted remote-to-remote transfer,
whose signed receiver requires encrypted TCP: it fails rather than fall back.

The listener accepts IPv4 and IPv6 on the same port. The remote advertises its
addresses of both families in order of preference: the address your ssh
session arrived on, then private-network addresses, then public ones, then
overlay addresses such as Tailscale, with faster NICs first within each group;
link-local IPv6 addresses and virtual interfaces such as docker bridges are
left out. The client adds the name you gave ssh, which is what works for a
host behind NAT or port forwarding, probes every candidate once in parallel
for one second, and uses the best that answers. When several NICs of
comparable speed answer, such as a multi-rail RoCE fabric, syq spreads its
data connections across every path within 2x of the fastest, so a slow link
never drags a fast transfer down. With ufw:

```sh
sudo ufw allow from 192.0.2.0/24  to any port 47600:47699 proto tcp   # example LAN
sudo ufw allow from 203.0.113.5   to any port 47600:47699 proto tcp   # a specific client
```

On Linux, `--tcp-congestion ALGO` selects a congestion-control algorithm for
both ends of every direct TCP data connection. It is a per-socket override:
syq does not change sysctls, load modules, or alter queueing disciplines, and
without the option every socket keeps its host's default. The algorithm must
be registered on both hosts and, for an unprivileged syq, listed in
`net.ipv4.tcp_allowed_congestion_control`; if either kernel rejects it, the
copy fails naming the host and error rather than silently using another
algorithm, and if the TCP route is unreachable the usual ssh fallback applies
and notes that the algorithm is not in use. Congestion control is
sender-side, which is why syq sets it on both ends. See [Server
tuning](server-tuning.md) for host prerequisites.

With `--stats`, direct TCP copies also report the kernel's socket counters
from both ends: the effective congestion-control algorithm, retransmissions,
RTT, congestion window and delivery rate, window-limited time, and ECN marks.
Fields a kernel does not provide are labeled unavailable, and ssh data
connections expose none of them.

Use `-vv` to see the route planned for a transfer: for each remote endpoint
it reports the helper identity and platform, every address considered with
its reachability and link speed, why each was or was not selected, the
planned TCP or ssh transport, and the initial connection count. Under
`--dry-run` the same probes run and the same route is reported, but no data
connection is opened. For a native remote-to-remote copy the report is
relative to whichever endpoint runs the coordinator (the source unless
`--coordinate-at` says otherwise), which connects to the other endpoint's
listener.

No special server setup is required. For a measurement-first checklist of
optional firewall, sshd, TCP, and host-network changes, see [Server
tuning](server-tuning.md).

## Defaults chosen for network filesystems

Small files are read and written in pipelined batches, but every write that is
not `--inplace` still finishes with an atomic rename. That costs one rename per
file on NFS, but never exposes an incomplete file under its final name;
`--inplace` is the explicit space/safety tradeoff.

## Same-machine copies (copy_file_range and NFS)

When source and destination are on the same machine, syq copies each file with
`copy_file_range(2)` instead of streaming bytes through userspace: the kernel
does a reflink or a straight in-kernel copy, and on NFS 4.2 the *server* copies
the file internally (no client round trip). Measured: a single 8 GB file
/raid→/raid at 24.8 GB/s vs 2.5 GB/s for `cp`; NFS→NFS at 3.3 GB/s vs 0.4.
If the kernel cannot offload a cross-mount copy from a recognized local disk
filesystem into an ordinary asynchronous NFS mount, the receiver automatically
uses one sequential reader/writer for that file. That avoids both per-inode NFS
write contention and needless transport framing and hashing. NFS-to-NFS copies,
other source filesystem types, synchronous NFS destinations, an explicit fixed
worker count above one, and unsupported non-NFS destinations retain the
parallel, hash-resumable streaming fallback.
`--hash`, any existing partial, and `--bwlimit` disable the receiver-side
shortcut.
Small new bandwidth-limited files that fit in one paced transfer block still
use the pipelined whole-file request described in the
[transfer engine](reference.md#how-it-works) section.

## NFS

Local↔NFS copies are a local-to-local syq run
(`syq cp /raid/x --into /mnt/nfs`)
and benefit from parallelism across files and on reads: measured on a 20 Gbit
NFSv4.2 mount, reads of one 4 GB file reached 858 MiB/s with eight workers vs ~400 MB/s
for `cp`, and 20,000 small files were written in 28 s vs 72 s for `cp -r`.
Writes from a recognized local disk filesystem into one asynchronous NFS inode
are instead serialized automatically by the receiver when the kernel cannot
offload them.
On a fresh 4 GiB `/raid`→NFS copy, that sequential writer reached a 9.93 s
median versus 10.94 s for `cp` (two interleaved runs). Synchronous destinations and
NFS sources retain the adaptive parallel path; the reciprocal NFS→`/raid` copy
reached 1.13 GiB/s with parallel range reads.
Separate files still run concurrently and have reached ~650 MB/s in aggregate.
Mounting with `nconnect=8` (NFS 4.1+; needs an unmount/mount, not a remount) can
add headroom for those concurrent files and other NFS traffic.
