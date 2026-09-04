# Speed

Syq was born of frustration with how slow existing tools are on modern
hardware and networks. This document lists what makes syq fast in rough order
of importance, collects the measurements recorded so far, says when
parallelism does not help, and then documents each mechanism in detail. The
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
   measured rate (one worker is a valid answer for a spinning disk), and
   remembers that count per path and transport as the next run's starting
   point. See [How many connections](#how-many-connections).
2. **A TCP data path beside ssh.** OpenSSH caps each channel at a 2 MB window,
   which is roughly 2 MB per round trip (about 7 MB/s at 265 ms), and caps each
   process at a few hundred MB/s of cipher work. Syq keeps ssh for
   authentication and control and moves data over separate TCP connections
   carrying AES-256-GCM records keyed through the ssh session. It advertises
   every IPv4 and IPv6 address the remote has, prefers the fastest that
   answers, and spreads connections across NICs of comparable speed. If no port is reachable it says
   so once and falls back to ssh data connections. See [TCP data
   connections](#tcp-data-connections).
3. **Kernel and server-side copies on one machine.** Same-machine copies use
   the kernel copy (`copy_file_range`), which becomes a reflink where the filesystem supports it
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
   transfer of nothing but fresh small files over ssh reuses the authenticated
   control connection instead of paying a handshake per worker. A native push
   of a few small local files into an existing remote directory goes further:
   the destination check, the placement, and the writes travel as one request
   on the control connection, so the copy costs one network round trip once
   the connection is up.
6. **Compression that costs nothing when it cannot help.** Remote transfers
   try zstd level 1 on each piece of data they send, sending the compressed
   form only when it is smaller, so archives, media, and encrypted data are not expanded on the
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
| Same path, TCP data connections | line rate, ending at 8–13 connections | |
| 262 ms path, fresh 2,000-file / 8 MiB tree over `--no-tcp` | 11.29 s | 16.85 s with independent worker handshakes |
| 20 Gbit LAN, two 160-core hosts, `-j8` into tmpfs | 1.2–1.3 GiB/s | one ssh stream 450–550 MB/s |

### Path-confinement cost

syq opens each selected directory once and keeps that handle open for the
whole run, so later work is relative to the handle and renaming the path
cannot redirect it. The cost of working this way was measured separately on
2026-09-04, comparing a build from before that change with the Linux
`openat2` implementation of it. Each campaign used 32 connections, checksum
verification, a 100,000-file mixed-depth tree holding 100 MiB, and both tool
orderings. File pages were evicted where possible, but dentry and inode
caches remained warm.

On local ext4, the open-handle build took 3.27–3.32 s median by ordering
versus 2.17–2.22 s before the change, a 47–53% increase on a deliberately short,
metadata-heavy workload. A shallow 100,000-file tree increased by 12–18%, and
the sub-second no-change case showed no stable difference. The absolute
mixed-tree cost was about 1.1 seconds per 100,000 files.

On a same-datacenter NFSv4 mount, five local-to-NFS fresh-copy samples had
combined medians of 46.45 s with open handles and 44.05 s before the change; the sample
ranges overlapped widely (41.19–50.96 s and 38.43–52.58 s). The NFS-to-local
campaign had the same 8.93 s combined median for both builds. A destination
no-change campaign did not show a penalty for the open-handle build. NFS
metadata probes varied
from 552 to 1,264 files/s during these runs, so the measurements rule out a
large consistent regression in this setup rather than a small one. They are
not a performance guarantee for other servers, mount options, cache states, or
tree shapes.

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
- **Short copies.** Connection setup (one ssh handshake per connection, about
  0.3 s on a LAN and seconds across continents) and the auto-tuner's probes
  need a transfer long enough to amortize them. Syq starts at a remembered or sensible count and
  only opens more once they have been shown to pay.
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

The rest of this document describes each mechanism in detail.

## When parallelism helps

- **ssh CPU**: one ssh process tops out at a few hundred MB/s of cipher/MAC
  work. N processes scale roughly linearly. Multiplexed channels over one
  connection wouldn't help (same TCP stream, same single encrypting process),
  so syq passes `-o ControlMaster=no -o ControlPath=none` for its connections
  on purpose.
- **WAN**: several TCP flows beat one against per-flow window and loss limits.
- **High-latency filesystems** (NFS, FUSE, object-backed): many small files
  are latency-bound; parallel stat and I/O hide it. The scan is parallel too.
- **NVMe / RAID** on either side.
- **Not** a single spinning disk: parallel reads of one file there mean seeks.
  Fix the worker count at one (`syq cp --connections 1`, or
  `syq rsync --syq-connections 1`).

## How many connections

Without an explicit connection count, the auto-tuner adjusts the number of
workers while a copy runs instead of guessing. On a data path it has measured
before, it starts at the count it last finished on for that path; otherwise it
starts with 16 when every remote endpoint has a reachable TCP data path, 8
over ssh, or, when both ends are local, 16 if the process has at most two CPUs
available and 32 otherwise. This uses the CPU
affinity or container limit reported by the OS; the lower count remains large
enough to overlap filesystem latency. A single same-machine file eligible for
the whole-file path or the kernel copy starts with one worker because extra
loopback connections cannot help; finding a partial file, or a kernel copy the
filesystem does not support, immediately restores the usual local starting
count of 16 or 32.
Remembered results are keyed only by the directional endpoint path and
transport (TCP and ssh learn separately), not by RTT, workload, filesystem or
other volatile telemetry. A stale hint only costs the auto-tuner a probe or two. The
cache is
`$XDG_CACHE_HOME/syq/tuning.json` (normally
`~/.cache/syq/tuning.json`; set `SYQ_TUNING_CACHE` to override it or to an
empty value to disable it). An explicit connection count, dry runs, verification, short runs
that compare no counts, failed/aborted copies, and runs whose TCP path falls
back to ssh after workers start do not update it; the last case may contain
mixed-transport measurements that are not representative of either pure path.

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

Measured from a 1 Gbit box in Germany to a host in Japan (265 ms): over TCP
data connections it ends up around 8–13 at line rate; over ssh data
connections (where each stream is capped by OpenSSH's 2 MB window) it
reaches line rate (~110 MB/s, where a fixed eight workers managed 44) about 30 s
after the connections are up.

On the same kind of long path (262 ms), a fresh 2,000-file / 8 MiB tree over
`--syq-no-tcp` took 11.29 s in two verified runs after fresh-small-file workers
began reusing the authenticated control connection, versus 16.85 s with eight
independently authenticated worker connections. Larger and mixed workloads
still use independent SSH connections so they keep multi-flow throughput.

Native `-j N`/`--connections N`, or compatibility
`--syq-connections N`, fixes the count and disables the auto-tuner. Use it
when you know better (for example, one worker for a spinning disk that must
not be read in parallel) or to be polite on a shared link.

## TCP data connections

ssh caps every stream at a few hundred MB/s of cipher CPU, and its 2 MB
per-channel flow-control window caps a stream at roughly `2 MB / RTT` on long
links (≈7 MB/s at 265 ms). So by default (unless `--syq-no-tcp`) syq keeps ssh for
authentication and control only and moves the data over separate TCP
connections: the remote opens a listener on a port from `--syq-tcp-ports` (default
47600-47699), and the data connections are plain TCP sockets carrying
AES-256-GCM records keyed by a secret exchanged over the ssh session
(`--syq-tcp-plain` skips the encryption on trusted networks; `--syq-no-tcp` sends data over the ssh connection instead). If the port can't be
reached (a firewall, typically), syq says so once and falls back to ssh data
connections, so the default is always safe.

The listener accepts IPv4 and IPv6 on the same port, and the remote advertises
its global addresses of both families: the address your ssh session arrived
on first, then private-network addresses, then public ones, then overlay
addresses such as Tailscale, with faster NICs first within each group.
Link-local IPv6 addresses (`fe80::`) and addresses on virtual interfaces such
as docker bridges are not advertised. syq also tries the name you gave ssh,
which is what works when the remote sits behind NAT or port forwarding. Every
distinct address is probed once, in parallel, for one second; on an IPv6-only
private network such as a cloud provider's internal mesh the IPv6 address is
the one that answers.

On Linux, `--syq-tcp-congestion ALGO` requests a congestion-control algorithm for
both ends of every TCP data connection. The connecting socket is
configured before `connect`, and the remote listener is configured before its
port is advertised, so accepted sockets inherit the same algorithm. This is a
per-socket override: syq does not change sysctls, load kernel modules, or alter
queueing disciplines. Without the option, every socket keeps its host's
default. An explicit override that either kernel rejects is a fatal error with
the affected host and kernel error; syq never silently substitutes another
algorithm. If the TCP route itself is unreachable, the normal warned SSH
fallback still applies and says that the requested algorithm is not used by
the SSH fallback.

The algorithm must be registered on both Linux hosts and available to the syq
process. Unprivileged processes may choose only entries in
`net.ipv4.tcp_allowed_congestion_control`; inspect host prerequisites and qdisc
state as described in [server-tuning.md](server-tuning.md). Congestion control
is sender-side, so setting it only on a download server does not also select it
for uploads from a client. syq can cover both directions because it owns the
data socket on each endpoint.

With `--stats`, copies over TCP data connections also report the kernel counters available on
both socket ends: the effective congestion-control algorithm, retransmitted
packets and bytes (a packet-loss signal), current/minimum RTT, congestion window
and delivery rate, receive-window and send-buffer limited time, and ECN CE
deliveries. These are for diagnosis only and do not affect which remembered
connection count syq starts from. Unsupported fields are labeled unavailable rather than displayed as
zero. SSH does not expose per-data-connection TCP counters to syq, so the
statistics say they are unavailable when the data transport is SSH.

The remote advertises every address it has (the one your ssh session arrived
on first, then private LAN, then public, then CGNAT/Tailscale); the client
adds the name it reached ssh through (the only address that works for a
host behind NAT or port forwarding) ahead of the overlay ones, tries them
all, and prefers the best that answers. If none answers it says so and uses
ssh (silenced by `-q`). When several NICs of
comparable speed are reachable (e.g. an 8-rail RoCE fabric), syq spreads its
data connections across all of them (multipath); it keeps only paths within
2x of the fastest, so it never drags a fast transfer down by mixing in a slow
link. Every candidate still gets its complete bounded probe window, but those
independent probes run while the control connection prepares the destination.
When the destination is not the command-restricted receiver, each destination
worker takes over the open handle for its destination directory as part of its
authenticated hello (this is the cost of handing open directory handles to
worker processes), and the destination side reports ready only after that
handoff succeeds. Single-homed hosts and laptops use the one best path,
unchanged. With ufw:

```sh
sudo ufw allow from 192.0.2.0/24  to any port 47600:47699 proto tcp   # example LAN
sudo ufw allow from 203.0.113.5   to any port 47600:47699 proto tcp   # a specific client
```

Use `-vv` to see the route planned for the real transfer. For each remote
endpoint seen by the active coordinator (the host that runs the copy) it
reports the identity and platform of the authenticated remote helper (a copy
of syq that syq installs on the remote host the first time it connects), every
TCP address syq considered, reachability and advertised link speed, why a
reachable address was or was not selected by the check that runs before
anything is written, the resulting planned TCP/ssh transport, and the initial
connection count. Workers authenticate their data connections after this report; if TCP
then fails, syq prints its normal data-over-ssh fallback notice. `-v` alone
keeps its existing file-listing behavior.

`-vv --dry-run` only observes: it reports the same control connection,
remote helper startup, TCP listener, address probes, and fallback decision that plain
`--dry-run` already performs. It does not open an authenticated data connection
or start transfer workers, and verbosity does not change dry-run's success or
failure. The reported route is therefore a plan for a real transfer, not a
claim that a worker data connection was completed.

Native remote-to-remote copies work the same way: the coordinator on hostA
connects to hostB's listener. Diagnostics are relative to that active
coordinator. If both endpoints name hostA, `-vv` reports a local filesystem
route there.

No special server setup is required. For a measurement-first checklist of
optional firewall, sshd, TCP, and host-network changes, including their
trade-offs and rollback considerations, see [Server
setup](server-tuning.md).

## Defaults chosen for network filesystems

Small files are read and written in pipelined batches, but every non-`--inplace`
write still finishes with an atomic rename. When both ends are local, the
auto-tuner starts with 16 workers on a process limited to one or two CPUs, and 32 otherwise;
an all-new small-file job starts no more workers than it has batches. This costs
one rename per file on NFS, but avoids exposing incomplete final-named files.
`--inplace` is the explicit space/safety tradeoff.

## Same-machine copies (copy_file_range and NFS)

When source and destination are on the same machine, syq copies each file with
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
`-c`, any existing partial file, and `--bwlimit` disable that destination-side
shortcut.
Small new bandwidth-limited files that fit in one paced transfer block still
use the pipelined whole-file request described in the
[How it works](reference.md#how-it-works) section.

## NFS

Local↔NFS copies are a local-to-local syq run
(`syq cp --connections 16 /raid/x --into /mnt/nfs`)
and benefit from parallelism across files and on reads: measured on a 20 Gbit
NFSv4.2 mount, reads of one 4 GB file reached 858 MiB/s with eight workers vs ~400 MB/s
for `cp`, and 20,000 small files were written in 28 s vs 72 s for `cp -r`.
Writes from a recognized local disk filesystem into one asynchronous NFS inode
are instead written one at a time on the destination side, automatically,
when the kernel cannot copy them itself.
On a fresh 4 GiB `/raid`→NFS copy, that changed syq from 21.44 s with 32 range
writers to a 9.93 s median with one sequential writer on the destination
side, versus a
10.94 s median for `cp` (two interleaved runs). Synchronous destinations and
NFS sources keep the adaptive parallel path; the reciprocal NFS→`/raid` copy
reached 1.13 GiB/s with parallel range reads.
Separate files still run concurrently and have reached ~650 MB/s in aggregate.
Mounting with `nconnect=8` (NFS 4.1+; needs an unmount/mount, not a remount) can
add headroom for those concurrent files and other NFS traffic.

## Performance notes

- syq asks ssh for `aes128-gcm@openssh.com` first (falling back to the usual
  ciphers). On x86 with AES-NI that is noticeably faster per stream than
  OpenSSH's default chacha20-poly1305.
- Each connection costs one ssh handshake (~0.3 s on a LAN, several seconds
  across continents). The control connections always come up first
  (everything waits on them; only then do data connections start), up to 32
  at a time, and if the
  server sheds one (sshd's `MaxStartups`, default 10, randomly rejects
  sessions beyond 10 being set up at once), syq halves that number for the
  rest of the run and retries. Raising `MaxStartups` can reduce setup time for
  independent ssh data connections; fresh-small-file workers using default ssh
  reuse the authenticated control connection instead. A higher limit increases
  the resources available to unauthenticated clients; see
  [Server setup](server-tuning.md).
  The auto-tuner starts at 16 for TCP data, or 8 for ssh data, and only opens more
  once they have been shown to pay.
- The default direct remote-to-remote path (the restricted path) uses one
  enrollment-key authentication for the hostB control connection, then
  encrypted token-authenticated TCP workers.
- Measured on two 160-core hosts on a 20 Gbit LAN: a single ssh stream tops out
  around 450–550 MB/s; `syq rsync --syq-connections 8` into tmpfs reached
  ~1.2–1.3 GiB/s (the raw
  multi-stream ssh ceiling), while writes to the destination's ext4 NVMe capped
  everything, rsync included, at ~600 MB/s. Check the disk before blaming the
  network.
- `SYQ_DEBUG=1` prints connect times and where each worker and each remote
  helper spent its time (blocked on reads, pipe writes, acks; waiting, handling).
