# Introduction

Syq is fast, safe, programmable *file motion*: copying and deleting files and
directory trees on one machine or across a network. It is built for the jobs
where `cp -r`, `rm -r`, and rsync are too slow or too trusting. Compared with
rsync, the headline differences for a casual user are:

- **Much faster in many common situations**: fast LANs and lossy WANs, many
  small files and a few giant ones. Syq parallelizes across files and inside
  large files, moves data over encrypted TCP connections instead of one ssh
  stream, lets the kernel copy on a single machine, and tunes its own
  connection count while a copy runs. See [Speed](speed.md).
- **Direct server-to-server transfers without dangerous ssh agent
  forwarding.** `syq cp --from hostA --srcs-in big --to hostB --into big`
  sends data straight from A to B. HostA never receives your agent or a
  reusable credential for hostB; it gets a signed, single-use grant for
  exactly this transfer, and hostB signs a receipt saying what it actually
  wrote. See [Remote-to-remote transfers](remote-to-remote.md).
- **Filters in gitignore syntax** (`--ignore node_modules`, `--ignore '*.o'`,
  `--ignore-from .gitignore`) instead of rsync's include, exclude, and filter
  rules.

Unsafe agent forwarding (`ssh -A`) lets anyone who compromises a server you
log into use all of your ssh keys, against every host they can name, for as
long as you stay logged in. It is one of the most common insecure habits among
otherwise careful people, because the alternatives were inconvenient. Syq's
answer is a constrained agent broker plus a command-restricted receiver;
[Security](security.md) explains how they work and what each protects.

## Why another file tool?

Some of the first commands anyone learns are `cp`, `rm`, and `mv`. They do
essential work and have barely changed in fifty years, and they have four
serious limitations.

1. **Connectivity.** They do not work between computers.
2. **Speed.** They are slow, mostly because nothing in them is parallel. This
   bites hardest on networked filesystems such as NFS and sshfs, which are
   otherwise the easy way around the connectivity problem.
3. **Composability.** They fuse planning with execution. `cp -r`, `rm -r`, and
   `mv` cannot tell you in advance how many files or bytes they will touch, so
   they cannot refuse before changing anything when you lack a permission or
   the disk is too small. More important, a command that cannot plan is hard to
   build on.
4. **Security.** They are hard to use safely if your threat model includes the
   possibility that an attacker can modify part of the filesystem while you
   work in it. Defense in depth says that it should.

Rsync helps considerably with connectivity and security, and to a limited
degree with speed and composability. It is mainly a replacement for `cp`, not
`rm` or `mv`, but `cp` is the command that most needed replacing, and rsync's
`--delete` adds a mirroring capability the classical commands never had.

Syq aims to do most of what rsync does while doing better on all four counts.
Today its biggest strengths are speed and secure remote-to-remote transfers.
Its composability story is still developing but is arguably already ahead of
rsync's. On filesystem hardening, rsync, and especially [its security
design](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md), has
been a great teacher; native `cp` and `rm` now follow the same design, and the
remaining differences are documented rather than hidden.

## Speed

Syq was born of frustration with how slow existing tools are, and speed is the
reason most people will use it. In rough order of importance, syq is faster
because it:

1. **Parallelizes everything.** It scans both sides in parallel, transfers
   many files at once, and splits large files into ranges that different
   workers move concurrently, so a tree of small files and a single giant file
   both benefit. An auto-tuner adjusts the connection count during the copy,
   settling on the smallest count that is within a few percent of the best
   measured rate, and remembers it per path.
2. **Moves data over TCP, not through ssh.** Ssh authenticates and controls the
   transfer; file data flows over separate AES-256-GCM encrypted TCP
   connections, escaping OpenSSH's per-channel window (about 2 MB per round
   trip) and per-process cipher throughput. Comparably fast NICs are used
   together. If the ports are firewalled, syq says so once and falls back to
   ssh.
3. **Lets the kernel copy.** On one machine, `copy_file_range` does a reflink
   or an in-kernel copy, and an NFS 4.2 server copies the file itself without
   moving the bytes through the client.
4. **Resumes at block granularity with no state file.** Interrupted or changed
   files are hashed in blocks on both sides, and only mismatching blocks move.
5. **Pipelines small files** in batches, overlaps connection setup with
   scanning, keeps one authenticated ssh connection per host alive between
   commands when you ask it to, and compresses each protocol frame with zstd
   only when that makes it smaller.

Measured numbers, the cases where parallelism does not help (one spinning
disk), and host tuning are in [Speed](speed.md) and [Server
tuning](server-tuning.md). You can benchmark syq against rsync and cp in your
own environment with [syq-bench](https://github.com/greaber/syq-bench).

There is one scenario in which rsync moves less data than syq. When an old
version of a file already exists on the receiver, rsync's rolling checksum
finds matching blocks at *any* byte offset, so one byte inserted near the start
of a 100 GB file costs rsync a few tens of megabytes of hashes. Syq compares
blocks at the same offsets: appends and in-place modifications (VM images,
databases, logs) are handled with the same economy, but an insertion shifts
everything after it and that tail is resent. Delta transfer has costs of its
own: the receiver must read its entire old copy, which on a network filesystem
can be slower than the transfer it saves, and it must hold that copy still
while waiting for the sender. Most large files are never modified in place, so
for most workloads this does not matter. Rolling-checksum delta transfer is not
implemented; if your workload needs it, measure with syq-bench and tell us.

## Connectivity

Like rsync, syq uses ssh to reach other machines, so it cannot reach a host
that rsync could not. In practice it has two connectivity advantages.

**Self-installation.** Rsync must already be installed on the remote host, and
you trust whatever version is there, however old. Syq installs a helper of its
own exact version on first use, one per version, so both ends always run
matching code. The remote downloads the release directly when it has the tools,
or the local machine uploads it. Either way the binary is checked against a
signed release manifest, verified with a public key compiled into your local
syq, before it runs.

**Direct remote-to-remote transfers.** Rsync cannot copy between two remote
hosts from your laptop. You download and re-upload, at your laptop's bandwidth,
or you ssh to one server with agent forwarding and run rsync there. Syq starts
the transfer on hostA and streams data to hostB while progress comes back to
you, and hostA never holds your credentials. When hostA cannot reach hostB,
`--coordinate-at local` routes the bytes through your machine instead. See
[Remote-to-remote transfers](remote-to-remote.md).

## Composability

The classical commands fuse planning and execution. Syq separates them as far
as the filesystem allows.

- **Plan before touching anything.** `--dry-run` scans both sides and reports
  the mapping, how many files it would create, update, and delete, how much
  data would move, and the network route it would take. Conflicts such as two
  sources writing one destination path are refused before the destination is
  touched. Pruning runs only after a complete, error-free scan, and
  `--max-delete` is all-or-nothing.
- **Selection and placement as data.** `--files-from` and `--ignore-from` read
  lists. Native placement (`--into`, `--as`, `--into-new`, ...) is explicit
  rather than inferred from trailing slashes and whether the destination
  exists. A *mapping* is a JSON-lines manifest of source→destination claims
  that `syq map` emits and `syq cp --mapping` executes, with conflict checking
  across the whole manifest, so any tool that edits JSON can reshape a
  transfer.
- **Results as data.** Exit codes distinguish partial failure, `--progress-json`
  streams progress, and `--results` writes a machine-readable outcome per
  operation, so "retry what failed" is one `jq` filter away.

Filesystems are not transactional, so plans do not make a copy reversible.
Permissions can change or a disk can fill between the plan and the write, and
a partially executed plan cannot always be rolled back. Separating planning
from execution is still worth a great deal. See
[Composability](composability.md) and [Mappings](mappings.md).

## Security

Syq's security story has two parts, and this documentation is candid about the
state of each.

**Hardening against a hostile filesystem.** If attackers might modify a tree
while you copy it (when you run as root, or over shared storage, they might),
a file tool must not be redirected by a swapped symlink, a crafted file list,
or a pre-planted temporary file. Rsync 3.5 is the state of the art here. Syq
already validates every peer-supplied path, follows an operator-named
destination symlink only when root or the receiving user owns it, opens leaves
without following links, never recursively deletes an object that changed
type, and pins every selected source and destination as an open descriptor
before anything changes, so every worker reads and writes relative to those
descriptors and a directory swapped for a symlink mid-transfer cannot redirect
it. Two things remain weaker than rsync: syq's always-on resume files assume
their directory is not writable by untrusted users, and the peer protocol has
not been fuzzed the way rsync's has.

**Least privilege for remote transfers.** For a remote-to-remote copy, the
default gives hostA neither your agent nor a credential. A temporary local
broker signs only for the exact hostA→user@hostB path, checked through
OpenSSH's session binding; a dedicated key on hostB is bound to a forced `syq`
receiver; each transfer carries a signed, single-use request naming the
destination, the semantics, and the limits, which the receiver enforces on its
own with descriptor-rooted operations; and hostB ends the transfer with a
signed receipt of what it published, verified on your machine. A compromised
hostA can lie about the source. It cannot escape the destination, widen the
grant, replay it, reach anything else, or misreport what landed.

**Release integrity.** Releases are built by a protected workflow from signed
tags and published with attestations and an Ed25519-signed manifest. Every
remote helper and self-update is verified against that manifest before it
runs.

[Security](security.md) explains all three, what each protects, and what it
does not. Report vulnerabilities as described in
[SECURITY.md](https://github.com/greaber/syq/blob/master/SECURITY.md).

## Interfaces

1. **Rsync compatibility mode.** `syq rsync` accepts rsync's argument shape
   and most of its common options for local, push, and pull copies. **This is
   the easiest way to start today.** Syq-specific options carry a `--syq-`
   prefix there (`--syq-ignore`, `--syq-connections`, `--syq-verify-only`), so
   a command that works with rsync keeps working and the extensions are
   unmistakable. Rsync's filter rules are the biggest missing piece;
   `--syq-ignore` takes gitignore syntax instead. Two remote operands are
   refused, as rsync refuses them. The [compatibility record](rsync-compat.md)
   lists what matches, what differs on purpose, and what is missing.
2. **Native mode.** `syq cp`, `syq rm`, and `syq map` put the verb first, make
   endpoints, selection, and placement explicit, and add what rsync lacks:
   remote-to-remote copies, a parallel `rm`, exact placement, filters and
   preservation as ordinary options, mappings. Native mode is experimental,
   and its grammar may change between releases.
3. **Programmatic.** `--progress-json` streams progress, native `cp` and `rm`
   accept `--results` for a machine-readable NDJSON outcome stream with a versioned contract
   ([Automation results](automation-v1.md)), and mappings let a program
   supply selection and placement as data. See
   [Composability](composability.md).

## Status and limitations

Syq is 0.1.x software with release binaries for Linux (x86-64, ARM64) and
macOS (Apple Silicon, Intel). `syq rsync` is the most stable surface; native
commands are experimental. Not implemented: rsync
filter rules, `--link-dest`, hard links (`-H`), ACLs and xattrs, sparse files,
rolling-checksum delta transfer, and rsync daemon mode. The
[compatibility record](rsync-compat.md) has the complete list with reasons.
Syq is MIT licensed; the source is at
[github.com/greaber/syq](https://github.com/greaber/syq).
