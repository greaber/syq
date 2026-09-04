# Security

Syq's security design has three parts, and this document is candid about the
state of each:

1. [Hardening against a hostile filesystem](#hardening-against-a-hostile-filesystem):
   what an attacker who can modify a tree while syq works in it can and cannot
   do, compared with rsync 3.5, which is the state of the art.
2. [Least privilege for remote transfers](#least-privilege-for-remote-transfers):
   how a remote-to-remote copy runs without giving the source host your ssh
   agent or a reusable credential, what each layer protects, and how the
   mechanism generalizes.
3. [Release and bootstrap integrity](#release-and-bootstrap-integrity): how
   the binary that runs on a remote host, or replaces your local one, is
   verified.

To report a vulnerability, follow [SECURITY.md](https://github.com/greaber/syq/blob/master/SECURITY.md).

## Hardening against a hostile filesystem

### The threat

A file tool usually runs with more authority than everything it touches. Root
copies a tree an unprivileged user can write to; a backup account mirrors
directories owned by other tenants; a service extracts an upload. In each case
the interesting attacker is not someone who has compromised the account syq
runs as (nothing in a file tool can help with that), but someone who can
change names and objects (an object is a file, directory, symlink, or special
file) *inside* a tree while syq reads or writes it: swap a directory for a
symlink between the check and the open, plant a file where the tool will create
its temporary, hand the destination side a file list containing `..`, or flip a
file into a directory just before a recursive delete reaches it.

Rsync's [security design](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md)
addresses these systematically: file lists from the other side are untrusted
and validated; transfer paths are resolved one component at a time from a
directory handle that rsync opens at the start and keeps open; work on the
named file or directory itself happens through `*at()` calls relative to an
open parent handle; temporary files are created exclusively with random names
and owner-only access; and the protocol is fuzzed. Syq's native copy and
removal commands, and the command-restricted receiver (a forced command on
hostB, the destination host of a remote-to-remote copy, that syq installs when
you enroll a destination) follow the same principle: they work relative to
open directory handles, not by pathname. The deliberate exceptions and
remaining differences are listed below.

### Where syq stands

Native `cp` and `rm` follow the same design as rsync 3.5, and in a few places
go further:

- Every path the other side of a remote copy sends is validated before it
  reaches the filesystem: absolute names, NUL, empty components, `.` and `..`
  are rejected.
- Syq opens each selected source once, before anything on the destination
  changes, and keeps that handle open for the whole run; every worker acquires
  those exact open handles when it starts. Directory walks, stats, content
  hashes, and reads use that handle plus strict relative names; they never
  reopen the path you typed and never follow a symlink found inside the tree.
  A selected file authorizes only the exact object syq opened, and a symlink's
  target is read through the opened link itself, not by name.
- The destination directory is resolved once (a symlink component in the path
  you typed is followed only when root or the user on the destination side owns
  it), opened, and handed to every worker as an open handle. Scanning, prune
  planning, creation, metadata, deletion, file preparation, writes, and
  publication (the final rename of a finished file into place) all happen
  relative to that handle and never follow a symlink below it. Conditional
  updates check the identity of the object syq saw, not a name.
- The control files you pass (`--ignore-from`, `--files-from`, a named
  `--mapping`) are opened by walking their path one component at a time and
  read through that open handle, so renaming them mid-run cannot redirect the
  read, and a named `--results` file is created fresh relative to the open
  handle of its parent directory; an existing entry is refused.
- Regular files are opened with `O_NOFOLLOW` and the opened type is checked;
  the partial file a copy writes into before renaming it into place must be a
  regular file with a single link; special files are refused without blocking.
- Planned deletion removes each named entry itself and never recurses: a file
  that becomes a directory is not descended into. Deletion runs only after an
  error-free scan of both sides.
- Native `rm` resolves every selected path and opens a handle on it before its
  first change, enumerates the opened directories, re-checks device, inode,
  and type, and removes with `unlinkat`. A name swapped to a different inode
  before that re-check is refused, not deleted. The re-check and `unlinkat`
  are separate system calls, and no POSIX call removes a name only if it still
  refers to a given inode, so an entry renamed over the name in that window is
  removed as a single entry:
  a swapped-in symlink is unlinked without being followed, a swapped-in
  directory is refused by the kernel where a file was expected, and a
  non-empty directory is never descended into. The selected object survives
  under its new name. On Linux, syq holds an open handle on every selected or
  walked directory and reports the removal as a failure when that directory is
  still linked once its name is gone, whether the name was swapped or renamed
  away. macOS does not update the link count of a removed directory, so there
  such a directory is reported as removed or already absent. A swapped file
  has no open handle to check and is reported as removed on every platform.
  Exploiting the window needs write permission on the parent directory syq
  holds open, which already permits removing the entry that gets swapped in.
- The restricted receiver used by remote-to-remote copies performs every
  operation relative to the open handle of the enrolled directory; a symlink
  below it is copied as data, never followed.
- Native `cp` defaults to `-rlt`: no owner, group, mode, or device is applied
  unless `--preserve` or the rsync-shaped flags ask for it, and ACLs and
  xattrs are not implemented at all. Several classes of rsync vulnerability
  are simply unreachable.
- `--files-from` is stricter than rsync: a listed path whose parent is a
  symlink on the source is refused before syq creates the implied destination
  directory, where rsync creates it first and fails the content open afterward.

What is different from rsync, or weaker:

- **Resume files.** Syq always keeps partial files, at predictable names
  (`.name.syq-part.<copy-id>`) so a rerun finds its state without a state file.
  Rsync's equivalent, `--partial-dir`, is opt-in and its manual warns that the
  directory must not be writable by other users. The same warning applies to
  syq's destination directories, and applies by default: a user who can write
  the destination directory can pre-create a partial-file name. Mode `0600`
  creation and the singly-linked-regular-file check limit what that buys, but
  they cannot prove who created a predictable pathname. Do not run a
  privileged copy into a directory writable by untrusted users.
- **The rsync-mode escape hatch.** `syq rsync --insecure-links` turns off the
  symlink ownership check for every path the operator supplies: the source
  and destination arguments and control files such as `--files-from` and
  `--syq-ignore-from`. A symlink in any of those paths is then followed
  whoever owns it, so the flag also drops the destination-side refusal of an
  attacker-owned link, not only the source-side one. It additionally switches
  source traversal back to walking by pathname, which can leave the source
  tree through a symlink, including through symlinked `--files-from` parents.
  It exists for compatibility and is never selected automatically; do not
  reach for it to satisfy a source-side need without accepting that
  destination and control paths lose the same check. Like rsync's flag, it is
  local only: it never reaches a remote endpoint, which keeps the default
  ownership check and keeps source traversal inside the source tree. Rsync lets
  the remote side opt out through `--rsync-path`; syq's `--rsync-path` names
  an executable only, so a remote endpoint cannot opt out. It does
  not enable rsync's separate descendant-link modes:
  `-L`/`--copy-links`, `--copy-unsafe-links`, `-k`/`--copy-dirlinks`, and
  `-K`/`--keep-dirlinks` remain unsupported and are rejected before either
  endpoint is contacted. `--safe-links` and `--munge-links` are likewise not
  implemented; selected symlink target bytes are preserved unchanged.
- **Older macOS.** Reading a selected symlink through its open handle, which
  syq relies on when it opens the sources, needs macOS 13 or newer; older
  releases fail at that point instead of falling back to a read by name.
- **Protocol robustness.** Frames are length-bounded and several requests have
  specific limits, but the protocol between the two sides has not been fuzzed
  the way rsync's has.

### How confinement is verified

Syq's tests for this behavior do not rely on scheduler timing. After syq has
selected or opened a path, the test pauses it at that point, renames the
selected directory or object, replaces its old pathname with a symlink or a
different inode, and then lets syq continue. The operation must then either
continue through the handle it holds open or fail without touching the
replacement.

The evidence is split along the boundaries where authority changes form:

| Boundary | What is exercised |
| --- | --- |
| The paths you select | Replacing the selected directory, substituting a symlink for an intermediate component, replacing the named file or directory itself, and placing something at a path that was missing |
| Handing the open source handle to workers | Local workers, remote workers on TCP data connections that duplicate the open handle, and fresh remote worker processes that acquire it from the process that hands open directory handles to workers |
| Handing the open destination handle to workers | Local destination-side workers, remote destination-side workers on TCP data connections, and fresh remote destination-side processes, for both replacement of the destination directory and substitution of a parent below it |
| The restricted receiver | A destination directory whose identity no longer matches the signed grant is refused, and parent directories below it are opened without following links |
| Operations relative to an open handle | Scanning, stat and hashing, content reads, partial-file preparation, writes, publication, metadata, and pruning are each tested against the shared code that performs them relative to an open handle |
| Native `rm` and `map` | Opening every selected path before the first change, replacement races, and traversal relative to open handles |

These race tests run on both Linux and macOS, including both kinds of remote
worker and the restricted receiver. The remote tests start real syq client and
server processes over a local loopback shell and exercise the wire protocol,
the handoff of open handles to workers, and TCP data connections; they do not
test sshd authentication and are not a network-filesystem stress test. After
handoff, every transport uses the same code to work relative to an open handle,
so each kind of operation is tested once against that shared code rather than
once per transport.

On Linux, syq normally resolves a multi-component parent path below an open
handle in one `openat2` call with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`,
relative to that handle. This is a performance optimization, not a different
rule: it allows nested mounts but neither escape through `..` nor any symlink
below the handle. If the syscall is unavailable, blocked, or rejects a request,
syq walks the path one component at a time relative to the open handle, which
works on every platform; it never falls back to opening the full pathname.
Tests check that the fast path selects the same inode as the component walk,
refuses an intermediate symlink, reports the same failure, and crosses a nested
mount. macOS always walks component by component.

### What to do

- Prefer native `cp` without `--preserve` when you do not need owner, mode,
  or device preservation; it cannot be asked to create a setuid file.
- Treat every destination directory as a trust boundary for resume state, as
  you would rsync's `--partial-dir`. This matters most when syq runs as root.
- In rsync mode, leave `--insecure-links` off unless a symlinked parent in a
  file list is exactly what you mean.
- For an untrusted or semi-trusted source host in a remote-to-remote copy, use
  the restricted path described below (the default for a remote-to-remote
  copy: a constrained agent broker on your machine plus the restricted receiver
  on hostB); it protects the destination from a compromised source, and the
  receipt tells you what actually landed.
- When another process may modify a destination file in place during a
  transfer, no file tool can promise a consistent result; use a snapshot.

## Least privilege for remote transfers

### The problem

A remote-to-remote copy such as
`syq cp --from hostA --srcs-in src --to hostB --into dst` runs the transfer on
hostA (the coordinator: the host that runs the copy), which must authenticate
to hostB (the peer: the other remote host). The traditional way to give hostA
that ability is ssh
agent forwarding (`ssh -A`): hostA gets a socket through which it can ask your
agent to sign anything. Anyone with root on hostA, or merely access to that
socket, can then log into every host your keys open and do anything you can
do there, for as long as the forwarded session lasts. OpenSSH added
destination-constrained keys (`ssh-add -h`) to narrow this, but they require
loading the private key into the agent with constraints, which hardware tokens
and desktop agents cannot do, and they constrain only *where* a key may be
used, not *what* the session may do once there.

Syq's default gives hostA neither the agent nor a credential. It is built from
layers that are independently useful, each with a clear statement of what it
protects.

### Layer 1: the constrained agent broker

For the duration of a transfer, syq starts a temporary agent-protocol socket
locally (the constrained agent broker, or the broker for short) and forwards
*that* to hostA instead of your real agent. The broker holds no private keys;
it forwards signing requests to your real agent (or to the enrollment key
below) only after validating the exact path the request is
for:

```text
trusted hostA session -> configured-user@trusted-hostB session
```

It does this with OpenSSH's session-bind extension and host-bound public-key
authentication (OpenSSH 8.9 and later): the ssh client on hostA must present
signatures proving which server it is talking to, and the broker checks the
destination host key against your local `known_hosts`, the destination login
user against the one you configured, the session ID, the selected credential,
and the signature algorithm. Key addition and removal, raw or non-host-bound signing,
unknown extensions, and extra forwarding hops are refused. When the transfer
ends, the socket is closed and removed.

What it protects: hostA cannot use your agent against any other host, as any
other user, or through a further hop, and it cannot enumerate more than the
public halves of the identities offered. Hardware tokens and desktop agents
keep their own touch, PIN, and approval behavior because the private keys
never move.

What it does not protect, on its own: stock OpenSSH does not bind the
*command*. If the broker is used with one of your own existing keys for hostB
(`--peer-auth broker`), hostA holds the full authority of that destination
account for the lifetime of the session. That mode restricts where and as
whom hostA may authenticate; the next layers restrict what it may do.

### Layer 2: enrollment

The first transfer to a destination parent on hostB (or an explicit
`syq receiver enroll hostB:/path`) generates a new Ed25519 key locally (the
enrollment key), uploads the exact running syq to hostB as the restricted
receiver, and appends one managed `restrict,command=...` line to hostB's
`authorized_keys`. The private half of the enrollment key never leaves the
local machine. HostA never sees it; the broker signs with it only along the
verified path above. Before installing the enrollment key on hostB, syq creates
its private directories as mode 0700 and secret files as mode 0600. It does not
try to judge whether the receiver has been tampered with from ownership,
groups, ACLs, or a walk of the ancestor directories: hostB and the programs it
runs are the trusted side of this boundary. Instead, a transfer on the
restricted path is refused before copying when the destination paths it may
change overlap the receiver's SSH configuration, installed receiver directory,
enrollment state, or configured signature verifier. Thus a compromised hostA
cannot use otherwise valid copy operations to replace the receiver, keys, or
policy that a later connection relies on. This rule applies only to the
restricted path, not to local copies or to remote copies that do not use the
restricted receiver. Enrollment can also run through hostA as an ssh
`ProxyJump`, in which case hostA carries encrypted bytes and sees no agent,
key, or session.

That one setup session is the bootstrap trust boundary: during it your local
ssh client has ordinary command authority on hostB, exactly as it would to
install anything. Every later transfer uses only the enrollment key. The
`syq-enrollment:ID` marker makes the managed line recognizable to users,
administrators, and monitoring, and `syq receiver list` and
`syq receiver revoke` manage its lifecycle. HostB also generates a receipt
signing key at installation and returns its public half, which the local
machine records with the enrollment (see Layer 6).

### Layer 3: signed, single-use requests

For each transfer, the local machine signs a grant: a typed, single-use
authorization naming the exact destination, login, copy semantics, hash block
size, TCP port range, entry, byte, deletion, and connection limits, a start-by
time, a finish-by time, and a fresh nonce. HostA carries this grant but cannot
alter it. The restricted receiver on hostB verifies the signature (via
OpenSSH's SSHSIG verifier and a policy file hostB owns), records the nonce as
redeemed on disk before doing anything, enforces the deadlines, and then
accepts protocol requests only within the signed scope. A grant is redeemed at
most once; a replayed grant is rejected.

Ignore rules, `--inplace`, preservation, the policy for objects that already
exist at the destination, and placement preconditions are signed into the
grant and enforced by the receiver on its own. Deletion through the receiver
requires an explicit `--max-delete`, and the `--receiver-max-entries` and
`--receiver-max-bytes` options lower the signed ceilings for one transfer, so
what a redeemed grant is worth to hostA is always bounded on the command line.
Behavior the receiver cannot check independently of hostA is refused rather
than trusted: `--mapping`, `--min-size`, sending data unencrypted or through
ssh instead of over TCP data connections, and several others (the
[complete list](remote-to-remote.md#signed-policies-and-options-that-fail-closed)
is in the remote-to-remote guide). `--dry-run` is marked read-only in the
grant, and the receiver rejects every mutation under it even if hostA sends
one.

### Layer 4: the rooted receiver

Every destination scan, stat, hash, partial-file operation, metadata change,
write, and deletion the receiver performs happens relative to the open handle
of the enrolled directory: intermediate directories are opened with
`O_DIRECTORY | O_NOFOLLOW`, and the named file or directory itself is handled
relative to its open parent. A symlink below the enrolled directory is copied
as data, never followed. There is no fallback to a pathname for an operation
the handle-based code does not support. Preserved modes are bound to the inode
the receiver observed; a mode cannot be carried onto a replacement object.
Without `--preserve=permissions`, hostA cannot supply special bits or gain
chmod authority over existing objects.

### Layer 5: data connections that inherit the grant

After the control session is authenticated, file data flows over TCP data
connections, each encrypted and authenticated by a token. The receiver
permits one listener in the signed port range and closes it when the control
session ends or the grant
expires. There is no second ssh authentication and no silent fallback to an ssh
data path that would need one.

### Layer 6: signed, encrypted receipts

HostA carries the transfer, so on its own it could report success while having
written nothing. Every transfer on the restricted path that stays attached
(not `--detach`) therefore ends with hostB issuing a receipt: a stream with
one outcome for every pathname mutation the receiver saw (each file's
lifecycle, each directory, symlink, or
metadata operation, each individual prune deletion, and every failed,
abandoned, or refused request), followed by the final type, size, and, with
`--receiver-receipt digests`, BLAKE3 digest of every path an admitted mutation could have
changed. A small signed terminal record (the record that closes the receipt)
binds the stream to the complete signed grant, the enrollment ID, the grant's
single-use ID, and a clean or non-clean status. HostB encrypts the stream and
terminal to a fresh per-transfer key; hostA relays opaque frames; your machine
decrypts them and
checks the encryption's authentication, the enrolled Ed25519 signature, the
grant binding, the sequence, and the digest that commits to the whole stream
before printing trusted results. Missing, altered, reordered, replayed, or
suppressed frames cannot become a valid clean receipt, though suppression
remains a denial of service.

The receipt is hostB's account of its own state when the transfer closed: it
says what landed, not what hostA omitted or invented, and it is neither a
transaction nor a rollback. `--detach` is not available with the restricted
receiver because the broker exists only while syq remains attached. A detached
launch instead requires hostA to hold its own credentials for hostB
(`--peer-auth own-credentials`), or an explicit `--rsh` policy. Neither path
prepares a restricted grant or signed receipt.

### Putting the layers together

| Mode | HostA receives | Protects hostB against a compromised hostA? | Data path |
|---|---|---|---|
| `--peer-auth restricted` (the default: enrolled receiver + broker + receipt) | A signed single-use grant; the broker signs with the enrollment key for this path only | Yes: cannot escape the destination, widen semantics, exceed limits, replay, or misreport what landed | A → B directly |
| `--peer-auth broker` | Broker access to your own agent, valid only for hostA→user@hostB | Partially: cannot reach other hosts or users, but has that account's full authority during the session | A → B directly |
| `--coordinate-at local` | Nothing | Yes, by never involving hostA in authentication | A → you → B, at your bandwidth |
| `--peer-auth own-credentials` | Nothing; hostA must already hold its own hostB credential | Out of syq's hands | A → B directly |
| `--peer-auth full-agent` | Your whole agent, as `ssh -A` would | No; compatibility escape hatch with a warning `-q` cannot silence | A → B directly |
| `--rsh CMD` | Whatever the command does | Whatever the command does | A → B directly |

In every mode, a compromised hostA remains an untrusted *source*: it can omit
files, alter contents, lie about metadata, or stop. The design protects the
destination and your other credentials, not the fidelity of what a hostile
source chooses to send. Session binding identifies hostB by host key, not name;
two hosts sharing a private host key are the same host to the broker.

### Beyond copying

The broker is not specific to file transfer: "forward my agent to this host,
usable only to log into that user on that other host" is what most people
actually want from `ssh -A`. It runs today as part of syq's remote-to-remote
transfers, on the restricted path and with `--peer-auth broker`; it is not
available as a standalone command.

The enrollment and grant layers likewise turn a Unix account into narrow,
revocable transfer permissions. The receiver accepts a small typed protocol
rather than shell commands, which is what makes it auditable, and a grant names
an operation, a destination directory, and limits. The policies it enforces
are the copy, verify, and delete semantics of syq's own transfers.

## Persistent connections

`syq persist on` trades a little exposure for speed, and the trade should be
understood before it is made. While it is on, an OpenSSH control connection
to each endpoint you use stays authenticated for five minutes after the last
command, and a small per-endpoint background process keeps one helper
session opened on that connection ready for the next command. During that
window, anything that can act as the same local user can run commands on
those endpoints without touching your key or agent: through the control
socket, or by taking the ready session. This is the same boundary as sudo's
credential cache. The sockets live in a private runtime directory that only
your user can open, the pool checks the caller's user id as well, and the
window ends with `syq persist off`.

The pool cannot widen that boundary. It never authenticates: a session is
opened only after the master answers a liveness check, with every
authentication method turned off, so a dead connection leaves the pool empty
rather than logging in on its own, and a changed host key or a required
prompt reaches you through the next command you run yourself. It never reads
from the session it holds, so the command that takes it sees exactly what a
fresh session would show. It matches the exact remote command and syq build
of the command asking, and exits when a different build appears, when its
scope is removed, or after five minutes idle. Restricted receivers, explicit
remote shells, and remote coordinators do not use it.

## Release and bootstrap integrity

Using a file tool over ssh means running its code on the other machine. With
rsync you run whatever version is installed there. Syq installs a helper of its
own exact version, and everything about how that binary gets there is
verified:

- **Releases are built by a protected workflow** from a signed, annotated tag
  that must point at a commit reachable from protected `master` with green
  checks. The workflow embeds an Ed25519 signature over the release manifest's
  RFC 8785 canonical JSON, publishes provenance attestations, checks every
  uploaded byte, and publishes once. The signing key lives in an encrypted
  inventory on maintainer machines; CI receives only the two individual
  secrets it needs. [RELEASING.md](https://github.com/greaber/syq/blob/master/RELEASING.md) has the procedure.
- **The public key is compiled into every official syq.** A remote helper is
  installed only after the *local* client has verified the manifest signature
  and compared the binary's digest, whether the remote downloaded the release
  itself or the local client uploaded it. The managed helper cache executes
  only verified release binaries; versions coexist, so the client always
  controls exactly which code runs remotely.
- **Self-update is explicit.** Standalone installs check for a newer signed
  manifest at most once a day and print a reminder; nothing is installed as a
  side effect of a copy. `syq --self-update` installs after the same
  verification, and only for installs it owns (never over Homebrew or Cargo).
- **Source builds are honest about identity.** A checkout build carries its Git
  revision, is not an immutable release, and cannot populate the managed
  helper cache; both ends of a connection must present matching build
  identities to connect.
- **Both ends of a connection must have matching build identities.** Every
  connection starts by exchanging build identities in plain bytes, and any
  mismatch is refused before either side decodes a protocol message. The
  identity is the release version for an official binary and the Git revision
  (plus a hash of any
  uncommitted changes) for a source build, so it names the source the binary
  was built from, not the exact executable: release artifacts for different
  platforms share one identity, and so do clean builds of the same commit.
  There is no protocol version number and no negotiation between versions;
  the wire format is free to change between releases because two ends built
  from different source never talk to each other. The managed helper install
  is what makes this practical, and it separately guarantees that the remote
  side runs a verified release artifact rather than whatever is installed
  there.
