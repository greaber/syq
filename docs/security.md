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
change names and objects *inside* a tree while syq reads or writes it: swap a
directory for a symlink between the check and the open, plant a file where the
tool will create its temporary, hand a receiver a file list containing `..`,
or flip a file into a directory just before a recursive delete reaches it.

Rsync's [security design](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md)
addresses these systematically: peer file lists are untrusted and validated;
transfer paths are resolved component by component from a retained root
descriptor; leaf work happens through `*at()` calls relative to a held parent;
temporary files are created exclusively with random names and owner-only
access; and the protocol is fuzzed. Syq's native copy, removal, and restricted
receiver paths follow the same descriptor-rooted principles. The deliberate
exceptions and remaining differences are listed below.

### Where syq stands

Native `cp` and `rm` follow the same design as rsync 3.5, and in a few places
go further:

- Every path a remote peer sends is validated before it reaches the
  filesystem: absolute names, NUL, empty components, `.` and `..` are rejected.
- Every selected source is resolved and registered as an open descriptor
  before anything on the destination changes, and every worker claims those
  exact descriptors when it starts. Directory walks, stats, content hashes, and
  reads use that descriptor plus strict relative names; they never reopen the
  operator's spelling and never follow a symlink found inside the tree. A
  selected file authorizes only the exact object observed at registration, and
  a symlink's target is read through the opened link object, not by name.
- The destination directory is resolved once (a symlink component in the
  operator's own path is followed only when root or the receiving user owns it),
  registered, and handed to every worker as an open descriptor. Scanning, prune
  planning, creation, metadata, deletion, file preparation, writes, and
  publication all happen relative to it and never follow descendant symlinks.
  Conditional updates verify the observed identity rather than a name.
- The control files you pass (`--ignore-from`, `--files-from`, a named
  `--mapping`) are read from the identity selected by the component walk, so
  renaming them mid-run cannot redirect the read, and a named `--results` file
  is created fresh beneath its retained parent; an existing entry is refused.
- Regular files are opened with `O_NOFOLLOW` and the opened type is checked;
  sidecars must be singly linked regular files; special files are refused
  without blocking.
- Planned deletion is non-recursive per leaf: a file that becomes a directory
  is not descended into. Deletion runs only after an error-free scan of both
  sides.
- Native `rm` resolves and pins every selector before its first change and
  enumerates opened directories. Before deletion, it atomically moves the
  current entry into an owner-only quarantine directory in a trusted ancestor
  on the same filesystem, then re-checks device, inode, and type there. Under
  `--root`, it verifies that the selected entry's opened parent still has the
  opened root in its ancestor chain before it creates the quarantine; a parent
  moved outside the root is refused. A name swapped to a different inode is
  restored or preserved in the reported quarantine, not deleted, and a later
  entry at the selected name is left alone. If the
  filesystem has no atomic no-replace rename, or no writable trusted ancestor
  inside the allowed boundary can hold the quarantine, removal fails closed.
  On Linux, an open descriptor also lets syq report a selected directory
  renamed away before quarantine as a failure; macOS cannot expose that
  directory state and reports it as already absent.
- The restricted remote-to-remote receiver performs every operation relative
  to an opened root; descendant symlinks are payload, never traversal.
- Native `cp` defaults to `-rlt`: no owner, group, mode, or device is applied
  unless `--preserve` or the rsync-shaped flags ask for it, and ACLs and
  xattrs are not implemented at all. Several classes of rsync vulnerability
  are simply unreachable.
- `--files-from` is stricter than rsync: a listed path whose parent is a
  symlink on the source is refused before syq creates the implied destination
  directory, where rsync creates it first and fails the content open afterward.

What is different from rsync, or weaker:

- **Resume files.** Syq always keeps partials, at deterministic names
  (`.name.syq-part.<job-id>`) so a rerun finds its state without a state file.
  Rsync's equivalent, `--partial-dir`, is opt-in and its manual warns that the
  directory must not be writable by other users. The same warning applies to
  syq's destination directories, and applies by default: a user who can write
  the destination directory can pre-create a sidecar name. Mode `0600`
  creation and the singly-linked-regular-file check limit what that buys, but
  they cannot prove who created a predictable pathname. Do not run a
  privileged copy into a directory writable by untrusted users.
- **The rsync-mode escape hatch.** `syq rsync --insecure-links` turns off the
  symlink ownership check for every path the operator supplies: the source
  and destination arguments and control files such as `--files-from` and
  `--syq-ignore-from`. A symlink in any of those paths is then followed
  whoever owns it, so the flag also drops the destination-side refusal of an
  attacker-owned link, not only the source-side one. It additionally restores
  the unconfined, name-based source traversal, including through symlinked
  `--files-from` parents. It exists for compatibility and is never selected
  automatically; do not reach for it to satisfy a source-side need without
  accepting that destination and control paths lose the same check. It does
  not enable rsync's separate descendant-link modes:
  `-L`/`--copy-links`, `--copy-unsafe-links`, `-k`/`--copy-dirlinks`, and
  `-K`/`--keep-dirlinks` remain unsupported and are rejected before either
  endpoint is contacted. `--safe-links` and `--munge-links` are likewise not
  implemented; selected symlink target bytes are preserved unchanged.
- **Older macOS.** The descriptor-bound symlink read that source registration
  relies on needs macOS 13 or newer; older releases fail registration instead
  of falling back to a name-based read.
- **Protocol robustness.** Frames are length-bounded and several requests have
  specific limits, but the peer protocol has not been fuzzed the way rsync's
  has.

### How confinement is verified

The adversarial `confinement_matrix_` tests use bounded two-way barriers after
a path has been selected or registered. Syq acknowledges that it has reached
the barrier and does not continue until the test confirms that it has renamed
the selected directory or object and replaced its old pathname with a symlink
or a different inode. The operation must then either continue through the
retained descriptor or fail without touching the replacement. These matrix
cases exercise the race boundary directly instead of relying on scheduler
timing.

The evidence is split along the boundaries where authority changes form:

| Boundary | What is exercised |
| --- | --- |
| Operator selection | Root replacement, intermediate-link substitution, exact-leaf replacement, and missing-path placement |
| Source capability handoff | Local workers, remote TCP workers that clone the registered descriptor, and fresh remote worker processes that claim it from the descriptor broker |
| Destination capability handoff | Local receivers, remote TCP receivers, and fresh remote receiver processes, for both root replacement and descendant-parent substitution |
| Restricted receiver | A changed signed root identity is refused, and descendant parents are opened without following links |
| Descriptor-rooted operations | Scanning, stat and hashing, content reads, sidecar preparation, writes, publication, metadata, and pruning are tested separately against the shared rooted primitives |
| Native `rm` and `map` | Pre-mutation selector pinning, replacement races, and descriptor-rooted traversal |

Linux CI runs the complete suite. macOS CI also runs the tests whose names
begin with `confinement_matrix_`, including both remote worker transports and
the restricted-receiver race. The loopback remote-shell harness starts real
syq client and server processes and exercises the wire protocol, descriptor
broker, and TCP handoff; it does not test sshd authentication or claim to be a
network-filesystem stress test. Each operation family is tested at the shared
rooted primitive rather than repeating every operation over every transport:
after handoff, all transports use the same `Root` methods.

Linux normally resolves a multi-component confined parent in one `openat2`
call with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, relative to the already
opened root. This is a performance optimization, not a different authority
model: it permits nested mounts but neither `..` escape nor any descendant
symlink. If the syscall is unavailable, blocked, or rejects a request, syq
uses the portable component-by-component descriptor walk; it never falls back
to an unconfined full pathname. Direct tests compare the selected inode with
the portable walk, refuse an intermediate symlink, preserve the portable
failure, and cross a nested mount. macOS always uses the portable walk.

### What to do

- Prefer native `cp` without `--preserve` when you do not need owner, mode,
  or device preservation; it cannot be asked to create a setuid file.
- Treat every destination directory as a trust boundary for resume state, as
  you would rsync's `--partial-dir`. This matters most when syq runs as root.
- In rsync mode, leave `--insecure-links` off unless a symlinked parent in a
  file list is exactly what you mean.
- For an untrusted or semi-trusted source host in a remote-to-remote copy, use
  the default restricted path described below; it protects the destination
  from a compromised source, and the receipt tells you what actually landed.
- When another process may modify a destination file in place during a
  transfer, no file tool can promise a consistent result; use a snapshot.

## Least privilege for remote transfers

### The problem

`syq rsync hostA:src hostB:dst` runs the transfer on hostA, which must
authenticate to hostB. The traditional way to give hostA that ability is ssh
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
locally and forwards *that* to hostA instead of your real agent. The broker
holds no private keys; it forwards signing requests to your real agent (or to
the enrollment key below) only after validating the exact path the request is
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
*command*. If the broker is used with an ordinary key on hostB
(`--agent-broker-only`), hostA holds the full authority of that destination
account for the lifetime of the session. That mode restricts where and as
whom hostA may authenticate; the next layers restrict what it may do.

### Layer 2: enrollment

The first transfer to a destination parent on hostB (or an explicit
`syq enrollment add hostB:/path`) generates a dedicated Ed25519 key locally, uploads the
exact running syq to hostB as a receiver, and appends one managed
`restrict,command=...` line to hostB's `authorized_keys`. The private half of
that key never leaves the local machine. HostA never sees it; the broker signs
with it only along the verified path above. Before publishing the forced key,
syq creates its private directories as mode 0700 and secret files as mode 0600.
It does not try to infer receiver integrity from ownership, groups, ACLs, or an
ancestor-directory walk: the receiver machine and the programs it runs are the
trusted side of this boundary. Instead, a signed command-restricted transfer
is refused before copying when its mutation scope overlaps the receiver's SSH
configuration, installed receiver directory, enrollment state, or configured
signature verifier. Thus a compromised hostA cannot use otherwise valid copy
operations to replace the control plane used by a later connection. This rule
does not apply to ordinary local or remote copies. Enrollment can also
run through hostA as an ssh `ProxyJump`, in which case hostA carries encrypted
bytes and sees no agent, key, or session.

That one setup session is the bootstrap trust boundary: during it your local
ssh client has ordinary command authority on hostB, exactly as it would to
install anything. Every later transfer uses only the forced key. The
`syq-enrollment:ID` marker makes the managed line recognizable to users,
administrators, and monitoring, and `syq enrollment list` and
`syq enrollment revoke` manage its lifecycle. HostB also generates a receipt
signing key at installation and returns its public half, which the local
machine records with the enrollment (see Layer 6).

### Layer 3: signed, single-use requests

For each transfer, the local machine signs a typed request naming the exact
destination, login, copy semantics, hash block size, TCP port range, entry,
byte, deletion, and connection limits, a validity interval, and a fresh nonce.
HostA carries this request but cannot alter it. The forced receiver on hostB
verifies the signature (via OpenSSH's SSHSIG verifier and a policy file hostB
owns), durably claims the nonce before doing anything, enforces the deadline,
and then accepts protocol requests only within the signed scope. Redemption is
at most once; a replayed request is rejected.

Filters, `--inplace`, preservation, existing-object policy, and placement
preconditions are signed into the grant and enforced by the receiver on its
own. Deletion through the receiver requires an explicit `--max-delete`, and
the native `--max-entries`, `--max-total-bytes`, and `--max-runtime` options
lower the signed ceilings for one transfer, so what a claimed grant is worth to
hostA is always bounded on the command line. Options whose semantics the
receiver cannot enforce independently of hostA fail closed rather than
trusting hostA: `--files-from`, `--mapping`, `--update`, unencrypted or ssh
data transport, and several others (the
[complete list](remote-to-remote.md#signed-policies-and-options-that-fail-closed)
is in the remote-to-remote guide). `--dry-run` and verification-only runs are marked
read-only in the grant, and the receiver rejects every mutation under them even
if hostA sends one.

### Layer 4: the rooted receiver

Every destination scan, stat, hash, sidecar operation, metadata change, write,
and deletion the receiver performs is rewritten onto an opened root descriptor
with `O_DIRECTORY | O_NOFOLLOW` intermediate opens and descriptor-relative leaf
operations. Descendant symlinks are payload. There is no pathname fallback for
an unsupported operation. Preserved modes are bound to the inode the receiver
observed; a mode cannot be carried onto a replacement object. Without `-p`,
hostA cannot supply special bits or gain chmod authority over existing objects.

### Layer 5: data connections that inherit the grant

After the control session is authenticated, file data flows over encrypted,
token-authenticated TCP connections. The receiver permits one listener in the
signed port range and closes it when the control session ends or the grant
expires. There is no second ssh authentication and no silent fallback to an ssh
data path that would need one.

### Layer 6: signed, encrypted receipts

HostA carries the transfer, so on its own it could report success while having
written nothing. Every attached command-restricted transfer therefore ends
with hostB issuing a receipt: a stream with one outcome for every pathname
mutation the receiver saw (each file's lifecycle, each directory, symlink, or
metadata operation, each individual prune deletion, and every failed,
abandoned, or refused request), followed by the final type, size, and, with
`--receipt hashed`, BLAKE3 digest of every path an admitted mutation could have
changed. A small signed terminal record binds the stream to the complete
signed grant, the enrollment and one-time request IDs, and a clean or
non-clean status. HostB encrypts the stream and terminal to a fresh
per-transfer key; hostA relays opaque frames; your machine decrypts them and
checks the encryption's authentication, the enrolled Ed25519 signature, the
grant binding, the sequence, and the stream commitment before printing trusted
results. Missing, altered, reordered, replayed, or suppressed frames cannot
become a valid clean receipt, though suppression remains a denial of service.

The receipt is hostB's closure-time account of hostB: it says what landed, not
what hostA omitted or invented, and it is neither a transaction nor a rollback.
A detached restricted transfer is weaker: the receipt lands in hostA's log in
plaintext, the launcher warns about that even under `-q`, and `--follow`
displays completion without verifying it locally.

### Putting the layers together

| Mode | HostA receives | Protects hostB against a compromised hostA? | Data path |
|---|---|---|---|
| Default (enrolled receiver + broker + receipt) | A signed single-use grant; broker signs with the enrollment key for this path only | Yes: cannot escape the destination, widen semantics, exceed limits, replay, or misreport what landed | A → B directly |
| `--agent-broker-only` | Broker access to your ambient agent, valid only for hostA→user@hostB | Partially: cannot reach other hosts or users, but has that account's full authority during the session | A → B directly |
| `--coordinate-at local` | Nothing | Yes, by never involving hostA in authentication | A → you → B, at your bandwidth |
| `--no-forward-agent` | Nothing; hostA must already hold its own hostB credential | Out of syq's hands | A → B directly |
| `--unrestricted-agent-forwarding` | Your whole agent, as `ssh -A` would | No; compatibility escape hatch with a warning `-q` cannot silence | A → B directly |
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
transfers, in the default path and in `--agent-broker-only`; it is not
available as a standalone command.

The enrollment and grant layers likewise turn a Unix account into narrow,
revocable transfer capabilities. The receiver accepts a small typed protocol
rather than shell commands, which is what makes it auditable, and a grant names
an operation, a root, and limits. The policies it enforces are the copy,
verify, and delete semantics of syq's own transfers.

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
  helper cache; peers must present matching build identities to connect.
