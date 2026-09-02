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

To report a vulnerability, follow [SECURITY.md](../SECURITY.md).

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
access; and the protocol is fuzzed. Syq's design follows the same principles
and, in the places it has been applied, uses the same mechanisms. It has not
yet been applied everywhere.

### Where syq stands

The [threat inventory](threat-inventory.md) is the detailed, threat-by-threat
ledger, written against a specific code snapshot and compared with rsync 3.5.0.
The summary, grouped by whether syq matches rsync, is:

**Matches or exceeds rsync.**

- Every path a remote peer sends is validated before it reaches the
  filesystem: absolute names, NUL, empty components, `.` and `..` are rejected.
- The operator-named destination root is resolved with rsync's ownership rule
  (a symlink component is followed only when root or the receiving user owns
  it; `--insecure-links` is the explicit legacy opt-out), then retained as an
  opened directory whose device and inode every worker verifies, so changing
  the external spelling afterward cannot redirect the copy.
- Regular files are opened with `O_NOFOLLOW` and the opened type is checked;
  sidecars must be singly linked regular files; special files are refused
  without blocking.
- Planned deletion is non-recursive per leaf: a file that becomes a directory
  is not descended into. Deletion runs only after an error-free scan of both
  sides.
- Native `rm` resolves and pins every selector before its first change,
  enumerates opened directories, re-checks device, inode, and type, and removes
  with `unlinkat`. A name swapped to a different inode is refused, not deleted.
- The restricted remote-to-remote receiver performs every operation relative
  to an opened root; descendant symlinks are payload, never traversal.
- Native `cp` and `cp-prune` default to `-rlt`: no owner, group, mode, device,
  ACL, or xattr is applied unless the rsync-shaped flags ask for it, and ACLs
  and xattrs are not implemented at all. Several classes of rsync
  vulnerability are simply unreachable.

**Not yet at parity.**

- **Descendant parents in ordinary copies.** The destination root is retained,
  but many operations on descendants still use pathnames relative to it. An
  attacker who can replace an intermediate directory with a symlink between
  syq's plan and its write can redirect that write. Rsync holds the parent
  descriptor for every leaf. This is the most important open item; the
  descriptor-rooted primitives already used by the restricted receiver and
  native `rm` are the intended fix for the ordinary engine.
- **Ordinary source enumeration** is not uniformly rooted either, so the
  guarantee against a source-side symlink race needs a code-level audit beyond
  the passing regression cases.
- **Resume files.** Syq always keeps partials, at deterministic names
  (`.name.syq-part.<job-id>`) so a rerun finds its state without a state file.
  Rsync's equivalent, `--partial-dir`, is opt-in and its manual warns that the
  directory must not be writable by other users. The same warning applies to
  syq's destination directories, and applies by default: a user who can write
  the destination directory can pre-create a sidecar name. Mode `0600`
  creation and the singly-linked-regular-file check limit what that buys, but
  they cannot prove who created a predictable pathname. Do not run a
  privileged copy into a directory writable by untrusted users.
- **Protocol robustness.** Frames are length-bounded and several requests have
  specific limits, but there is no fuzzing corpus or resource envelope
  comparable to rsync's.

### What to do today

- Prefer native `cp` and `cp-prune` when you do not need owner, mode, or
  device preservation; they cannot be asked to create a setuid file.
- Treat every destination directory as a trust boundary for resume state, as
  you would rsync's `--partial-dir`. This matters most when syq runs as root.
- Leave `--insecure-links` off.
- For an untrusted or semi-trusted source host in a remote-to-remote copy, use
  the default restricted path described below; it protects the destination
  from a compromised source even though the ordinary engine on the source side
  is not what enforces it.
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
and the signature algorithm. Key addition and removal, raw or legacy signing,
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

The first transfer to a destination parent on hostB (or an explicit `syq
enroll hostB:/path`) generates a dedicated Ed25519 key locally, uploads the
exact running syq to hostB as a receiver, and appends one managed
`restrict,command=...` line to hostB's `authorized_keys`. The private half of
that key never leaves the local machine. HostA never sees it; the broker signs
with it only along the verified path above. Before publishing the forced key,
syq checks that the installed receiver and every path ancestor are owned by
the trusted user or root, are not writable by others, and carry no foreign ACL
grants, so the account cannot broaden its own authority. Enrollment can also
run through hostA as an ssh `ProxyJump`, in which case hostA carries encrypted
bytes and sees no agent, key, or session.

That one setup session is the bootstrap trust boundary: during it your local
ssh client has ordinary command authority on hostB, exactly as it would to
install anything. Every later transfer uses only the forced key. The
`syq-enrollment:ID` marker makes the managed line recognizable to users,
administrators, and monitoring, and `syq enrollments` and `syq revoke` manage
its lifecycle.

### Layer 3: signed, single-use requests

For each transfer, the local machine signs a typed request naming the exact
destination, login, copy semantics, hash block size, TCP port range, entry,
byte, deletion, and connection limits, a validity interval, and a fresh nonce.
HostA carries this request but cannot alter it. The forced receiver on hostB
verifies the signature (via OpenSSH's SSHSIG verifier and a policy file hostB
owns), durably claims the nonce before doing anything, enforces the deadline,
and then accepts protocol requests only within the signed scope. Redemption is
at most once; a replayed request is rejected.

Options whose semantics the receiver cannot enforce independently of hostA
fail closed rather than trusting hostA: filters, `--files-from`, `--mapping`,
`--inplace`, unencrypted or ssh data transport, and several others (the
[complete list](remote-to-remote.md#options-that-fail-closed-under-the-restricted-path)
is in the remote-to-remote guide). `--dry-run` and `--verify-only` are marked
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

### Putting the layers together

| Mode | HostA receives | Protects hostB against a compromised hostA? | Data path |
|---|---|---|---|
| Default (enrolled receiver + broker) | A signed single-use grant; broker signs with the enrollment key for this path only | Yes: cannot escape the destination, widen semantics, exceed limits, or replay | A → B directly |
| `--agent-broker-only` | Broker access to your ambient agent, valid only for hostA→user@hostB | Partially: cannot reach other hosts or users, but has that account's full authority during the session | A → B directly |
| `--relay` | Nothing | Yes, by never involving hostA in authentication | A → you → B, at your bandwidth |
| `--no-forward-agent` | Nothing; hostA must already hold its own hostB credential | Out of syq's hands | A → B directly |
| `--unrestricted-agent-forwarding` | Your whole agent, as `ssh -A` would | No; compatibility escape hatch with a warning `-q` cannot silence | A → B directly |
| `-e CMD` | Whatever the command does | Whatever the command does | A → B directly |

In every mode, a compromised hostA remains an untrusted *source*: it can omit
files, alter contents, lie about metadata, or stop. The design protects the
destination and your other credentials, not the fidelity of what a hostile
source chooses to send. Session binding identifies hostB by host key, not name;
two hosts sharing a private host key are the same host to the broker.

### Beyond copying

The broker is not specific to file transfer. "Forward my agent to this host,
usable only to log into that user on that other host" is what most people
actually want from `ssh -A`: pushing from a build host to one git server,
running a configuration tool from a jump host, running rsync itself from hostA
to hostB. Today the broker exists only inside syq's transfers (the default
remote-to-remote path and `--agent-broker-only`); exposing it as a standalone
command is the natural next step and is under consideration. Its requirements
would be the same: OpenSSH 8.9 or newer on all three hosts and exact host keys
in your local `known_hosts`.

The enrollment-and-grant layers generalize in a different direction: they turn
a Unix account into a set of narrow, revocable *transfer capabilities*. The
receiver accepts a small typed protocol rather than shell commands, which is
what makes it auditable, and a grant names an operation, a root, and limits.
The same shape supports read-only publishing, write-without-delete deposits,
mirroring, and append-only backup targets where committed snapshots sit
outside the uploader's authority. Those policies are design directions, not
shipped features; the current receiver enforces the copy, verify, and delete
semantics syq's transfers need, and the project deliberately does not intend
to grow it into a general remote-command-authorization system.

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
  secrets it needs. [RELEASING.md](../RELEASING.md) has the procedure.
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
- **SDKs pin a release.** Each SDK release pins one syq release and verifies the
  downloaded binary against the manifest embedded in the package before every
  use.
- **Source builds are honest about identity.** A checkout build carries its Git
  revision, is not an immutable release, and cannot populate the managed
  helper cache; peers must present matching build identities to connect.

## Known gaps and direction

In priority order, as the maintainers see it:

1. Descriptor-rooted descendant operations for the ordinary copy engine and
   source scan, closing the parity gap with rsync's held-parent model.
2. A live two-host integration exercise of the broker and restricted receiver
   with a hardware token, beyond the current protocol-level tests.
3. A fuzzing corpus and resource envelope for the peer protocol.
4. A standalone broker command.
5. Transfer-capability policies (deposit, read-only) on the enrolled receiver.

The [threat inventory](threat-inventory.md) records the evidence behind each
of these at a named code snapshot and should be re-inspected whenever the
filesystem or receiver code changes.
