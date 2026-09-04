# Remote-to-remote transfers

Rsync can copy between the machine you run it on and one remote host. Syq can
also copy directly between two remote hosts, `syq cp --from hostA ... --to
hostB ...`, and it does so without handing hostA your ssh agent. In such a
copy, hostA is the coordinator (the host that runs the copy) and hostB is the
peer (the other remote host). This document describes how the copy is laid
out; the restricted path, which is the default for a remote-to-remote copy (a
constrained agent broker on your machine plus the command-restricted receiver,
a forced command on hostB that syq installs when you enroll a destination);
what that path does and does not protect; the policies signed into each
transfer and the options that are refused under it; the enrollment lifecycle;
and the escape hatches. The design rationale and threat model are in
[Security](security.md); the native layout and transport options are in the
[command reference](reference.md#native-commands).

## Topology

Rsync refuses two remote operands, and so does rsync mode (`syq rsync`). The
native commands accept them:

```sh
syq cp --from hostA --srcs-in big --to hostB --into big
syq cp --prune --from hostA --srcs-in tree --to hostB --into-existing tree
```

syq starts the coordinator on hostA and sends data straight to hostB, so file
data does not pass through your machine; path arguments travel encoded in the
command syq runs on hostA, so any filename works. Matching helpers are
installed automatically on both hosts and output is streamed back. When both
endpoints name the same host and user, syq runs a local copy on that host.
For a source build, `--syq-path` or `--no-bootstrap` chooses the syq executable
that runs as the coordinator on hostA, including on the restricted path. It
does not choose the receiver on hostB: that executable is the restricted
receiver installed by enrollment and is replaced only by enrolling again.

## The default path: enrolled receiver plus constrained broker

When syq runs ssh itself (no `--rsh`), the default is the restricted path: the
restricted receiver enrolled on hostB plus the broker, a temporary agent socket
on your machine. The first transfer to a destination parent generates an
Ed25519 enrollment key locally, uploads the exact running syq as
`~/.local/libexec/syq-receiver` on hostB, and appends one managed
`restrict,command=...` line to hostB's `authorized_keys`. The private enrollment
key stays under `~/.local/state/syq/restricted/` on the local machine and is
never copied to hostA. HostB keeps the enrollment key's public half, the policy
file it uses to verify signed grants, its record of which grants were already
redeemed, and a receipt signing key it generates at installation under
`~/.local/share/syq/restricted/`; the receipt key's public half is returned to
the local machine and recorded with the enrollment. Syq creates private
enrollment directories with mode 0700 and secret files with mode 0600; it does
not refuse to run because of the Unix ownership, group membership, or ACLs of
the receiver binary, the verifier, or their ancestor directories. Those files
are part of the trusted receiver machine, not something a hostile source can
make trustworthy through a permission check.

Instead, every grant (the signed, single-use authorization for one transfer)
is rejected before copying if any destination directory it may change overlaps
the receiver's SSH configuration, installed receiver directory, enrollment
state, or configured signature verifier. Your machine performs the same check
before anything is written where it knows the paths, and the receiver's own
check is the one that counts. This protection applies only to the restricted
receiver; local copies and remote copies that do not use it keep their normal
destination behavior.

That state directory is not a cache. Removing `~/.cache/syq` on either host
only costs a fresh helper bootstrap on the next transfer, but removing
`~/.local/share/syq/restricted` on hostB breaks every enrollment there and
discards the record of which grants were already redeemed; revoke and
enroll again instead.

Enrollment first tries local→hostB directly. If SSH reports a transport
failure, it retries through hostA with OpenSSH `ProxyJump`; a remote validation
or installation error is reported against hostB without repeating it through
the proxy. HostA gets only
`ssh -W` byte forwarding and cannot see the encrypted hostB session, an agent
socket, or the enrollment key. The destination parent must already exist.
Enrollment is durable, is reused for later destinations inside the same
parent, and is reported as an intentional remote state change. The local
OpenSSH client has ordinary command authority on hostB during this initial
installation, whether the connection is direct or tunneled through hostA. That
one setup session is the bootstrap trust boundary; later transfers use only the
enrollment key. Syq generates that key automatically, and its
`syq-enrollment:ID` marker makes the managed `authorized_keys` line
recognizable to users, administrators, and monitoring tools.

## Signed per-transfer requests

For each transfer, your machine signs a grant naming the exact destination,
login, copy semantics, hash block size, TCP port range, limits, start-by and
finish-by times, and a fresh single-use nonce. The broker advertises only the
enrollment key to hostA and releases its signature only after validating this
path:

```text
trusted hostA session -> configured-user@trusted-hostB session
```

The broker verifies OpenSSH session-bind signatures for both hosts and strictly checks
the final host-bound authentication request's session ID, destination login
user, host key, selected credential, and signature algorithm. Key addition,
removal, raw or non-host-bound signing, unknown extensions, and extra forwarding hops
are refused. The A → B client is forced to use host-bound public-key
authentication. The restricted receiver verifies the grant and records it as
redeemed on disk before starting syq's protocol. Every destination scan, stat,
hash, partial-file operation (the partial file is `.name.syq-part.<copy-id>`,
which syq writes into before renaming it into place), metadata change, write,
and deletion happens relative to the open handle of the enrolled directory. A
symlink below it is copied as data, never followed. HostA cannot replace that
guard, widen the destination, add an unsigned preservation option, exceed the
signed entry, byte, deletion, or connection limits, or replay the grant.
Copying with `--preserve=permissions` and copying without it use distinct
protocol flags and signed policy. Without it, existing objects keep the mode
hostB observed; new objects (an object is a file, directory, symlink, or
special file) accept only ordinary permission bits masked by hostB's umask.
HostA cannot supply special bits or turn this path into chmod authority over
existing objects. A new directory does keep a setgid bit inherited from its
destination parent by hostB's kernel; that bit is read from the newly created
inode and is not accepted from hostA's mode proposal. A preserved mode is bound
to the inode the receiver observed; if that object changes, publication (the
final rename into place) fails instead of carrying the mode onto a
replacement. Hash requests must use the signed block size, and the receiver
rejects any request whose hash vector could exceed the protocol frame limit.
Workers on TCP data connections, encrypted and authenticated by a token,
inherit the same authority. The receiver permits one encrypted listener in the
signed port range and closes it when the control session through the
restricted receiver ends or the grant expires; after redemption there is no
second SSH authentication or silent SSH fallback.

The restricted path gives hostA neither a credential nor access to your
agent. Your own agent (including a YubiKey) is used for the login from your
machine to hostA and for the enrollment sessions, but hostA never gets access
to it.

## What the restriction does and does not protect

The restriction protects hostB; it does not make hostA a trustworthy source.
A compromised hostA can invent the source tree wholesale: names, object types,
metadata, and file bytes need not correspond to anything on hostA's filesystem.
It can also omit entries or stop the transfer. HostB can enforce only what is
signed into the grant and visible in the requests it receives: the destination
directories, the publication, preservation, and existing-object policies,
resource limits, and whether a requested change could have come through the
signed ignore rules. HostA still cannot escape those checks or independently
authenticate to hostB with the enrollment key.

## Signed receipts

HostA also cannot forge a clean account of what hostB's restricted receiver
did. Every transfer on the restricted path that stays attached (not
`--detach`) ends with a receipt. Its stream records one outcome for every
change to a pathname that the receiver saw: one file lifecycle, each
directory, symlink, special-file, or metadata operation, and each individual
`--prune` unlink or rmdir. Failed and abandoned operations, and a bounded
number of records for refused requests, remain visible. After closing the grant
and waiting for admitted requests to settle, hostB records the final type,
size, symlink target, applicable metadata, and optional BLAKE3 digest of every
path an admitted change could have touched. Paths are raw bytes relative to
the numbered destination directories in the grant, never absolute hostB paths.

A small signed terminal record (the record that closes the receipt) binds the
complete signed grant, the enrollment ID and the grant's single-use ID, the
stream's digest, record count, and size, the policy, the summary, and a clean
or non-clean status. HostB then encrypts the stream and the terminal record to
a fresh per-transfer X25519 recipient key using HPKE (X25519/HKDF-SHA-256/
ChaCha20-Poly1305). HostA relays bounded opaque frames. Your machine spools
them to a temporary file rather than holding them in memory, decrypts them,
and checks the HPKE authentication, the enrolled Ed25519 signature, the grant
binding, the sequence, the digest of the complete stream, the summary, and the
terminal status before printing trusted results. Missing, altered, reordered,
replayed, or suppressed frames cannot become a valid clean receipt; suppression
remains a denial of service. `-v` prints the verified totals. Enrollments made
by an older syq must be refreshed with `syq receiver enroll` first (a copy
that is not read-only does this automatically). The initial signed policy caps
the stream at 4,000,000 records and 512 MiB of plaintext. Reaching either cap
ends the receiver's authority to make further changes and produces an explicit
non-clean terminal record instead of a truncated clean receipt. Encryption
does not pad or conceal frame count, ciphertext length, or timing.

This is hostB's account of its own state when the transfer closed, not a
transaction or a list of what the source held. It does not prove that hostA
supplied every intended path or the intended bytes, roll back a failed
transfer, list source scans, blocks, system calls, or the descendants of one
recursive operation, protect against a compromised hostB or receipt key,
protect against a writer on hostB already authorized to modify the tree, or
freeze the observed state after the receipt is issued. Diagnostic text is
there for context and may change; the structured codes and outcomes are the
stable part. Proving that every intended path and byte arrived would need an
authenticated list of what was expected, which the receipt does not provide.

`--detach` is not available with the restricted receiver because the broker
exists only while syq remains attached. A detached launch instead requires
hostA to hold its own credentials for hostB (`--peer-auth own-credentials`) or
an explicit `--rsh` policy. Neither path prepares a restricted grant or signed
receipt; the returned remote log is not a receipt your machine can verify.

## Signed policies and options that fail closed

The restricted path requires encrypted TCP data connections (`--no-tcp` and
`--tcp-plain` are refused). The ordered `--ignore` rules are signed into the
grant: the receiver requires destination scans to use exactly those rules and
rejects changes that could only descend through an ignored source directory.
Whether such destination paths may be deleted is also signed; native `--prune`
protects ignored paths and does not delete them. The destination directory
each source maps to is signed, so a source you named explicitly keeps its own
destination directory even when it overlaps a path ignored under a `--srcs-in`
selection.
The signed publication policy distinguishes writing to a partial file and
renaming it into place from `--inplace`; an in-place write opens and writes the
final file relative to the open handle of the enrolled directory and cannot
silently switch back to the partial-file method.
The policy for objects that already exist at the destination is signed and
enforced by the receiver. It can tell the receiver to create only: every
creation and publication then refuses to replace anything, metadata or content
changes to any non-directory that existed before the transfer are refused, and
existing directories are reused, as in any copy. It can instead tell the
receiver to update only: the receiver then refuses to create any object and
ties each update to the object it observed, so an existing object cannot
change type. These are policies inside the grant rather than options you type:
the native commands do not have rsync mode's `--ignore-existing` and
`--existing`, and rsync mode cannot run a remote-to-remote copy. What you can
type is the placement: `--into-new`/`--as-new` and
`--into-existing`/`--as-existing` travel as a signed precondition on the
destination directory, checked against the enrolled directory when the grant
is redeemed. `--inplace` is refused together with `--as-new` on this path,
because an in-place write opens the final pathname directly and can neither
refuse to replace nor be tied to an observed object.
The native commands have no equivalent of rsync mode's `--update` (skip files
that are newer on the destination), and the restricted path would refuse it
anyway: it compares against source modification times that only hostA reports.
`--mapping` and `--min-size` are refused because the receiver cannot check
them independently of hostA.
`--max-size` is enforced as a signed per-file limit, but is refused together
with `--prune` because filtered source files could otherwise make hostA's
deletion plan ambiguous. Explicit `--connections` values above 64 are also
refused; automatic tuning may use up to that signed ceiling.

Deletion through the receiver (`cp --prune`) requires an explicit
`--max-delete`, so the deletion authority a compromised hostA could exercise
inside the scope is always stated on the command line rather than defaulting
to a hundred million; `--max-delete 0` signs a grant that forbids deletion
outright. The other signed ceilings default to 100 million entries and 8 TiB of
file data; native `--receiver-max-entries` and `--receiver-max-bytes` lower them for one
transfer, which bounds what a redeemed grant is worth to hostA. Every grant also
carries two deadlines: hostA must start the transfer within 24 hours of the
grant being issued, and the transfer must finish within 7 days of it.

`--dry-run` is read-only in a way hostA cannot override: the signed grant
marks it read-only and the receiver rejects every mutation even if hostA sends
one. (The native commands have no equivalent of rsync mode's
`--syq-verify-only`.) A dry run uses an existing enrollment but does not
install one; run `syq receiver enroll` first when previewing a new destination.
A destination directory that is itself a symlink is also refused on this path;
enroll the directory the link points to, so that the signed pathname and the
opened directory identify the same object.

One rsync-shaped edge case is handled conservatively inside the grant. In
rsync's operand spelling, a named directory source such as `hostA:dir` lands
either inside the destination or exactly at it, depending on whether the
destination already exists; the grant authorizes only the reading where the
destination is an existing directory, so if it does not exist, creating
children at the exact-path reading is denied. The native commands avoid the
ambiguity because `--as` and `--into` state the placement explicitly, and
rsync mode cannot run a remote-to-remote copy in any case; create the
destination directory first if that distinction ever matters.

## Enrollment lifecycle

Use `syq receiver enroll [USER@]HOST:DEST [--via [USER@]HOST]` to pre-enroll,
`syq receiver list` to list local enrollments, and
`syq receiver revoke ID [--via ...]` to
remove the enrollment key from hostB's `authorized_keys` and both sides'
per-enrollment state. Before changing
hostB, syq durably records a pending enrollment and its private key locally. If
the installation response is lost, the next enrollment of the same endpoint
and destination retries the same ID safely; `syq receiver list` labels that
state `pending`, and `syq receiver revoke` can remove either pending or
active state. Running `syq receiver enroll` again for an active destination
also refreshes the installed
receiver to the exact local syq binary; the receipt key is kept for the life
of the enrollment, so a refresh, or a retry after a lost reply, never leaves
the two sides holding different keys. To rotate it, revoke and enroll again.
Revocation keeps the shared receiver while another enrollment or managed
`authorized_keys` entry may use it. The final revoke removes the shared
receiver and, once it is empty, the `syq/restricted` state directory on hostB.
General account directories such as `.local`, `share`, and `libexec` are
preserved even when empty because syq does not assume it created them.
Enrolling and revoking each upload and run a temporary helper within one SSH
session, which removes the helper's files when it ends. Enrolling and revoking
take turns with the shared receiver, so an enrollment that runs at the same
time as a revoke reinstalls the receiver before installing its enrollment key.
Revocation prevents new receiver sessions. A session that already redeemed its
grant can finish an operation already in progress; once the grant's finish-by
deadline passes, later protocol requests are rejected rather than interrupting
a filesystem call midway.

## Requirements and host identity

The restricted path requires OpenSSH 8.9 or newer session-bind and host-bound
authentication support on the local machine, hostA, and hostB; a local
`SSH_AUTH_SOCK`; and exact plain host keys for both hosts in the effective local
`known_hosts` files. Host-certificate/CA-only trust is refused because syq does
not validate certificate principals and validity as strictly as OpenSSH. Static
`HostKeyAlgorithms` and `RequiredRSASize` policy is enforced. A configured
`KnownHostsCommand` or `RevokedHostKeys` KRL is refused because the broker does
not reproduce those dynamic or external revocation checks. Host-key
algorithms that syq's SSH library cannot cryptographically verify are refused.
OpenSSH's `ssh -G` output does not preserve quoting for custom known-hosts
filenames. Syq uses OpenSSH's debug provenance to inspect the configuration
files OpenSSH actually read for the host. It accepts the compiled default list
only when none of those files contains the corresponding known-hosts directive;
an explicitly configured value that renders exactly like the defaults is still
treated as configured. Otherwise syq accepts one absolute whitespace-free
configured file per
`UserKnownHostsFile`/`GlobalKnownHostsFile` directive. Ambiguous custom
multi-file or whitespace-containing values fail closed.

The local configuration resolves hostB's login user, network hostname, port,
and host-key algorithms, and syq passes those values explicitly to hostA. The
ssh client hostA runs to reach hostB (the inner client) reads no hostA SSH
configuration, disables all identity and
certificate files and PKCS#11 providers, and permits only public-key
authentication through its forwarded `SSH_AUTH_SOCK`. Its ordinary
`known_hosts` lookup is disabled because the broker independently validates
the session-bound host key against the stricter local policy before releasing
a signature. Thus hostA's `IdentityFile`, `CertificateFile`, `IdentityAgent`,
`IdentitiesOnly`, proxy, and multiplexing configuration cannot accidentally
bypass the broker. This does not revoke unrelated credentials that an already
privileged hostA possessed before syq; the restricted path assumes precisely
that hostA has no hostB credential of its own. Connection multiplexing is
disabled for the session from your machine to hostA (the outer session) so a
pre-existing master connection cannot substitute another forwarded agent.
Configured
port forwards, X11 and GSS credential delegation, PTY allocation, and
`LocalCommand` are also disabled on that session.

Session binding identifies a host by its host key, not by a DNS name or network
address. The configured name chooses the locally trusted key set, but an
endpoint that shares hostB's private host key is intentionally equivalent to
hostB for this broker. Deployments requiring distinct host identities must not
reuse host private keys between them.

Syq uses your SSH configuration to resolve the login user, host-key name,
port, static known-hosts files, host-key algorithms, and RSA size. The broker
requires already recorded exact keys for hostA and hostB before connecting; it
never learns a key through hostA or silently accepts one.
Dynamic `KnownHostsCommand`, external `RevokedHostKeys`, and host-certificate
trust are refused as described above. If first-contact trust is
appropriate, establish it with ordinary SSH (directly or through the configured
jump path) before starting the transfer.
