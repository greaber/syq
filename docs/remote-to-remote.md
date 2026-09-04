# Remote-to-remote transfers

Rsync can copy between the machine you run it on and one remote host. Syq can
also copy directly between two remote hosts, `syq cp --from hostA ... --to
hostB ...`, and it does so without handing hostA your ssh agent. This document
describes the topology, the default least-privilege authentication path, what
it does and does not protect, the signed policies and the options that fail
closed under it, enrollment lifecycle, and the escape hatches. The design
rationale and threat model are in [Security](security.md); the native
topology and transport options are in the
[command reference](reference.md#native-commands).

## Topology

Rsync refuses two remote operands, and so does `syq rsync`. Native copy keeps
syq's endpoint-aware remote-to-remote operation:

```sh
syq cp --from hostA --srcs-in big --to hostB --into big
syq cp --prune --from hostA --srcs-in tree --to hostB --into-existing tree
```

syq starts the coordinator on hostA and pushes directly to hostB, so file
data does not traverse the invoking machine; path operands travel encoded in
the delegated command, so any filename works. Matching helpers are installed
automatically on both hosts and output is streamed back. When both endpoints
name the same host and user, syq runs a local copy on that host.
For a source build, `--syq-path` or `--no-bootstrap` selects the ordinary hostA
coordinator, including on the command-restricted path. It is not forwarded as
authority to choose hostB's receiver: that executable is the separately
enrolled forced command and is refreshed by enrollment.

## The default path: enrolled receiver plus constrained broker

With implicit OpenSSH, the default combines a pre-enrolled forced receiver on
hostB with a temporary local agent broker. The first transfer to a destination
parent generates an Ed25519 enrollment key locally, uploads the exact running
syq as `~/.local/libexec/syq-receiver` on hostB, and appends one managed
`restrict,command=...` line to hostB's `authorized_keys`. The private enrollment
key stays under `~/.local/state/syq/restricted/` on the local machine and is
never copied to hostA. HostB keeps its forced public key, SSHSIG verifier
policy, replay state, and a receipt signing key it generates at installation
under `~/.local/share/syq/restricted/`; the receipt key's public half is
returned to the local machine and recorded with the enrollment. Syq creates
private enrollment directories with mode 0700 and secret files with mode 0600;
it does not reject the invoking binary, verifier, or their ancestor directories
based on Unix ownership, group membership, or ACLs. Those files are part of the
trusted receiver machine, not something a hostile source can make trustworthy
through a permission check.

Instead, every command-restricted grant is rejected before copying if any of
its mutation scopes overlaps the receiver's SSH configuration, installed
receiver directory, enrollment state, or configured signature verifier. The
local machine performs the same preflight where it knows the paths, and the
receiver enforces it authoritatively. This protection applies only to the
enrolled command-restricted receiver; ordinary local and remote copies retain
their normal destination semantics.

That state directory is not a cache. Removing `~/.cache/syq` on either host
only costs a fresh helper bootstrap on the next transfer, but removing
`~/.local/share/syq/restricted` on hostB breaks every enrollment there and
discards the record of which signed requests were already redeemed; revoke and
enroll again instead.

Enrollment first tries local→hostB directly. If SSH reports a transport
failure, it retries through hostA with OpenSSH `ProxyJump`; a remote validation
or installation error is reported against hostB without repeating it through
the proxy. HostA gets only
`ssh -W` byte forwarding and cannot see the encrypted hostB session, an agent
socket, or the enrollment key. The destination parent must already exist.
Enrollment is durable, is reused for later destination leaves sharing that
parent, and is reported as an intentional remote state change. The local
OpenSSH client has ordinary command authority on hostB during this initial
installation, whether the connection is direct or tunneled through hostA. That
one setup session is the bootstrap trust boundary; later transfers use only the
forced key. Syq generates the special key automatically, and its
`syq-enrollment:ID` marker makes the managed `authorized_keys` line
recognizable to users, administrators, and monitoring tools.

## Signed per-transfer requests

For each transfer, the local machine signs a typed request naming the exact
destination, login, copy semantics, hash block size, TCP port range, limits,
start-by and finish-by times, and a fresh one-time nonce. The temporary broker advertises
only that enrollment key to hostA and releases its signature only after
validating this path:

```text
trusted hostA session -> configured-user@trusted-hostB session
```

The broker verifies OpenSSH session-bind signatures for both hosts and strictly checks
the final host-bound authentication request's session ID, destination login
user, host key, selected credential, and signature algorithm. Key addition,
removal, raw or non-host-bound signing, unknown extensions, and extra forwarding hops
are refused. The A → B client is forced to use host-bound public-key
authentication. The forced receiver verifies and durably redeems the signed
request before starting syq's protocol. Every destination scan, stat, hash,
sidecar operation, metadata change, write, and deletion is rewritten onto the
enrolled root descriptor. Descendant symlinks are payload, never traversal.
HostA cannot replace that guard, widen the destination, add an unsigned
preservation option, exceed signed entry/byte/deletion/connection limits, or
replay the request. Source-permission preservation and ordinary non-`-p`
creation/restoration use distinct protocol flags and signed policy. For
non-`-p` requests, existing objects retain the mode observed on hostB; new
objects accept only ordinary permission bits masked by hostB's umask. HostA
cannot supply special bits or turn this path into chmod authority over existing
objects. A new directory does retain a setgid bit inherited from its destination
parent by hostB's kernel; that bit is read from the newly created inode and is
not accepted from HostA's mode proposal. Preserved modes are bound to the
receiver-observed inode fingerprint; publication fails if that object changes
instead of carrying its mode onto a replacement. Hash requests must use
the signed block size, and the receiver rejects any request whose hash vector
could exceed the protocol frame
limit.
Encrypted token-authenticated TCP workers inherit the same authority. The
receiver permits one encrypted listener in the signed port range and closes it
when the forced control session ends or the grant expires; after redemption
there is no second SSH authentication or silent SSH fallback.

This preferred path gives hostA neither a credential nor an ambient-agent
capability. The local ambient agent—including a YubiKey—is used for the
local→hostA login and ordinary enrollment SSH sessions, but hostA never gets
access to it.

## What the restriction does and does not protect

The restriction protects hostB; it does not make hostA a trustworthy source.
A compromised hostA can invent the source tree wholesale: names, object types,
metadata, and file bytes need not correspond to anything on hostA's filesystem.
It can also omit entries or stop the transfer. HostB can enforce only signed
command properties visible in receiver requests, such as destination scopes,
publication, preservation, and existing-object policy, resource limits, and
whether a requested mutation could have survived the signed filter traversal. HostA still cannot
escape those checks or independently authenticate to hostB with the enrollment
key.

## Signed receipts

HostA also cannot forge a clean account of what hostB's restricted receiver
did. Every attached command-restricted transfer ends with a receipt. Its
canonical stream records one outcome for every receiver-visible logical
pathname mutation: one file lifecycle, each directory/symlink/special or
metadata operation, and each individual `--prune` unlink or rmdir. Failed and
abandoned operations and bounded refusal records remain visible. After closing
the grant and waiting for admitted requests to settle, hostB records the final
type, size, symlink target, applicable metadata, and optional BLAKE3 digest of
every path an admitted mutation could have changed. Paths are raw bytes
relative to numbered signed mutation scopes, never ambient absolute hostB
paths.

The small signed terminal binds the complete signed grant, enrollment and
one-time request IDs, stream digest/count/size, policy, summary, and clean or
non-clean status. HostB then encrypts the stream and signed terminal to a fresh
per-transfer X25519 recipient key using HPKE (X25519/HKDF-SHA-256/
ChaCha20-Poly1305). HostA relays bounded opaque frames. The invoking machine
spools them outside the heap, decrypts them, and checks HPKE authentication,
the enrolled Ed25519 signature, grant binding, sequence, complete stream
commitment, summary, and terminal status before printing trusted results.
Missing, altered, reordered, replayed, or suppressed frames cannot become a
valid clean receipt; suppression remains a denial of service. `-v` prints the
verified totals. Enrollments made by an older syq must be refreshed with
`syq receiver enroll` first (eligible ordinary copies can do this
automatically). The initial signed policy caps the stream at 4,000,000 records
and 512 MiB of plaintext. Reaching either cap closes further mutation authority
and produces an explicit non-clean terminal instead of a truncated clean
receipt. Encryption does not pad or conceal frame count, ciphertext length, or
timing.

This is hostB's closure-time account, not a transaction or a source manifest.
It does not prove that hostA supplied every intended path or the intended
bytes, roll back a failed transfer, inventory source scans, blocks, syscalls,
or descendants of one logical recursive operation, protect a compromised
hostB or receipt key, protect against a hostB-local writer already authorized
to modify the tree, or make the observed state immutable after issuance.
Diagnostic text is bounded context rather than a stable interface; structured
codes and dispositions are authoritative. An authenticated expected manifest
is required for source completeness and byte authenticity.

`--detach` is not available with the command-restricted receiver because its
constrained agent exists only while syq remains attached. A detached launch
instead requires coordinator-owned peer credentials (`--peer-auth own-credentials`) or
an explicit `--rsh` policy. Neither path prepares a restricted grant or signed
receipt; the returned remote log is not a locally authenticated receipt.

## Signed policies and options that fail closed

The command-restricted path requires encrypted TCP data connections. Ordered
filter rules and `--delete-excluded` are included in the signed grant: the
receiver requires destination scans to use the exact policy and rejects
mutations that could only descend through a pruned source directory unless
their deletion was explicitly authorized. Each source's actual mapped
destination root is signed, so an explicitly selected named source remains a
root even when it overlaps an ignored path from another contents source.
The signed publication policy distinguishes atomic staged writes from
`--inplace`; in-place requests use descriptor-relative opens and writes beneath
the enrolled root and cannot silently switch back to staged publication.
The existing-object policy is signed and enforced by the receiver. Under
`--ignore-existing` every creation and publication is forced to no-replace
creation, and metadata or content changes to any non-directory that existed
before the transfer are refused; existing directories are reused, as in the
ordinary engine. Under `--existing` the receiver refuses to create any object
and pins each update to the object it observed, so an existing object cannot
change type. `--inplace` is refused together with `--ignore-existing`,
`--existing`, or `--as-new` on this path, because an in-place write opens the
final pathname directly and can neither be made no-replace nor be pinned to
an observed object.
Native `--into-new`/`--as-new` and `--into-existing`/`--as-existing` travel as
a signed root precondition, checked against the enrolled root when the grant is
redeemed. `--update` still fails closed because it compares against source
modification times that only hostA reports.
`--mapping` and `--min-size` also fail closed because the receiver cannot
enforce those semantics independently of hostA.
`--max-size` is enforced as a signed per-file limit, but is refused together
with deletion because filtered source files could otherwise make hostA's
deletion plan ambiguous. Explicit `--connections` values above 64 are also
refused; auto tuning may use up to that signed ceiling.

Deletion through the receiver (`cp --prune`) requires an explicit
`--max-delete`, so the deletion authority a compromised hostA could exercise
inside the scope is always stated on the command line rather than defaulting
to a hundred million; `--max-delete 0` signs a grant that forbids deletion
outright. The other signed ceilings default to 100 million entries and 8 TiB of
file data; native `--receiver-max-entries` and `--receiver-max-bytes` lower them for one
transfer, which bounds what a redeemed grant is worth to hostA. Every grant also
carries two deadlines: hostA must start the transfer within 24 hours of the
grant being issued, and the transfer must finish within 7 days of it.

`--dry-run` and `--verify-only` are cryptographically read-only: the signed
grant marks them as such and the receiver rejects every mutation even if hostA
sends one. They use an existing enrollment but do not install one; run
`syq receiver enroll` first when previewing or verifying a new destination.
Destination-root symlinks are also refused in this mode; enroll the explicit
referent so the signed pathname and opened root identify the same object.

One conservative rsync-shaped edge fails safely: for a named recursive source
such as `hostA:dir` and a destination path whose existence changes rsync's
placement meaning, the grant authorizes the existing-directory interpretation.
If that destination does not exist, creation of children at the alternate
exact-path interpretation is denied. Use a trailing slash (`hostA:dir/`), the
native `--as`/`--into` placement spelling, or create the destination directory
first when that distinction matters.

## Enrollment lifecycle

Use `syq receiver enroll [USER@]HOST:DEST [--via [USER@]HOST]` to pre-enroll,
`syq receiver list` to list local enrollments, and
`syq receiver revoke ID [--via ...]` to
remove the forced key and both sides' per-enrollment state. Before changing
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
forced-key entry may use it. The final revoke removes the shared receiver and
empty `syq/restricted` state namespace on hostB. General account directories
such as `.local`, `share`, and `libexec` are preserved even when empty because
syq does not assume it created them. Each installer or revoker uploads and runs
its temporary management helper within one SSH session whose cleanup trap owns
the stage. Install and revoke serialize the shared receiver lifecycle, so a
concurrent enrollment recreates the receiver before publishing its forced key.
Revocation prevents new receiver sessions. A
session that already redeemed its signed request can finish an operation already
in progress; later protocol requests are rejected once the signed execution
deadline expires rather than forcibly interrupting a filesystem syscall.

## Requirements and host identity

The constrained path requires OpenSSH 8.9 or newer session-bind and host-bound
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
inner client reads no hostA SSH configuration, disables all identity and
certificate files and PKCS#11 providers, and permits only public-key
authentication through its forwarded `SSH_AUTH_SOCK`. Its ordinary
`known_hosts` lookup is disabled because the broker independently validates
the session-bound host key against the stricter local policy before releasing
a signature. Thus hostA's `IdentityFile`, `CertificateFile`, `IdentityAgent`,
`IdentitiesOnly`, proxy, and multiplexing configuration cannot accidentally
bypass the broker. This does not revoke unrelated credentials that an already
privileged hostA possessed before syq; the preferred threat model is precisely
that hostA has no independent hostB credential. Connection
multiplexing is disabled for the outer session
so a pre-existing master cannot substitute another forwarded agent. Configured
port forwards, X11 and GSS credential delegation, PTY allocation, and
`LocalCommand` are also disabled on that session.

Session binding identifies a host by its host key, not by a DNS name or network
address. The configured name chooses the locally trusted key set, but an
endpoint that shares hostB's private host key is intentionally equivalent to
hostB for this broker. Deployments requiring distinct host identities must not
reuse host private keys between them.

SYQ uses the user's SSH configuration to resolve the login user, host-key name,
port, static known-hosts files, host-key algorithms, and RSA size. The default
constrained broker requires already recorded exact keys for hostA and hostB
before connecting; it never learns a key through hostA or silently accepts one.
Dynamic `KnownHostsCommand`, external `RevokedHostKeys`, and host-certificate
trust are refused as described above. If first-contact trust is
appropriate, establish it with ordinary SSH (directly or through the configured
jump path) before starting the transfer.
