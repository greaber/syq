# Remote-to-remote transfers

Rsync can copy between the machine you run it on and one remote host. Syq can
also copy directly between two remote hosts, `syq rsync hostA:src hostB:dst`
(natively, `syq cp --from hostA ... --to hostB ...`), and it does so without
handing hostA your ssh agent. This document describes the topology, the
default least-privilege authentication path, what it does and does not
protect, the options that fail closed under it, and the escape hatches. The
design rationale and threat model are in [Security](security.md).

## Topology

`syq rsync hostA:src hostB:dst` starts the orchestrator *on hostA*, which then pushes
to hostB with N connections, so data flows A → B directly. Matching helpers
are installed automatically on both hosts. Progress and `-v` output are
streamed back. If hostA can't reach hostB, `--relay` keeps the orchestrator
here and routes every byte A → you → B — always works, at half the bandwidth.
`syq rsync hostA:src hostA:dst` (same host and user on both ends) simply runs a
local copy on hostA and disables agent forwarding.

## The default path: enrolled receiver plus constrained broker

With implicit OpenSSH, the default combines a pre-enrolled forced receiver on
hostB with a temporary local agent broker. The first transfer to a destination
parent generates an Ed25519 enrollment key locally, uploads the exact running
syq as `~/.local/libexec/syq-receiver` on hostB, and appends one managed
`restrict,command=...` line to hostB's `authorized_keys`. The private enrollment
key stays under `~/.local/state/syq/restricted/` on the local machine and is
never copied to hostA. HostB keeps only its forced public key, SSHSIG verifier
policy, and replay state under `~/.local/share/syq/restricted/`. Before
publishing the forced key, syq verifies that the installed receiver is a
regular executable and that it and every path ancestor are trusted-owner- or
root-owned, non-writable by other users, and free of non-owner ACL grants.

Enrollment first tries local→hostB directly. If that network path is
unavailable, it retries through hostA with OpenSSH `ProxyJump`; hostA gets only
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
validity interval, and a fresh one-time nonce. The temporary broker advertises
only that enrollment key to hostA and releases its signature only after
validating this path:

```text
trusted hostA session -> configured-user@trusted-hostB session
```

The broker verifies OpenSSH session-bind signatures for both hosts and strictly checks
the final host-bound authentication request's session ID, destination login
user, host key, selected credential, and signature algorithm. Key addition,
removal, raw or legacy signing, unknown extensions, and extra forwarding hops
are refused. The A → B client is forced to use host-bound public-key
authentication. The forced receiver verifies and durably claims the signed
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
receiver-observed inode fingerprint; atomic publication fails if that object
changes instead of carrying its mode onto a replacement. Hash requests must use
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
A compromised hostA can omit source files, alter their contents, lie about
source metadata, or stop the transfer. It still cannot escape the signed
destination scopes or independently authenticate to hostB with the enrollment
key.

## Options that fail closed under the restricted path

The command-restricted path requires atomic staged publication and encrypted
TCP data connections. `--inplace`, `--no-tcp`, `--tcp-plain`,
`--tcp-congestion`, `--update`, `--existing`, `--ignore-existing`, native
`--*-new`/`--*-existing`,
`--ignore`/`--ignore-from`, `--files-from`, `--mapping`, `--min-size`,
`--syq-path`, and `--no-bootstrap` currently fail closed because
the receiver cannot enforce those semantics independently of hostA.
`--max-size` is enforced as a signed per-file limit, but is refused together
with deletion because filtered source files could otherwise make hostA's
deletion plan ambiguous. Explicit `-j` values above 64 are also refused; auto
tuning may use up to that signed ceiling.

`--dry-run` and `--verify-only` are cryptographically read-only: the signed
grant marks them as such and the receiver rejects every mutation even if hostA
sends one. They use an existing enrollment but do not install one; run
`syq enroll` first when previewing or verifying a new destination.
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

Use `syq enroll [USER@]HOST:DEST [--via [USER@]HOST]` to pre-enroll,
`syq enrollments` to list local enrollments, and `syq revoke ID [--via ...]` to
remove the forced key and both sides' per-enrollment state. Before changing
hostB, syq durably records a pending enrollment and its private key locally. If
the installation response is lost, the next enrollment of the same endpoint
and destination retries the same ID safely; `syq enrollments` labels that state
`pending`, and `syq revoke` can remove either pending or active state. Running
`syq enroll` again for an active destination also refreshes the installed
receiver to the exact local syq binary. Revocation leaves that shared binary
because other enrollments may use it. It prevents new receiver sessions. A
session that already claimed its signed request can finish an operation already
in progress; later protocol requests are rejected once the signed execution
deadline expires rather than forcibly interrupting a filesystem syscall.

## Broker-only mode

`--agent-broker-only` explicitly selects the authentication-only compromise.
It installs no receiver. HostA may list a sanitized snapshot of the ambient
agent's supported public identities with comments removed, but the broker signs
only for the exact hostA→user@hostB path above. Key changes, raw or legacy
signing, unknown extensions, and extra hops are refused; successful ambient
signatures are verified before release.

In broker-only mode, use OpenSSH 10.5 or newer for the ambient agent if relying
on its existing per-key destination constraints as an additional layer.
OpenSSH 10.5 fixed an
interaction in which a locked agent refused session-bind requests, allowing
operations intended to be local—including use of destination-restricted
keys—to occur remotely ([OpenSSH 10.5 release notes](https://www.openssh.com/txt/release-10.5);
CVE-2026-73281). Syq cannot query an agent's version and does not count that
extra layer as part of its own mandatory path restriction.

In broker-only mode, private keys remain in the original agent, so
hardware-backed, PIV/OpenPGP-agent, and desktop-agent identities continue to handle their own
touch/PIN/approval behavior. For a user certificate selected by hostB's local
`CertificateFile`, syq exposes only that exact certificate in place of its
matching raw agent identity, validates the exact certificate-bearing host-bound
request, and translates only the agent request's outer credential back to the
matching raw key. This supports the common arrangement where a YubiKey or other
agent lists the private key while a centrally managed certificate is a local
file. When no `CertificateFile` is explicitly configured, syq also follows
OpenSSH's implicit `<IdentityFile>-cert.pub` convention. An OpenSSH agent may
itself reject certificate translation when the raw key has
`ssh-add -h` destination constraints but the certificate was not associated
with the agent; that combination fails closed. Loading the certificate into the
agent avoids translation. The broker socket and every open channel are closed
when the attached transfer ends; SIGINT and SIGTERM also remove its private
socket directory. Stalled broker and ambient-agent operations
time out after two minutes, long enough for ordinary hardware-token approval
while preventing idle clients from holding worker slots indefinitely.

Broker-only mode restricts *where and as whom* hostA may authenticate; stock
OpenSSH does not bind the subsequent command. A compromised hostA still receives the
authority of that destination account for the transfer's lifetime. Command or
filesystem restrictions require destination-side policy such as a forced syq
receiver. This is not a signed grant: it adds no timestamp, expiry, or replay
cache beyond the live SSH sessions and the broker socket's lifetime.

## Requirements and host identity

The constrained path requires OpenSSH 8.9 or newer session-bind and host-bound
authentication support on the local machine, hostA, and hostB; a local
`SSH_AUTH_SOCK`; and exact plain host keys for both hosts in the effective local
`known_hosts` files. Host-certificate/CA-only trust is refused until syq can
validate certificate principals and validity as strictly as OpenSSH. Static
`HostKeyAlgorithms` and `RequiredRSASize` policy is enforced. A configured
`KnownHostsCommand` or `RevokedHostKeys` KRL is refused because the broker does
not yet reproduce those dynamic or external revocation checks. Local
`CertificateFile` and implicit `IdentityFile` certificate expansion supports the
ordinary OpenSSH percent tokens except `%C`; named-user tildes are also refused
rather than guessed. Credential and host-key algorithms that syq's SSH library
cannot cryptographically verify are removed or refused rather than failing only
after a signing request. OpenSSH's `ssh -G` output does not preserve quoting for
custom known-hosts filenames. Syq uses OpenSSH's debug provenance to inspect the
configuration files OpenSSH actually read for the host. It accepts the compiled
default list only when none of those files contains the corresponding
known-hosts directive; an explicitly configured value that renders exactly like
the defaults is still treated as configured. Otherwise syq accepts one absolute
whitespace-free configured file per
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

## Escape hatches and explicit remote shells

Pass `--no-forward-agent` to give hostA no agent at all; hostA must then have
its own credentials for hostB, and its own `IdentityAgent` configuration is
left intact. `--unrestricted-agent-forwarding` is a
conspicuous compatibility escape hatch that exposes the complete ambient agent
to hostA for the attached transfer without imposing the constrained path's
host-bound authentication requirement. With an explicit `-e/--rsh`, syq
creates no broker and adds neither `-A` nor `-a`, so that command is the
complete agent policy; `--no-forward-agent`, `--agent-broker-only`, and the
unrestricted escape hatch therefore conflict with `-e`. `--relay` also avoids exposing authentication to
hostA, at the cost of routing file data through this machine.

SYQ uses the user's SSH configuration to resolve the login user, host-key name,
port, static known-hosts files, host-key algorithms, RSA size, and configured or
implicit user certificates. The default constrained broker requires already
recorded exact keys for hostA and hostB before connecting; it never learns a key
through hostA or silently accepts one. Dynamic `KnownHostsCommand`, external
`RevokedHostKeys`, and host-certificate trust are currently refused as described
above. If first-contact trust is appropriate, establish it with ordinary SSH
(directly or through the configured jump path) before starting the transfer.
An explicit `-e 'ssh -o StrictHostKeyChecking=accept-new'` bypasses the broker
and leaves that policy to the supplied command.

## Detached transfers

Add `--detach --no-forward-agent` to let a remote-to-remote transfer outlive
the ssh session that launched it: syq starts it on hostA, returns, and writes
progress to a log on hostA. HostA needs its own hostB credential because a
temporary local broker cannot survive detachment. An explicit `--rsh` may
provide another persistent authentication policy. Reattach with
`syq --follow hostA:LOG` to stream that progress.
An explicit `--checkpoint` path belongs to the machine running the
orchestrator: normally the invoking machine, but hostA for a direct or detached
remote-to-remote copy (`--relay` keeps it local).

