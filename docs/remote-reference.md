# Remote copy reference

For setup and examples, start with [Copy between servers](remote-to-remote.md).
This page covers copies from hostA (the source) to hostB (the destination).
See [`syq cp`](commands/cp.md) and [`syq receiver`](commands/receiver.md) for
the option lists.

## SSH configurations

Host-certificate-only trust, `KnownHostsCommand`, and `RevokedHostKeys` are
unsupported by the broker. Custom known-hosts paths must be unambiguous:
one absolute, whitespace-free filename per configured user/global directive.
The default known-hosts file list works. Syq reports unsupported configurations
instead of relaxing host verification.

Your local SSH configuration selects hostB's login, address, port, and trusted
host keys. HostA's SSH configuration does not override those choices.

## Enrollment

Enrollment needs normal command authority on the destination during setup.
The receiver does not run as root or with root's capabilities, so enroll an
ordinary account.
Use a real directory, not a symlink. Transfers cannot overwrite the receiver's
SSH configuration, programs, or enrollment state. Manage that state with
`syq receiver` commands; it is not a disposable cache.

New enrollments match the SSH key that authenticated setup. Ed25519 stays
Ed25519; RSA uses at least 3,072 bits and at least the login key's size.
Unencrypted ECDSA keeps its curve. FIDO (`*-sk`) logins create a separate
hardware-backed key with the same effective touch and PIN requirements;
creating and checking that key can require touching the device. Syq checks
that the destination's selected SSH agent can sign before installing the key.
PIN-protected keys need a working `SSH_ASKPASS` program in that agent's
environment; the agent cannot use syq's terminal for its PIN prompt. Enrollment
stops before installation if the signing check fails.

For a passphrase-protected Ed25519 or RSA login, the receiver key is encrypted
using a secret derived through the login key's SSH agent. There is no new
passphrase. If the login key is not loaded, `ssh-add` asks for its usual
passphrase. Syq uses the agent selected by the destination's `IdentityAgent`
setting, or `SSH_AUTH_SOCK` when that setting is absent. Losing that login key requires revoking and enrolling again through
another login. Revocation itself does not need the receiver key unlocked.

Automatic matching needs the login's local OpenSSH private-key file or FIDO
handle, readable only by its owner (mode 0400 or 0600). Passphrase-protected ECDSA, encrypted FIDO handles, SSH certificates,
password or multi-factor logins, and agent-only identities (including
PIV/OpenPGP keys) are unsupported. For FIDO, the login key must have one matching
entry in `~/.ssh/authorized_keys` so syq can read its server policy. Syq reports
an error when it cannot preserve the key's protection.

Repeating `enroll` updates the receiver to match your local build. A pending
enrollment can be retried or revoked. Existing keys keep their protection;
revoke and enroll again to adopt matching protection or rotate either key. Revocation stops active receivers before removing their state;
see [access management](remote-to-remote.md#first-copy-and-access-management)
for interruption and retry behavior.

Stop active copies before upgrading: replacing the executable does not update
running receivers. Repeat `syq receiver enroll hostB:/destination` afterward
to refresh the installed receiver. Compatible enrollment keys and replay records
are preserved. Different client builds cannot share one installed receiver
concurrently; each needs a matching receiver.

An incompatible enrollment requires fresh setup, which needs ordinary SSH
access. Eligible copies install it automatically, or you can use `enroll`.
Incompatible old enrollments are not listed or removed by the new build;
they require manual cleanup on both machines.

Enrollment detects the destination platform and installs a matching executable.
Source builds require compatible platforms; `--syq-path` does not select the
restricted receiver. See [Developing syq](https://github.com/greaber/syq/blob/master/CONTRIBUTING.md#direct-server-to-server-copies)
for testing source builds.

## Limits and unsupported options

Default limits are 100 million entries and 8 TiB of file data. Override them
for one transfer with `--receiver-max-entries N` and
`--receiver-max-bytes SIZE`. Values can raise or lower the defaults within the
allowed ranges. The transfer must start within 24 hours of authorization and
finish within seven days of authorization. New authorizations allow up to
128 worker connections, including for named destinations; a smaller worker
setting or resource limit lowers that allowance. Existing authorizations keep
their original limits.

| Option or combination | Restricted receiver |
|---|---|
| `--no-tcp` | Use SSH workers directly from source to destination |
| `--tcp-congestion` | The receiver enforces the algorithm authorized for TCP |
| `--no-tcp-encryption` | Unsupported; data connections must be encrypted |
| `--mapping` | Listed destinations and necessary parent creation are authorized |
| Fixed `workers` above 128 | Unsupported |
| `--inplace` with `--if-exists=keep`, `--only-existing` or `--as-new` | Unsupported |
| `--detach` | Unsupported; the local broker must remain attached |
| Native `rm` | Unsupported; use a normal SSH login |

Restricted copies use encrypted TCP when reachable and otherwise use SSH
workers from the source to the destination. Both transports share the same
copy authorization, limits, revocation, and signed receipt. A failed direct
connection never selects a relay through your machine; choose
`--coordinate-at local` explicitly to send data through it.

## Signed results

The destination signs a receipt and your machine verifies it before reporting
results. Use `-v` for totals or `--results FILE` for
[automation](automation.md). These results arrive after verification, rather
than as live per-file progress. For `--dry-run --results`, use
`--coordinate-at local` to get the preview stream.

`--receiver-receipt hashes` adds BLAKE3 hashes of affected regular files.
Receipts allow up to four million records and 512 MiB of plaintext. Reaching
a cap stops further changes and reports an incomplete outcome.

A receipt does not prove that the source supplied every intended file or the
right contents. See [A compromised source server](security.md#a-compromised-source-server).

## Other authentication modes

| Option | Authority available to the coordinating server |
|---|---|
| `--peer-auth own-credentials` | Credentials already on that server |
| `--peer-auth broker` | Your full destination-account authority, limited to that host and user |
| `--peer-auth full-agent` | Ordinary, unrestricted agent forwarding |
| `--rsh COMMAND` | Whatever your supplied SSH command permits |

With `--peer-auth broker`, syq uses the coordinating host's configured
`IdentityAgent` for the outer SSH connection and the peer host's configured
agent for forwarded authentication. The two hosts can use separate agents.

Persistence can reuse an eligible native SSH connection from the invoking
machine to the coordinating server. Connections forwarding a constrained or
full SSH agent remain attached to the individual copy. Selecting `--pscope`
changes only local persistence; it does not pass that local path to another
server or change the file-data route.

The authentication broker allows 129 simultaneous clients by default. An
explicit worker count or ceiling changes this to that count plus one control
connection; restricted copies remain capped at 129 clients.

To make hostB pull from hostA using credentials already on hostB:

```sh
syq cp --coordinate-at dst --peer-auth own-credentials --from hostA data --to hostB --into /archive
```

Destination-coordinated remote-to-remote copies require one of these
alternatives to the default authentication. A copy started in a server shell
can instead request the source-read authorization described below.

## Detached copies

`--detach` leaves the copy running after your command exits. It requires
`--peer-auth own-credentials` or an explicit `--rsh` policy, so the coordinating
server can authenticate independently. It cannot use the restricted receiver
or `--results`.

Save the reported remote log location. The log is not a signed receipt.
If printing the location fails, the command reports an error but the job may
still be running. The coordinating server needs `/bin/kill` and either
`setsid` or `perl`.

## Authorization selection

For `syq cp` between this machine and one SSH server, omitted `--auth-from`
uses your [saved authorization choice](persistence-reference.md#authorization-defaults),
or `auto` if none is set. `--auth-from auto` tries this machine's native SSH
access, regardless of existing approved account connections.
SSH keeps its normal prompts and configured
timeouts. If SSH
reports rejected credentials, a host-key verification failure, an unresolved
hostname, or a refused connection, syq tries live receiving machines in
alphabetical order, allowing up to two seconds for each reply. The receiving
machine uses its own SSH configuration and trusted host keys. Timeouts,
temporary DNS failures, and unrecognized SSH errors end the attempt without
trying a receiving machine.
Offline or unsupported receiving connections are skipped. With none available,
the SSH error is reported. Unsupported copy options use only the source
machine's SSH access. Helper setup and copy errors do not trigger another
authorization attempt. Once approval is requested, refusal or failure ends
the attempt. Elapsed time includes authorization setup; handoffs to older helpers
may omit time spent before the handoff.

For object-storage copies and removal, explicit `--auth-from @NAME` uses
[storage authorization](object-storage.md#authorize-from-your-laptop).

For SSH copies, `--auth-from @NAME` selects that receiving machine; an ordinary
SSH endpoint selects an [SSH authorization provider](receive.md#use-an-ssh-authorization-provider).
An existing [approved account connection](persistence-reference.md#approved-account-connections)
for the same authorizer and endpoint supplies full account access without
another prompt. Otherwise an ordinary copy requests account access from the
provider. See [account permissions](persistence-reference.md#account-permissions)
for Allow and Remember. `--receiver-receipt` applies only to direct copies
between two remote endpoints; it does not select per-copy authorization for a
copy between this machine and one SSH server.
`--auth-from ssh` uses this machine's native SSH access and ignores account approvals.
These options choose authorization, not the destination: `--to host` names an
SSH destination, while `--to @NAME` sends files to a receiving machine.

Per-copy SSH authorization through a receiving machine does not support a root
login on the destination, `--detach`, custom
`--rsh` or `--syq-path`, `--no-bootstrap`, alternative `--peer-auth`
or `--coordinate-at`, or `--no-tcp-encryption`. The authorizing machine's copy
limits apply, including its `--max-delete` for pruning. Uploads send file data directly from
source to destination over encrypted TCP, falling back to SSH between those same
servers. `--no-tcp` selects SSH data directly. SSH workers require an exact host
key already trusted by the authorizing machine and writable
`~/.ssh/authorized_keys` on the destination. Syq temporarily adds a key that can
join only this approved copy, then removes it when the copy closes. The source
receives no laptop credentials or general SSH access. Remote path completion
can reuse existing account approval from the selected authorizer, but never
requests approval itself. `auto` and `ssh` completion use native SSH.

For restricted per-copy downloads (`--from HOST` to this machine), approval grants read access
to the displayed source files and directory trees. `--src-non-dir` grants only
that entry; directory selectors grant their trees. An untyped source grants
the entry or tree according to its type on the source. Filters narrow the copy,
but do not narrow the approved tree. Symlinks follow the command's selection
rules; the source helper enforces them and refuses writes. File data requires
encrypted direct TCP, with no SSH fallback or relay through the laptop.
`--no-tcp` and descriptor streams are unsupported on this per-copy route.
Account approval supports SSH-only downloads without this TCP requirement.

For per-copy uploads, quoted `~` and `~/archive` select the destination account's home
directory. Use `./~/archive` for a literal directory called `~`. Avoid
`~//archive`: explicit receiving authorization keeps it under the home directory,
but automatic selection uses ordinary SSH, where it resolves to `/archive`.

## Approved account copies

A direct copy between two other servers can request or reuse
[approved account connections](persistence-reference.md#approved-account-connections)
to both endpoints. Each endpoint uses its saved authorization choice unless
`--auth-from` overrides it. Both endpoints must select an authorization provider
for this route; `auto` and `ssh` use native authentication regardless of existing
approvals. `--auth-from @NAME` or `--auth-from PROVIDER_HOST` requests access to
both accounts through that provider as needed. Each prompt grants the named
account's authority. To prepare connections in advance, use
`syq persist connect ENDPOINT --auth-from PROVIDER`.

This route uses the default source coordinator or `--coordinate-at src`, with
`--peer-auth restricted`. It supports `--no-tcp`, helper overrides, mappings,
and receiver receipts. `--pscope` selects approved connections and authorization
choices in that local domain. Custom `--rsh`, detached copies, destination
coordination, and other peer-auth modes keep their separate
connection requirements. `--coordinate-at local` can reuse approved access to
each endpoint and explicitly relays file data through the invoking machine.

The source's SSH server must permit remote Unix-socket forwarding. A TCP copy
needs one free SSH session on each connection; SSH worker setup needs a second
free session on the destination's connection. Prepared helpers stay ready for
completion when sessions are available. If SSH refuses startup, syq releases
idle helpers on that connection and retries once. Other active operations keep
their sessions and can exhaust the server's limit. The forwarded
socket carries control, metadata, and worker setup; payload goes directly between
the source and destination. The invoking machine's `ProxyJump` route can
reach the control endpoints, but does not provide a data route between the
servers. Data workers still need to reach the peer directly. Disabled forwarding is an error and never selects a
payload relay. Syq creates a receiver for this copy over the destination's
approved account connection, which must not log in as root; durable receiver
enrollment is unnecessary.
The destination's [restricted-copy limits](#limits-and-unsupported-options)
and [signed results](#signed-results) still apply. Helpers must match the
invoking build; normal bootstrap installs them unless disabled.

## Verification

For comparisons between two servers, use `--dry-run --hash --coordinate-at local`.
This uses ordinary SSH access and supports `--results FILE` without restricted
receiver enrollment. Files are hashed on the servers; your machine receives
hashes, listings, and results. Remote setup may still cache the helper or
[install syq](install.md#automatic-installation-on-ssh-servers).
