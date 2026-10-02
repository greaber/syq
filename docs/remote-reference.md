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
Use a real directory, not a symlink. Transfers cannot overwrite the receiver's
SSH configuration, programs, or enrollment state. Manage that state with
`syq receiver` commands; it is not a disposable cache.

Repeating `enroll` updates the receiver to match your local build. A pending
enrollment can be retried or revoked. Revoke and enroll again to rotate its
receipt key. Revocation stops active receivers before removing their state;
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
| `--inplace` with `--as-new` | Unsupported |
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
or `auto` if none is set. `--auth-from auto` first reuses an existing approved
account connection for that exact endpoint. Without one, it tries this
machine's native SSH access. SSH keeps its normal prompts and configured
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

For SSH copies, `--auth-from @NAME` selects that receiving machine.
An existing [approved account connection](persistence-reference.md#approved-account-connections)
for the same authorizer and endpoint supplies full account access without
another prompt. Otherwise an eligible copy asks for per-copy authorization.
`--auth-from ssh` uses this machine's native SSH access and ignores account approvals.
These options choose authorization, not the destination: `--to host` names an
SSH destination, while `--to @NAME` sends files to a receiving machine.

Per-copy SSH authorization through a receiving machine does not support `--detach`, custom
`--rsh` or `--syq-path`, `--no-bootstrap`, `--pscope`, alternative `--peer-auth`
or `--coordinate-at`, or `--no-tcp-encryption`. Uploads send file data directly from
source to destination over encrypted TCP, falling back to SSH between those same
servers. `--no-tcp` selects SSH data directly. SSH workers require an exact host
key already trusted by the authorizing machine and writable
`~/.ssh/authorized_keys` on the destination. Syq temporarily adds a key that can
join only this approved copy, then removes it when the copy closes. The source
receives no laptop credentials or general SSH access. Remote path completion
can reuse existing account approval, but never requests approval itself. Without
an approved connection, `auto` and `ssh` completion use native SSH.

For downloads (`--from HOST` to this machine), approval grants read access
to the displayed source files and directory trees. `--src-non-dir` grants only
that entry; directory selectors grant their trees. An untyped source grants
the entry or tree according to its type on the source. Filters narrow the copy,
but do not narrow the approved tree. Symlinks follow the command's selection
rules; the source helper enforces them and refuses writes. File data requires
encrypted direct TCP, with no SSH fallback or relay through the laptop.
`--no-tcp` and descriptor streams are unsupported on this per-copy route.
A separately approved account connection supports SSH-only downloads.

For per-copy uploads, quoted `~` and `~/archive` select the destination account's home
directory. Use `./~/archive` for a literal directory called `~`. Avoid
`~//archive`: explicit receiving authorization keeps it under the home directory,
but automatic selection uses ordinary SSH, where it resolves to `/archive`.

## Approved account copies

A direct copy between two other servers can reuse existing
[approved account connections](persistence-reference.md#approved-account-connections)
to both endpoints. Each endpoint uses its saved authorization choice unless
`--auth-from` overrides it. `auto` selects existing approvals first;
`--auth-from @NAME` requires both connections to have been approved through
that name. The copy itself never requests full account access. Prepare it with
`syq persist connect ENDPOINT --auth-from @NAME` for each endpoint.

This route uses the default source coordinator or `--coordinate-at src`, with
`--peer-auth restricted`. It supports `--no-tcp`, helper overrides, mappings,
and receiver receipts. Custom `--rsh`, explicit `--pscope`, detached copies,
destination coordination, and other peer-auth modes keep their separate
connection requirements. `--coordinate-at local` can reuse approved access to
each endpoint and explicitly relays file data through the invoking machine.

The source's SSH server must permit remote Unix-socket forwarding. SSH fallback
also needs two simultaneous sessions on the destination's approved connection
(`sshd MaxSessions` of at least 2); direct TCP data does not need the second
session. The socket
carries control, metadata, and worker setup; payload goes directly between the
source and destination. Disabled forwarding is an error and never selects a
payload relay. Syq creates a receiver for this copy over the destination's
approved account connection; durable receiver enrollment is unnecessary.
The destination's [restricted-copy limits](#limits-and-unsupported-options)
and [signed results](#signed-results) still apply. Helpers must match the
invoking build; normal bootstrap installs them unless disabled.

## Verification

For comparisons between two servers, use `--dry-run --hash --coordinate-at local`.
This uses ordinary SSH access and supports `--results FILE` without restricted
receiver enrollment. Files are hashed on the servers; your machine receives
hashes, listings, and results. Remote setup may still cache the helper or
[install syq](install.md#automatic-installation-on-ssh-servers).
