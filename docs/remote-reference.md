# Remote copy reference

For setup and examples, start with [Copy between servers](remote-to-remote.md).
This page covers copies from hostA (the source) to hostB (the destination).
See [`syq cp`](commands/cp.md) and [`syq receiver`](commands/receiver.md) for
the option lists.

## SSH configurations

Host-certificate-only trust, `KnownHostsCommand`, and `RevokedHostKeys` are
unsupported by the default restricted path and the authentication broker.
Custom known-hosts paths must be unambiguous:
one absolute, whitespace-free filename per configured user/global directive.
The default known-hosts file list works. Syq reports unsupported configurations
instead of relaxing host verification.

Your local SSH configuration selects hostB's login, address, port, and trusted
host keys. HostA's SSH configuration does not override those choices.

## Enrollment

Restricted copying is set up once for each server account you copy to from
each of your machines. Setup needs an ordinary SSH login to the account with
an SSH key. The receiver does not run as root or with root's capabilities, so
enroll an ordinary account. The server needs OpenSSH 7.2 or newer and a
writable `~/.ssh/authorized_keys`; syq checks both before installing anything.

Setup installs three things on the server:

- One line in `~/.ssh/authorized_keys`. Its key, the entry key, can only start
  syq's receiver. The line's comment names the login key the receiver trusts:
  `syq-enrollment:ID signer TYPE KEY`.
- The receiver, at `~/.local/lib/syq/RELEASE/PLATFORM/syq`.
- Private state in `~/.local/share/syq/enrollments/ID`: the login key the
  receiver trusts, the record of authorizations already used, and the
  server's key for signing its reports.

Your machine keeps the entry key and its own record in
`~/.local/state/syq/enrollments/ID`. Manage that state with `syq receiver`
commands; it is not a disposable cache.

Copies cannot write the receiver's protected paths: the account's
`~/.ssh`, syq's stored programs, enrollment state on either side, and syq's
receiving state, such as `~/.config/syq` and its runtime directory
`$XDG_RUNTIME_DIR/syq-persist-UID`. Without `XDG_RUNTIME_DIR`, the runtime
directory is `/tmp/syq-persist-UID` on macOS and `$TMPDIR/syq-persist-UID`
elsewhere, which is also in `/tmp` when `TMPDIR` is unset. A copy into one of
them is refused, and so is one that copies a directory's contents into, or
deletes in, a directory that holds one, such as your home directory, or
`/tmp` when it holds the runtime directory, because it could change syq's own
files there. Copy into a subdirectory instead. Copying named files or
directories into such a directory is fine.

### Which key signs

The key you log in with during setup signs each copy's authorization, on your
machine. Syq signs through your SSH agent (the one your SSH configuration's
`IdentityAgent` selects for the server, else `SSH_AUTH_SOCK`), or reads the
key's file when it is not passphrase-protected. Syq never asks for a
passphrase: load passphrase-protected keys, FIDO keys, and PKCS#11 or PIV keys
into your agent. Before installing anything, setup checks that the key can
sign. A key added with `ssh-add -h`, which signs only logins, is refused, and
so is an RSA key with fewer than 2048 or more than 16384 bits.

- **FIDO keys** need one touch for each copy. A copy that sets up or refreshes
  restricted copying needs about three: for the login, for the check that the
  key can sign, and for the copy itself. The receiver requires what your login
  requires: a touch unless the server's `authorized_keys` line for your key
  says `no-touch-required`, and a PIN when that line says `verify-required` or
  the key itself always asks for one. For a certificate login, the
  certificate's options count as sshd counts them: the touch is skipped only
  when both the certificate and its authority's line allow it, and a PIN is
  needed when either asks for one. A PIN needs an `SSH_ASKPASS` program the
  agent can run; the agent cannot use syq's terminal.
- **Certificates:** the certificate's key signs, and the receiver stops
  accepting copies when the certificate expires. The next copy after that
  logs in again and records the new certificate's expiry. SSH does not report
  which of several certificates for one key it logged in with, so syq looks at
  the certificates for that key in your agent and beside its key file that are
  valid now, preferring those that name your login as a principal. If those
  differ in expiry or in their touch and PIN options, setup stops and asks you
  to keep only the one you log in with.
- **Other logins** cannot set up restricted copying: passwords,
  keyboard-interactive, Kerberos, host-based, and logins that need a second
  factor. A key alone would drop the second factor. Use
  [account access](persistence-reference.md#approved-account-connections) with `--auth-from @NAME`
  instead.

### Changing keys and updating syq

When the key syq recorded can no longer sign, for example because you now log
in with a new key, the next copy logs in again and trusts your current key
instead. Only the trusted key changes; the entry key stays, so copies already
running continue. The enrollment outlives removing or revoking your login key
on the server. To end it, run `syq receiver revoke ID`, or remove every
`authorized_keys` line that contains the key; syq's line names it in its
comment. `syq receiver list` shows the fingerprint of the key each enrollment
trusts.

Whether the receiver accepts a grant depends only on the login key's
signature, its touch and PIN policy, and a certificate's expiry. Options such
as `from=` or `expiry-time=` on your key's `authorized_keys` line, a
certificate's other critical options, such as `source-address` or
`force-command`, and revoking a certificate or its authority on the server do
not stop a grant your key signs. Revoke the enrollment to stop them.

After you change syq builds, the next copy logs in once to install the
matching receiver and rewrite syq's line. An SSH connection opened before that
refresh cannot start a new copy; copies already running finish. Releases stay
in `~/.local/lib/syq` until you delete them. Delete a release's directory only
when no syq line in `authorized_keys` names it.

If the server loses an enrollment's state, its receiver refuses every copy.
`syq receiver enroll` then sets up a new enrollment in its place and removes
the old line.

### Enrollments from older versions

Syq 0.4.0 to 0.7.1 made one enrollment per destination directory. This
version does not use, list, or remove them, and an older syq can keep copying
through them until you remove them. Revoke them with the older version before
upgrading, or remove them by hand: on the server, delete the
`authorized_keys` lines whose command runs `~/.local/libexec/syq-receiver`,
then `~/.local/share/syq/restricted` and `~/.local/libexec/syq-receiver`; on
your machine, delete `~/.local/state/syq/restricted`.

Enrollment detects the destination platform and installs a matching executable.
Source builds require compatible platforms; `--syq-path` does not select the
restricted receiver. See [Developing syq](https://github.com/greaber/syq/blob/master/CONTRIBUTING.md#direct-server-to-server-copies)
for testing source builds.

## Limits and unsupported options

Default limits are 100 million entries and 8 TiB of file data. Override them
for one transfer with `--receiver-max-entries N` and
`--receiver-max-bytes SIZE`. Values can raise or lower the defaults within the
allowed ranges. Entries count the changes the destination makes: each file it
writes, each directory, link or special file it creates, each metadata change
and each deletion. Looking at what is already there does not count, and
neither does a change that fails. The transfer must start within 24 hours of
authorization and finish within seven days of authorization. New
authorizations allow up to 128 worker connections, including for named
destinations; a smaller `--resource-limits workers` ceiling lowers that
allowance, while a worker count fixed with `--performance-tuning` does not.
Existing authorizations keep their original limits.

| Option or combination | Restricted receiver |
|---|---|
| `--no-tcp` | Use SSH workers directly from source to destination |
| `--tcp-congestion` | The receiver enforces the algorithm authorized for TCP |
| `--no-tcp-encryption` | Unsupported; data connections must be encrypted |
| `--mapping` | Listed destinations and necessary parent creation are authorized |
| Fixed `workers` above 128 | Unsupported |
| `--follow-dst` with `--into` | The receiver follows a destination symlink to the directory it leads to inside the directory the destination is in; not with `--widen-dirs all`, and not for [named destinations](persistence-reference.md#copy-limits) |
| `--widen-dirs` | Approved as part of the copy; `all` widens the directory the copy goes into and those on the way to it, but nothing above the directory the destination is in |
| `--detach` | Unsupported; the local authorization process must remain attached |
| Native `rm` | Unsupported; use a normal SSH login |

Restricted copies use encrypted TCP when reachable and otherwise use SSH
workers from the source to the destination. Both transports share the same
copy authorization, limits, revocation, and results. A failed direct
connection never selects a relay through your machine; choose
`--coordinate-at local` explicitly to send data through it.

<a id="signed-results"></a>

## Results from the destination

The destination reports each change it makes, refuses, or fails as the copy
runs. Your machine checks that the reports come from the destination and that
the source, which passes them on, left none out and added none. The source
leaves out its own report of each failure the destination reports, and reports
what it could not read as it happens. When that leaves a file unfinished on the
destination, the source's error explains the destination's report instead of
counting the failure again. A refusal or a failed change on the destination
decides the outcome even if the source reports success, and reports cut short
fail the copy. Use `-v` for the destination's totals or `--results FILE` for
[automation](automation.md); `--dry-run --results` previews the copy.

The destination's reports do not prove that the source supplied every intended
file or the right contents. See [A compromised source server](security.md#a-compromised-source-server).

## Other authentication modes

| Option | Authority available to the coordinating server |
|---|---|
| `--peer-auth own-credentials` | Credentials already on that server |
| `--peer-auth broker` | Your full destination-account authority, limited to that host and user |
| `--peer-auth full-agent` | Ordinary, unrestricted agent forwarding |
| `--rsh COMMAND` | Whatever your supplied SSH command permits |

`--peer-auth broker` requires OpenSSH 8.9 or newer on the invoking machine,
the coordinating client, and the peer SSH server. It uses the coordinating host's configured
`IdentityAgent` for the outer SSH connection and the peer host's configured
agent for forwarded authentication. The two hosts can use separate agents.

Persistence can reuse an eligible native SSH connection from the invoking
machine to the coordinating server. Connections forwarding a constrained or
full SSH agent remain attached to the individual copy. Selecting `--pscope`
changes only local persistence; it does not pass that local path to another
server or change the file-data route.

The authentication broker allows 129 simultaneous clients by default. An
explicit worker count or ceiling changes this to that count plus one control
connection.

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

Save the reported remote log location. If printing the location fails, the command reports an error but the job may
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
for Allow and Remember.
`--auth-from ssh` uses this machine's native SSH access and ignores account approvals.
These options choose authorization, not the destination: `--to host` names an
SSH destination, while `--to @NAME` sends files to a receiving machine.

Per-copy SSH authorization through a receiving machine does not support a root
login on the destination, `--detach`, custom
`--rsh` or `--syq-path`, `--no-bootstrap`, alternative `--peer-auth`
or `--coordinate-at`, or `--no-tcp-encryption`. The authorizing
machine's copy limits apply, including its `--max-delete` and `--max-entries`
for pruning. Uploads send file data directly from
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
and `--results`. `--pscope` selects approved connections and authorization
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
and [results from the destination](#results-from-the-destination) still apply. Helpers must match the
invoking build; normal bootstrap installs them unless disabled.

## Verification

For comparisons between two servers, use `--dry-run --hash --coordinate-at local`.
This uses ordinary SSH access and supports `--results FILE` without restricted
receiver enrollment. Files are hashed on the servers; your machine receives
hashes, listings, and results. Remote setup may still cache the helper or
[install syq](install.md#automatic-installation-on-ssh-servers).
