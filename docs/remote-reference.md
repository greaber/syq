# Remote copy reference

For setup and examples, start with [Copy between servers](remote-to-remote.md).
This page covers copies from hostA (the source) to hostB (the destination).
See [`syq cp`](commands/cp.md) and [`syq receiver`](commands/receiver.md) for
the option lists.

## SSH configurations

Your local SSH configuration selects hostB's login, address, and port. With an
enrollment, hostA connects to hostB with its own SSH configuration, looked up
for the address your laptop connects to rather than the name you typed, and
also accepts the host keys your laptop's known_hosts lists for hostB. See
[how hostA checks hostB's key](security.md#how-hosta-checks-hostbs-key).

The authentication broker (`--peer-auth broker`) needs your laptop to trust
both servers through exact plain host keys in known_hosts. It does not support
host certificates alone, `KnownHostsCommand`, or `RevokedHostKeys`. Syq
reports an unsupported configuration instead of relaxing host verification.

## Enrollment

Restricted copying is set up once for each server account you copy to from
each of your machines. Setup needs an ordinary SSH login to the account with
an SSH key. The receiver does not run as root or with root's capabilities, so
enroll an ordinary account. The server needs OpenSSH 7.2 or newer and a
writable `~/.ssh/authorized_keys`; syq checks both before installing anything.

Setup adds one line to the server's `~/.ssh/authorized_keys`. Its key, the
entry key, can only start syq's receiver, and its comment,
`syq-enrollment:ID signer TYPE KEY`, names the login key the receiver trusts.
Setup also installs this build of syq at
`~/.local/lib/syq/RELEASE/PLATFORM/syq` and keeps private state in
`~/.local/share/syq/enrollments/ID`. Your machine keeps the entry key and its
own record in `~/.local/state/syq/enrollments/ID`. Manage this state with
`syq receiver` commands; it is not a disposable cache.

Copies cannot write the receiver's protected paths: the account's `~/.ssh`,
syq's stored programs (including all of `~/.local/libexec`), enrollment state
on either side, and syq's receiving state, such as `~/.config/syq` and its
runtime directory, `$XDG_RUNTIME_DIR/syq-persist-UID` or, without
`XDG_RUNTIME_DIR`, `syq-persist-UID` in the temporary directory. A copy into
one of them is refused, and so is one that copies a directory's contents into,
or deletes in, a directory that holds one, such as your home directory, or
`/tmp` when it holds the runtime directory. Copy into a subdirectory instead.
Copying named files or directories into such a directory is fine.

### Which key signs

The key you log in with during setup signs each copy's authorization, on your
machine, through your SSH agent (the one your SSH configuration's
`IdentityAgent` selects for the server, else `SSH_AUTH_SOCK`) or from a key
file without a passphrase. Syq never asks for a passphrase, so load
passphrase-protected, FIDO, and PKCS#11 or PIV keys into your agent. Setup
refuses a key added with `ssh-add -h`, which can sign only logins.

- **FIDO keys** need one touch for each copy, and about three for a copy that
  sets up or refreshes restricted copying. The receiver requires a touch and
  a PIN whenever your login would. A PIN needs an `SSH_ASKPASS` program the
  agent can run.
- **Certificates:** the receiver stops accepting copies when the certificate
  expires; the next copy logs in again and records the new certificate.
- **Other logins** cannot set up restricted copying: passwords,
  keyboard-interactive, Kerberos, host-based, and logins that need a second
  factor. Use [account access](persistence-reference.md#account-access) with
  `--auth-from @NAME` instead.

### Changing keys and updating syq

When the key syq recorded can no longer sign, for example because you now log
in with a new key, the next copy logs in again and trusts your current key
instead; copies already running continue. `syq receiver list` shows the
fingerprint of the key each enrollment trusts.

The receiver decides whether to accept a copy only from the login key's
signature, its touch and PIN policy, and a certificate's expiry. Options such
as `from=` or `expiry-time=` on your key's `authorized_keys` line, a
certificate's other critical options, and removing or revoking the key, the
certificate, or its authority on the server do not stop a copy your key signs.
To end an enrollment, run `syq receiver revoke ID`, or remove every
`authorized_keys` line that contains the key; syq's line names it in its
comment.

After you change syq builds, the next copy logs in once to install the
matching receiver.

### Enrollments from older versions

Syq 0.7.1 and earlier made one enrollment per destination directory. This
version does not use, list, or revoke them, and sets up a new enrollment on
the first copy; until you remove the old ones, an older syq can keep copying
through them. Revoke them with the older version before upgrading, or delete
them by hand:

- On the server, delete each line in `~/.ssh/authorized_keys` whose command
  runs `~/.local/libexec/syq-receiver`, written with your home directory's
  full path (keep those that run syq from `~/.local/lib/syq`). Then delete the
  directory `~/.local/share/syq/restricted` and the file
  `~/.local/libexec/syq-receiver`.
- On your machine, delete the directory `~/.local/state/syq/restricted`.

## Limits and unsupported options

Default limits are 100 million entries and 8 TiB of file data. Override them
for one transfer with `--receiver-max-entries N` and
`--receiver-max-bytes SIZE`, within the allowed ranges. Entries count the
changes the destination makes: each file it writes, each directory, link or
special file it creates, each metadata change and each deletion. Looking at
what is already there does not count, and neither does a change that fails.
The transfer must start within 24 hours of authorization and finish within
seven days of it.

| Option or combination | Restricted receiver |
|---|---|
| `--no-tcp` | Use SSH workers directly from source to destination |
| `--tcp-congestion` | The receiver enforces the algorithm authorized for TCP |
| `--no-tcp-encryption` | Unsupported; data connections must be encrypted |
| `--mapping` | Listed destinations and necessary parent creation are authorized |
| Fixed `workers` above 128 | Unsupported |
| `--follow-dst` with `--into` | Follows a destination symlink only to a directory inside the directory the destination is in; not with `--widen-dirs all`, and not for [named destinations](persistence-reference.md#copy-limits) |
| `--widen-dirs` | Approved as part of the copy; `all` widens nothing above the directory the destination is in |
| `--detach` | Unsupported; the local authorization process must remain attached |
| Native `rm` | Unsupported; use a normal SSH login |

Restricted copies use encrypted TCP when reachable and otherwise SSH workers
from the source to the destination, under the same authorization and limits.
A failed direct connection never relays data through your machine; choose
`--coordinate-at local` to do that.

A copy through [approved account connections](#approved-account-copies) that
uses SSH workers adds a temporary line, with a comment starting
`syq-copy-worker-`, to the destination account's `~/.ssh/authorized_keys`. A
killed copy can leave it behind; it grants nothing, and you can delete it when
no copy to that account is running.

<a id="signed-results"></a>

## Results from the destination

The destination reports each change it makes, refuses, or fails as the copy
runs. Your machine checks that the reports come from the destination and that
the source, which passes them on, left none out and added none. A refusal or a
failed change on the destination decides the outcome even if the source
reports success, and reports cut short fail the copy. Use `-v` for the
destination's totals or `--results FILE` for [automation](automation.md);
`--dry-run --results` previews the copy.

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
the coordinating server, and the peer's SSH server.

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

Save the reported remote log location. If printing it fails, the command
reports an error but the job may still be running. The coordinating server
needs `/bin/kill` and either `setsid` or `perl`.

## Authorization selection

[Authorization defaults](persistence-reference.md#authorization-defaults)
describes how a command picks its `--auth-from` value. For SSH copies, `@NAME`
and SSH providers use or request an
[approved account connection](persistence-reference.md#approved-account-connections),
and `ssh` uses only this machine's own access. For object-storage copies and
removal, an explicit `--auth-from @NAME` uses
[storage authorization](object-storage.md#authorize-from-your-laptop).

For `syq cp` between this machine and one SSH server, `auto` first tries this
machine's own SSH access, with SSH's usual prompts and timeouts, even when an
approved account connection exists. If SSH rejects the credentials, can't
verify the host key, can't resolve the name, or is refused, syq asks your live
receiving machines, in alphabetical order, to approve just this copy; each
uses its own SSH configuration and trusted host keys. After a timeout, a
temporary DNS failure, or another SSH error, or with no receiving machine
available, syq reports the SSH error. Copies with options a receiving machine can't authorize (below) use only
this machine's access. Once approval is requested, a refusal or failure ends
the attempt.

Per-copy approval does not support a root login on the destination,
`--detach`, custom `--rsh` or `--syq-path`, `--no-bootstrap`, alternative
`--peer-auth` or `--coordinate-at`, or `--no-tcp-encryption`. The authorizing
machine's copy limits apply, including its `--max-delete` and `--max-entries`
for pruning.

A per-copy upload uses the destination account's [enrollment](#enrollment),
which the authorizing machine sets up on the first approved copy, and
refreshes after you upgrade syq, over its own SSH login without prompts. Its
login key must therefore be able to sign without a terminal: in its agent, or
an unencrypted key file. That login accepts a destination host key it has not
seen before; see [How hostA checks hostB's key](security.md#how-hosta-checks-hostbs-key).
If it can't connect, it tries again through the source, whose SSH server must
then allow TCP forwarding. See
[Copying between servers](security.md#copying-between-servers) for what the
source receives.

For per-copy downloads (`--from HOST` to this machine), approval grants read
access to the displayed source files and directory trees. `--src-non-dir`
grants only that entry; directory selectors grant their trees; an untyped
source grants the entry or tree it turns out to be. Filters narrow the copy,
but not the approved tree. File data requires encrypted direct TCP, with no
SSH fallback or relay through the laptop, so `--no-tcp` and descriptor streams
are unsupported on this route. Account approval supports SSH-only downloads.

For per-copy uploads, quoted `~` and `~/archive` select the destination account's home
directory, and `~//archive` is `/archive`, as with ordinary SSH. Use
`./~/archive` for a literal directory called `~`.

## Approved account copies

A direct copy between two other servers can request or reuse
[approved account connections](persistence-reference.md#approved-account-connections)
to both endpoints. Both endpoints must select an authorization provider,
through `--auth-from` or their saved choices; `auto` and `ssh` use native
authentication even when approvals exist. To prepare connections in advance,
use `syq persist connect ENDPOINT --auth-from PROVIDER`.

The copy runs on the source with `--peer-auth restricted`, and supports
`--no-tcp`, helper overrides, mappings, and `--results`; `--pscope` selects
the local domain's approved connections and choices. With
`--coordinate-at local`, it reuses approved access to each endpoint and relays
file data through the invoking machine instead.

The source's SSH server must permit remote Unix-socket forwarding, and on
OpenSSH 7.8 and later remote TCP forwarding too; syq never relays file data
through your machine to work around disabled forwarding. File data goes
directly between the servers, so a `ProxyJump` route that lets your machine
reach them does not let them reach each other. Syq starts a receiver for this
copy over the destination's approved connection, which must not log in as
root; no enrollment is needed, but copying over SSH needs a writable
`~/.ssh/authorized_keys` there for a
[temporary line](#limits-and-unsupported-options). The destination's
[restricted-copy limits](#limits-and-unsupported-options) and
[results from the destination](#results-from-the-destination) still apply.
Helpers must match the invoking build; normal bootstrap installs them.

## Verification

For comparisons between two servers, use `--dry-run --hash --coordinate-at local`.
This uses ordinary SSH access and supports `--results FILE` without restricted
receiver enrollment. Files are hashed on the servers; your machine receives
hashes, listings, and results. Remote setup may still install the helper or
[syq](install.md#automatic-installation-on-ssh-servers).
