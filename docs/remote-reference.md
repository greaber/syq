# Remote copy reference

This page answers questions about copies between two servers, hostA (the
source) and hostB (the destination). To set one up, start with
[Copy between servers](remote-to-remote.md); [`syq cp`](commands/cp.md) and
[`syq receiver`](commands/receiver.md) list the options.

## SSH configurations

Your laptop's SSH configuration decides how to reach hostB. HostA then connects
with its own SSH configuration, looked up under the address your laptop's
configuration gives hostB rather than the name you typed, and checks hostB's
host key as described in
[how hostA checks hostB's key](security.md#how-hosta-checks-hostbs-key).

`--peer-auth broker` needs your laptop to trust both servers through plain
host keys in known_hosts. It does not work with host certificates alone,
`KnownHostsCommand`, or `RevokedHostKeys`.

## Enrollment

In syq's default mode, restricted copying, hostB accepts only copies you
signed; see [Copies between servers](security.md#copies-between-servers). The
first copy to a server account sets this up there, once for each of your
machines; this is called enrollment. To do it ahead of time, run
`syq receiver enroll HOST`. Enrollment needs an SSH key login to an account
other than root.

Enrollment adds one line to the server's `~/.ssh/authorized_keys`. Its key,
the entry key, can only start syq's receiver, and its comment,
`syq-enrollment:ID signer TYPE KEY`, names the login key the receiver trusts.
It also installs syq under `~/.local/lib/syq` and keeps state in
`~/.local/share/syq/enrollments/ID`; your machine keeps the entry key in
`~/.local/state/syq/enrollments/ID`. Manage both with `syq receiver` commands
rather than deleting files.

Copies cannot write the account's `~/.ssh` or syq's own programs and state,
such as `~/.local/lib/syq`, `~/.local/libexec`, `~/.config/syq`, and
enrollment and receiving state. A copy that fills, prunes, or replaces a
directory holding one of these, such as your home directory, is refused; copy
into a subdirectory instead, or copy named files or directories into it.

### Which key signs

Your machine signs each copy with the key you logged in with during
enrollment, through your SSH agent or from a key file without a passphrase.
Syq never asks for a passphrase, so load passphrase-protected, FIDO, and
PKCS#11 or PIV keys into your agent. A key added with `ssh-add -h` cannot sign
copies.

- **FIDO keys** need one touch for each copy, and about three when the copy
  enrolls. The receiver also requires a PIN whenever your login would; a PIN
  needs an `SSH_ASKPASS` program the agent can run.
- **Certificates:** the receiver stops accepting copies when the certificate
  expires; the next copy logs in again and records the new one.
- **Other logins** cannot enroll: passwords, keyboard-interactive, Kerberos,
  host-based, and logins that need a second factor. Use
  [account access](persistence-reference.md#account-access) with
  `--auth-from @NAME` instead.

<a id="enrollments-from-older-versions"></a>

### Changing keys and updating syq

If you start logging in with a different key, the next copy logs in again and
trusts the new key; `syq receiver list` shows the key each enrollment trusts.
After you change syq builds, the next copy logs in once to update the
receiver.

Only `syq receiver revoke ID`, or deleting syq's line from `authorized_keys`,
ends an enrollment. Removing or revoking your login key, certificate, or
certificate authority on the server does not stop copies your key signs, and
neither do options such as `from=` or `expiry-time=` on your key's line.

## Limits and unsupported options

A restricted copy may make up to 100 million entries and write up to 8 TiB of
file data by default; change these for one copy with
`--receiver-max-entries N` and `--receiver-max-bytes SIZE`. Entries are the
changes hostB makes: files written, directories, links and special files
created, metadata changes, and deletions. The copy must start within 24 hours
of authorization and finish within seven days.

Restricted copies cannot use `--no-tcp-encryption`, `--detach`, or
`--performance-tuning workers=N` above 128, and `syq rm` cannot go through the
receiver; use a normal SSH login for those. With `--into`, `--follow-dst` follows a destination symlink only to a
directory inside the destination's parent directory, and `--widen-dirs all`
widens nothing above that parent.

<a id="signed-results"></a>

## Results from the destination

HostB reports each change it makes, refuses, or fails, and your machine checks
that hostA passed on every report unaltered. A refusal or failure on hostB
fails the copy even if hostA reports success. Use `-v` for hostB's totals,
`--results FILE` for [automation](automation.md), and `--dry-run --results` to
preview. The reports cannot prove that hostA sent the right files; see
[A compromised source server](security.md#a-compromised-source-server).

## Other authentication modes

When restricted copying does not fit, for example because hostB should pull
from hostA or the copy must keep running after you disconnect, choose another
mode. Each gives the server running the copy (hostA unless you set
`--coordinate-at`) more authority:

| Option | Authority available to the server running the copy |
|---|---|
| `--peer-auth own-credentials` | Credentials already on that server |
| `--peer-auth broker` | Your full destination-account authority, limited to that host and user |
| `--peer-auth full-agent` | Your whole SSH agent, as with `ssh -A` |
| `--rsh COMMAND` | Whatever your supplied SSH command permits |

`broker` needs OpenSSH 8.9 or newer on all three machines. A copy run by the
destination needs one of these modes; for example, to make hostB pull from
hostA with its own credentials:

```sh
syq cp --coordinate-at dst --peer-auth own-credentials --from hostA data --to hostB --into /archive
```

## Detached copies

`--detach` keeps the copy running after your command exits. It needs
`--peer-auth own-credentials` or `--rsh`, and cannot use `--results`. Save the
remote log location it prints; if printing fails, the job may still be
running. The server running the copy needs `/bin/kill` and either `setsid` or
`perl`.

## Authorization selection

With the default `--auth-from auto`, a `syq cp` between the machine you run it
on and one SSH server first tries that machine's own SSH access. If SSH rejects
the login, cannot verify the host key, cannot resolve the name, or is refused,
syq asks the first available receiving machine, in alphabetical order of
name, to approve just this copy. Otherwise, as after a timeout or with no
receiving machine available, syq reports the SSH error. A refusal or failure
on the receiving machine ends the copy.

Per-copy approval does not work with a root login on the destination,
`--detach`, `--rsh`, `--syq-path`, `--no-bootstrap`, other `--peer-auth` or
`--coordinate-at` values, or `--no-tcp-encryption`; such copies use only their
own SSH access. The receiving machine's copy limits apply, including its
`--max-delete` and `--max-entries`.

For an upload, the receiving machine sets up the destination's
[enrollment](#enrollment) on the first approved copy, and again after you
upgrade syq, over its own SSH login without prompts. Its key must therefore
sign without a terminal: in its agent, or an unencrypted key file. Unless its
SSH configuration sets `StrictHostKeyChecking yes`, that login accepts a
destination host key it has not seen before; see
[how hostA checks hostB's key](security.md#how-hosta-checks-hostbs-key). If it
cannot reach the destination, it goes through the source, whose SSH server
must then allow TCP forwarding.

For a download, approval grants read access only to the source files and
directory trees shown. A source given with `--src-non-dir` grants only that
entry; any other source grants the whole tree if it is a directory. Filters
narrow the copy but not the grant. File data needs direct encrypted TCP between
the servers, so `--no-tcp` and descriptor streams do not work. To download over
SSH, use an
[approved account connection](persistence-reference.md#approved-account-connections)
(`--auth-from @NAME`).

For uploads, quoted `~` and `~/archive` mean the destination account's home
directory, and `~//archive` means `/archive`, as with SSH. Use `./~/archive`
for a directory named `~`.

## Approved account copies

To copy between two other servers using your laptop's access to both, select
a provider for each server, with `--auth-from` or a saved choice (`auto` and
`ssh` never use approvals), and approve the
[account connections](persistence-reference.md#approved-account-connections).
The copy runs on the source as a restricted copy without enrollment, and
needs the default `--peer-auth restricted`. It supports `--no-tcp`, mappings,
and `--results`; with `--coordinate-at local`, file data goes through the
machine you run it on instead.

File data goes directly between the servers. The source's SSH server must
allow remote Unix-socket forwarding, and from OpenSSH 7.8 also remote TCP
forwarding, and the source must reach the destination itself; a `ProxyJump`
in your own configuration does not help. The destination login must not be
root. [Restricted-copy limits](#limits-and-unsupported-options) and
[results from the destination](#results-from-the-destination) apply.

A copy that carries file data over SSH adds a temporary line, with a comment
starting `syq-copy-worker-`, to the destination's `~/.ssh/authorized_keys`, so
that file must be writable. A killed copy can leave the line behind; it grants
nothing, and you can delete it when no copy to that account is running.

## Verification

To compare files on two servers without enrolling either, use
`--dry-run --hash --coordinate-at local`. The servers hash their own files and
send your machine hashes, listings, and results, so you can add
`--results FILE`. Syq still installs itself on the servers if needed.
