# Remote copy reference

This page answers questions about copies between two servers, hostA (the
source) and hostB (the destination). To set one up, start with
[Copy between servers](remote-to-remote.md); [`syq cp`](commands/cp.md) and
[`syq receiver`](commands/receiver.md) list the options.

## SSH configurations

To change how hostA connects to hostB, for example to require a known host
key, edit hostA's SSH configuration for the address hostA is given. Your
laptop's SSH configuration decides hostB's login, address, and port, and hostA
looks up its own configuration under that address, not the name you typed.
HostA checks hostB's host key as described in
[how hostA checks hostB's key](security.md#how-hosta-checks-hostbs-key).

## Enrollment

In syq's default mode, restricted copying, hostB accepts only copies you
signed; see [Copies between servers](security.md#copies-between-servers). The
first copy to a server account sets this up there, once for each of your
machines; this is called enrollment. To do it ahead of time, run
`syq receiver enroll HOST`. Enrollment needs an SSH key or certificate login.
A root account can be enrolled, but its receiver serves only downloads: it
refuses copies that write to the account, and copies between servers that it
would run. Enroll an account under the name the server gives its user ID:
another name for the same user, such as `toor` for root, is refused before
anything is set up.

Enrollment adds one line to the server's `~/.ssh/authorized_keys`. Its key,
the entry key, can only start syq's receiver, and its comment,
`syq-enrollment:ID signer TYPE KEY`, names the login key the receiver trusts.
It also installs syq under `~/.local/lib/syq` and keeps state in
`~/.local/share/syq/enrollments/ID`; your machine keeps the entry key in
`~/.local/state/syq/enrollments/ID`. Manage both with `syq receiver` commands
rather than deleting files.

Copies cannot write the account's `~/.ssh` or syq's own programs and state, such
as `~/.local/lib/syq`, `~/.local/libexec`, `~/.config/syq`, and enrollment and
receiving state. A copy that puts a directory's contents into, prunes, or
replaces a directory holding one of these, such as your home directory, is
refused; copy into a subdirectory instead, or copy named files or directories
into it. A copy from the account reads whatever its command names, these
included, as a login to the account could.

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

When the key syq recorded can no longer sign, for example because you removed
it from your agent after switching keys, the next copy logs in again and
trusts your current key. While the old key can still sign, syq keeps using it;
run `syq receiver enroll HOST` to switch to your current login key now.
`syq receiver list` shows the key each enrollment trusts. After you change syq
builds, the next copy logs in once to update the receiver. A server that
reaches the receiver itself, to run or coordinate a copy, needs the same syq
build as the machine that approves the copy, whose build the receiver follows.
Otherwise the receiver refuses it and says which builds it saw; update syq on
whichever of the two machines is older.

A copy between two servers that you start on your laptop can also find the
receiver running another build than your laptop recorded, for example after
another syq on your laptop updated it. Then syq updates the receiver to its
own build and runs the copy once more, signed as the same copy with the same
time limits, so the receiver, keeping its record of the copies it ran, runs
at most one of the two. It does this only when the server running the copy
runs your laptop's build, as it does unless you pass `--syq-path` or
`--no-bootstrap`, and never for a dry run. It doesn't when the enrollment was
revoked or set up again meanwhile, when hostB's record of the copies it ran
is damaged, or when the copy may no longer start; syq then reports the
refusal, and running the copy again starts afresh.

Only `syq receiver revoke ID`, or deleting syq's line from `authorized_keys`,
ends an enrollment. Removing or revoking your login key, certificate, or
certificate authority on the server does not stop copies your key signs, and
neither do options such as `from=` or `expiry-time=` on your key's line, or a
certificate's critical options, such as `source-address`.

## Limits and unsupported options

A restricted copy may make up to 100 million entries and write up to 8 TiB of
file data by default; change these for one copy with
`--receiver-max-entries N` and `--receiver-max-bytes SIZE`. Entries are the
changes hostB makes: files written, directories, links and special files
created, metadata changes, and deletions. The copy must start within 24 hours
of authorization and finish within seven days of it.

A copy between two servers can name up to 1,024 sources, like any copy. Long
paths lower that number in two cases. A restricted copy's signed command can
be at most 256 KiB, so 1,024 sources fit when their paths average up to about
250 characters. With `--detach`, `--syq-path` or `--no-bootstrap`, the server
that runs the copy gets the sources on its command line, which holds 128 KiB,
so 1,024 sources fit only when their paths average up to about 90 characters.

Restricted copies cannot use `--performance-tuning workers=N` above 128, and
`syq rm` cannot go through the receiver; use a normal SSH login for those.
With `--no-tcp-encryption`, the receiver accepts unencrypted TCP data only
because the signed command asks for it, and an approval prompt for such a copy
warns that anyone on the network between the servers can read or change the
files.

As in any copy, a symlink in the destination path you give stops the copy
unless you pass `--follow-dst`. With it, hostB follows the links, including
one at the destination itself, wherever they lead, as the account would,
except into its SSH configuration or syq's own programs and state.
`--widen-dirs all` widens nothing above the destination's parent directory,
and can't be combined with `--follow-dst` and `--into`.

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
from hostA, choose another mode. Each gives the server running the copy (hostA unless you set
`--coordinate-at`) more authority:

| Option | Authority available to the server running the copy |
|---|---|
| `--peer-auth own-credentials` | Credentials already on that server |
| `--peer-auth broker` | Your full destination-account authority, limited to that host and user |
| `--peer-auth full-agent` | Your whole SSH agent, as with `ssh -A` |
| `--rsh COMMAND` | Whatever your supplied SSH command permits |

`broker` needs OpenSSH 8.9 or newer on all three machines, and your laptop must
trust both servers through plain host keys in known_hosts; it does not work with
host certificates alone, `KnownHostsCommand`, or `RevokedHostKeys`. A copy run
by the destination needs one of these modes; for example, to make hostB pull
from hostA with its own credentials:

```sh
syq cp --coordinate-at dst --peer-auth own-credentials --from hostA data --to hostB --into /archive
```

## Detached copies

`--detach` keeps the copy running after your command exits, and cannot use
`--results`. Save the remote log location it prints; if printing fails, the
job may still be running. The server running the copy needs `/bin/kill` and
either `setsid` or `perl`.

A detached restricted copy runs until it finishes, until the seven days it
has to finish run out, or until you revoke hostB's enrollment. HostA deletes
the entry key when the copy ends. Your laptop doesn't see hostB's reports of
a detached copy, so the log on hostA is the copy's only record, and it is only
as trustworthy as hostA.

## Authorization selection

With the default `--auth-from auto`, a `syq cp` between the machine you run it
on and one SSH server first tries that machine's own SSH access. If SSH rejects
the login or cannot verify the host key, syq asks the first available
receiving machine, in alphabetical order of name, to approve just this copy.
The approved copy still connects from the machine you run it on, so after any
other SSH error, such as a name that does not resolve, a refused connection or
a timeout, or with no receiving machine available, syq reports the SSH error.
A refusal or failure on the receiving machine ends the copy.

Per-copy approval does not work for an upload to a root login, nor with
`--detach`, `--rsh`, `--syq-path`, `--no-bootstrap`, or other `--peer-auth` or
`--coordinate-at` values, and an approved upload
cannot preserve hard links, ACLs, extended attributes, or access or birth
times, or use `--open-noatime` or `--sparse`. Such copies need this machine's
own SSH access. The receiving machine's copy limits apply, including its
`--max-delete` and `--max-entries`.

The receiving machine sets up the other server's
[enrollment](#enrollment), the destination of an upload or the source of a
download, on the first approved copy, and again after you upgrade syq, over
its own SSH login without prompts; a dry run never sets it up. Its key must
therefore sign without a terminal: in its agent, or an unencrypted key file.
Unless its SSH configuration sets `StrictHostKeyChecking yes`, that login
accepts a host key it has not seen before; see
[how hostA checks hostB's key](security.md#how-hosta-checks-hostbs-key). If it
cannot reach the other server, it goes through the server you run the command
on, whose SSH server must then allow TCP forwarding.

The server you run the command on then logs in to the other server's
restricted receiver itself, with its own SSH configuration, so it must resolve
that server's name and reach its SSH port directly, without a `ProxyJump`. It
checks the host key as
[hostA checks hostB's](security.md#how-hosta-checks-hostbs-key). From then
on, the copy doesn't need the receiving machine, and stops when the command
that started it ends. File data goes over direct TCP, encrypted unless the
command passes `--no-tcp-encryption`, or over SSH with `--no-tcp` or when TCP
cannot connect.

For a download, the source's receiver serves only the files and directory
trees the command names, which the approval prompt shows as the source reads
them: relative paths start in the `-C` or `--root` directory you give, or else
in the source account's home directory. A source given with `--src-non-dir`
allows only that entry; any other source allows the whole tree if it is a
directory. Filters narrow the copy but not what may be read, and with
`--follow-src` symlinks are followed wherever they lead. Descriptor streams do
not work.

For uploads, quoted `~` and `~/archive` mean the destination account's home
directory, and `~//archive` means `/archive`, as with SSH. Use `./~/archive`
for a directory named `~`.

<a id="approved-account-copies"></a>

## Copies between two other servers

To copy from hostB to hostC while working on a third server, select a
receiving machine with `--auth-from @NAME` or an
[SSH authorization provider](persistence-reference.md#ssh-authorization-providers)
with `--auth-from [USER@]HOST[:PORT]`, or save either for one of the servers
(`auto` and `ssh` never ask). The receiving machine or provider asks you once,
applies its copy limits, and sets up or updates the [enrollment](#enrollment)
on each account when needed, over its own SSH logins without prompts, as for an
upload (see [Authorization selection](#authorization-selection)); a dry run
never sets them up. If a receiving machine can't reach hostB or hostC along
its own SSH configuration's route, it logs in through the server you run the
command on, whose SSH server must then allow TCP forwarding and which must
reach that server's SSH port. A provider can't tell which server is asking, so
it reaches both only along its own route, and its prompt names the provider
account instead of your server; see
[provider trust](security.md#ordinary-ssh-authorization-providers). Account
approvals are not used for these copies.

The server you run the command on logs in to hostB's restricted receiver,
which runs the copy and sends file data directly to hostC's receiver. Your
server must reach hostB's SSH port, and hostB must reach hostC's, each with
its own SSH configuration; hostB looks hostC up under the name in your
command. Your server checks hostB's host key, and hostB checks hostC's, as
[hostA checks hostB's](security.md#how-hosta-checks-hostbs-key), also
trusting what your laptop's known_hosts lists. The copy stops when the command
that started it ends.

The copy supports `--no-tcp`, `--no-tcp-encryption` and `--results`, and your
server checks [results from the destination](#results-from-the-destination).
It does not support `--mapping`, whose contents your laptop never sees,
`--coordinate-at dst`, `--detach`, `--rsh`, `--syq-path`, `--no-bootstrap`, or
other `--peer-auth` values, and neither login may be root. As for an upload, a
saved choice does not apply to a copy with one of these options:
your server's own SSH access runs it. An explicit `--auth-from @NAME` with one
of them is refused. [Restricted-copy limits](#limits-and-unsupported-options)
apply. With `--coordinate-at local`, file data goes through your server
instead, which then needs
[account access](persistence-reference.md#account-access) to both servers.

Older versions of syq added lines with a comment starting `syq-copy-worker-`
to the destination's `~/.ssh/authorized_keys` for these copies. They grant
nothing, and you can delete them.

## Verification

To compare files on two servers without enrolling either, use
`--dry-run --hash --coordinate-at local`. The servers hash their own files and
send your machine hashes, listings, and results, so you can add
`--results FILE`. Syq still installs itself on the servers if needed.
