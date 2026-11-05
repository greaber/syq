# Persistence details

See [`syq persist`](commands/persist.md) for the option list.

For everyday setup, start with [Keep connections open](persistence.md) or
[Use your laptop from a server](receive.md).

Persistence commands use the default domain unless you select an isolated one
with `--pscope PATH`, before or after any `persist` subcommand. Each domain has
its own connections, authorization defaults, receiving profiles, and
remembered account permissions. See [Isolated script scopes](#isolated-script-scopes)
for creation, lifetime, and cleanup.

## Account access

A server can log in to other servers with your laptop's SSH access, as shown
in [Open a shell on another server](receive.md#open-a-shell-on-another-server).
This section covers the choices, requirements, and lifetime of that access;
see [SSH account access](security.md#ssh-account-access) for what approving it
grants.

### Authorization defaults

`--auth-from` chooses how a command authorizes its SSH logins:

| Value | Meaning |
|---|---|
| `auto` (default) | Use this machine's own SSH access. A copy between this machine and one server can then ask a receiving machine to approve just that copy; see [Authorization selection](remote-reference.md#authorization-selection). Other commands run native SSH once. |
| `ssh` | Use only this machine's own SSH access, ignoring approved account connections |
| `@NAME` | Use or request access to the destination account through that receiving machine, without first trying this machine's own access; fails if the machine is unavailable or refuses |
| `[USER@]HOST[:PORT]` | The same, through an [SSH authorization provider](#ssh-authorization-providers) |

To save a choice on a server, for all hosts or for one:

```sh
syq persist auth-from @laptop
syq persist auth-from ssh --for backup
syq persist auth-from
syq persist auth-from --reset --for backup
syq persist auth-from --reset
```

A command uses the first of these that is set:

1. Its `--auth-from` option (`--syq-auth-from` for `syq rsync`), including `auto`.
2. The `SYQ_AUTH_FROM` environment variable, for one shell or script. An empty
   value counts as unset.
3. A saved `--for HOST` choice. It matches the exact hostname or SSH alias
   typed in the command, for every login and port, without expanding aliases.
4. The saved default.
5. `auto`.

`--reset --for HOST` removes one host's choice; `--reset` restores the default
to `auto` and keeps host choices. Omit the value to show saved choices, or add
`--for HOST` to show that host's effective choice; both say when
`SYQ_AUTH_FROM` overrides them. Choices are saved in `auth-from.json` in the
selected domain.

Saved choices and `SYQ_AUTH_FROM` apply to every command that takes
`--auth-from`, whether or not persistence is on: `syq ssh`, `persist connect`,
`persist ssh-config`, and the SSH endpoints of `cp`, `rsync`, `rm`, `map`, and
`clean-partials`. So with `@laptop` saved, `syq persist connect hostB` opens an
approved account connection rather than an ordinary persistent one. A copy
with `--coordinate-at local` selects access separately for each endpoint. Custom `--rsh` routes, copies to receiving names, and object storage
keep their own authentication; S3 storage authorization needs an explicit
`--auth-from @NAME`.

### Approved account connections

Commands selecting `@NAME` or an SSH provider open an approved account
connection when they need one, and `syq persist connect HOST --auth-from @NAME`
opens one in advance. Neither enables ordinary persistence or receiving on
`HOST`. Later commands that select the same provider reuse the connection,
including `ssh`, copies, `rsync`, `rm`, `map`, `clean-partials`, and
descriptor copies; for copies between two other servers, see
[Approved account copies](remote-reference.md#approved-account-copies). Remote
path completion reuses a matching connection, but never requests approval or
opens one. `persist status --json` lists these connections in
[`authorized_ssh`](automation.md#connection-status), and `syq persist off`
closes them.

Account access needs:

- OpenSSH 8.9 or newer for the requesting server's SSH client and the
  destination's SSH server.
- Exact plain host keys for both servers, trusted by the laptop; host
  certificates alone are not enough. The laptop looks up each key under the
  alias you typed, with any port you wrote, or your `HostKeyAlias`, in its own
  SSH configuration, so an alias may lead to different addresses on the two
  machines as long as both reach the same host.
- The laptop's key loaded in its SSH agent. The requesting server's SSH
  configuration chooses the destination account, address, port, and route,
  and its `IdentityFile` and `IdentitiesOnly` settings choose which keys to
  offer: an `IdentityFile` naming a public key selects the matching key in the
  laptop's agent, and a `CertificateFile` can pair a user certificate with it.

When a copy uses SSH for file data, because TCP is unavailable or you chose
`--no-tcp`, each data connection logs in under the same permission without
another approval prompt. The laptop or provider must stay available, and
withdrawing the permission stops the copy. An agent that requires
confirmation or a hardware-key touch asks for each connection.

`syq persist ssh-config HOST` prints an OpenSSH configuration for one approved
connection, for use with `ssh -F FILE`, `scp`, `sftp`, Git, or rsync:

```sh
syq persist ssh-config hostB > hostB.ssh
ssh -F hostB.ssh hostB hostname
GIT_SSH_COMMAND='ssh -F hostB.ssh' git clone hostB:project.git
rsync -e 'ssh -F hostB.ssh' report hostB:report
```

`HOST` must match the login, host spelling, and port that opened the
connection. The command never requests approval or opens a login, and the file
contains no private key. Once the connection closes, tools using the file fail
without trying other authentication, so export it again after reconnecting.
Use its absolute path when a tool runs from another directory.

### SSH authorization providers

An [SSH authorization provider](receive.md#use-an-ssh-authorization-provider)
needs the same syq build as the machines that use it. Its default domain's
first receiving profile must be enabled. Its SSH server must allow local
forwarding (`AllowTcpForwarding` and `AllowStreamLocalForwarding` set to
`local` or `yes`), and the login key's `authorized_keys` entry must not block
it with `restrict` or `no-port-forwarding`.

### Account permissions

**Allow** lasts until the laptop's receiving connection to the requesting
server ends, or for a provider, until that provider login ends. **Remember**
keeps the permission for later connections through the same receiving profile,
until you remove it. See [SSH account access](security.md#ssh-account-access)
for exactly what each covers.

Decide pending requests with the desktop prompt or locally, and manage
remembered permissions on the laptop:

```sh
syq persist receive approve REQUEST_ID
syq persist receive approve REQUEST_ID --remember
syq persist receive deny REQUEST_ID
syq persist receive permissions list
syq persist receive permissions remove PERMISSION_ID
```

`--remember` is accepted only for account-access requests. To stop further
access, run `syq persist off` on the requesting server to close its
connections, and `syq persist receive off` on the laptop to end session
permissions and stop further authorization; see
[SSH account access](security.md#ssh-account-access) for what this does not
undo. Add `--pscope PATH` on either machine for an isolated domain. Remembered permissions belong to the laptop's selected domain: a new
domain on the laptop starts without them, and a new domain on the server does
not revoke what that server account was already granted.

## Names and profiles

Give a project its own receiving name and directory:

```sh
mkdir -p ~/work/project
syq persist receive on --name laptop --cwd ~ --connection server
syq persist receive on --name project --root ~/work/project --connection server
```

Both profiles work from the same server account: `syq cp results --to @project`
and `syq cp report.pdf --to @laptop`. Each profile has its own directory, copy
root, limits, automatic approval root, and background connection to each
allowed server. New profiles start with the usual defaults, including asking
for approval; they do not inherit another profile's trust or confinement
settings. Up to 32 profiles can be saved.

### Change or stop a profile

`receive on --name NAME` creates a profile or updates that name's settings;
omitted options keep their saved values. It enables persistence in the selected
domain and applies the profile to allowed connections, active and future. It
connects only the endpoints supplied with `--connection` in this invocation,
and waits for receiving to become ready on them. If one fails, the settings
stay saved and healthy connections keep running, but the command exits
unsuccessfully. Use `persist connect HOST` to start another connection.
Without `--name`, `receive on` updates the first saved profile, shown first by
`receive status`.

```sh
syq persist receive status
syq persist receive status --name project
syq persist receive off --name project
syq persist receive on --name project
syq persist receive remove project
syq persist receive wait server --name laptop --timeout 30
```

Changing a profile's access settings, stopping it, or removing it cancels only
that profile's copies, commands, and pending approvals; other profiles keep
working, and changing only `--notify` or repeating unchanged settings cancels
nothing. A copy the profile approved from one server to another is the
exception: once approved, it no longer needs this machine, and runs until it
finishes, until someone interrupts it on the server, or until you revoke the
destination's enrollment with `syq receiver revoke`. `receive off` without a
name stops all profiles; `receive on` enables the first profile, and
`receive on --name NAME` enables another. Removing the first profile makes the
next saved profile the default. `pending`, `approve`, and `deny` work across
the selected domain's profiles, and `pending` names the receiving profile of
each request.

<a id="choose-allowed-servers"></a>

### Choose allowed connections

To give one server account an inbox for downloads that do not need approval:

```sh
mkdir -p ~/Downloads/work
syq persist receive on --name work-inbox --connection work \
  --auto-approve-root ~/Downloads/work
```

On `work`, use `syq cp results --to @work-inbox`. Other connections cannot
use that profile. Your general profile can still ask for approval on every
download.

Profiles default to all SSH connections in their domain. `--connection ENDPOINT`
restricts a profile to that exact SSH destination as used on the receiving
machine. Use the endpoint shown by `persist status`: for example `work`,
`alice@work`, or `alice@work:2222`. Matching includes an explicitly selected
user and port; it does not expand SSH aliases or equate omitted ports with
explicit ports. An alias reaches the account and host your local SSH
configuration gives it, so changing that configuration can change which
account an allowed alias reaches; the server cannot choose its own identity
for this check.

Repeat `--connection` to supply several endpoints. Each supplied list replaces
the saved list and connects the supplied endpoints; omitting `--connection`
keeps the restriction without connecting dormant endpoints.
`--all-connections` clears the restriction and starts receiving on active
connections. Changes apply to existing persistent connections too.

### Move a name to another machine

Names belong to a server account and stay assigned to their original receiving
machine when it disconnects. Another laptop cannot claim the same name, even
while the original is offline. Stopping receiving or removing a local profile
does not release its server-side name.

To replace a laptop, stop its receiving connection, then run
`syq persist destinations forget laptop` on the server. Run
`syq persist connect server` on the replacement laptop to claim the released
name. A rejected connection needs this explicit retry. Forgetting a live
connection is refused.

### Back up the receiving identity

Syq generates one receiver key per local account, shared by receiving profiles,
persistence domains, and syq versions, in
`~/.syq-receiver-identity/identity_ed25519`. It is independent of your SSH
login keys and profile settings. Keep that directory across upgrades, and
include it in private backups if you want to restore the same identity; losing
it means releasing the old names on each server. Copying it to another machine
gives that machine the same receiver identity, but only one connection can hold
a name: while the old one is still responsive, the replacement is rejected, and
an unresponsive one must time out first. Use different profile names to
receive on both machines at once.

## Directories

The three directory settings are independent:

| Setting | Purpose | Clear it with |
|---|---|---|
| `--cwd DIR` | Starting directory for relative paths | `--auto-cwd` |
| `--root DIR` | Hard boundary for downloads, even with approval | `--no-root` |
| `--auto-approve-root DIR` | Downloads confined here skip approval, except with some options | `--no-auto-approve-root` |

Each requires an existing directory with a UTF-8 path; neither root can be `/`.
An explicit cwd must be inside the hard root, if set. Otherwise the starting
directory is the hard root, the automatic approval root, or your home directory,
in that order.

Downloads outside the automatic approval root ask for approval, provided they
stay within the hard root if one is set. Symlinks cannot grant automatic writes
outside the approval root. Replacing the automatic root directory itself
requires approval, and is prohibited when it is also the hard root. These roots
do not restrict approved commands or the destinations of approved copies to
other servers.

## Copy limits

Copies to a receiving name use encrypted TCP connections that the receiving
machine opens to the sending server, falling back to SSH when TCP is
unreachable. `--no-tcp` forces SSH; `--tcp-ports` selects the listening port
range on the sending server. The receiving connection must stay open
throughout the copy.

Copies support directories, symlinks, modification times, filters, hashing,
resume, mappings, the `--copy-metadata` options, `--sparse`, `--in-place`,
and the [overwrite policies](reference.md#choose-which-existing-files-to-update).
Copies are refused while syq runs as root, so ownership and special files work
as for any copy by an ordinary account. Named copies do not follow a
destination symlink, even with `--follow-dst`; name the directory the link
points to instead.

Each copy is limited to 100 GiB and one million entries by default, counting
entries as [restricted copies](remote-reference.md#limits-and-unsupported-options)
do. Change these ceilings with
`syq persist receive on --max-bytes 20G --max-entries 100000`. Lower limits
requested by the sender also apply. Limits are per copy, so repeated copies can
fill the disk.

Pruning is disabled unless the laptop sets a positive `--max-delete`; until
then, a pruning copy is refused, and so is a dry run of it. A pruning copy
that plans more deletions than the laptop's `--max-delete` or `--max-entries`,
or than its own `--max-delete`, deletes nothing and exits 25. A dry run of it
exits 25 too, so you can check first.

## Connection lifetime and waits

`persist on` enables persistence for subsequent syq SSH connections.
`persist connect server` enables it and connects immediately; with receiving
enabled, it waits until receiving is ready. `--timeout 30` limits that wait
after SSH and helper setup, not authentication or installation. Failure leaves
persistence enabled, and connecting again reuses a healthy connection without
cancelling its requests.

Default-domain connections have no idle expiry. In an explicit domain, idle
SSH connections expire after five to ten minutes. An enabled receiving service
keeps its connection until you stop it and reconnects after interruptions;
other SSH logins reopen on their next use. Syq installs no login service, so
connect again after a reboot. Copies are not queued or retried automatically.
After you update syq, receiving services and the SSH authorization provider
switch to the new version by themselves once no copy, command, login, or
approval is in progress.

Use `syq persist receive wait server --timeout 30` to wait without starting or
restarting a connection. `syq ssh` can open or reuse a persistent SSH login,
but does not start receiving; use a file operation or `persist connect` for that.
On the server:

```sh
syq persist destinations list
syq persist destinations wait laptop --timeout 30
syq persist destinations forget laptop
```

`forget` releases the name assignment while its connection is stopped. For structured
status and approval requests, see [connection status](automation.md#connection-status).

## Isolated script scopes

`syq persist on --ephemeral` prints the path of a new, independent domain.
Pass it to later commands with `--pscope PATH` (`--syq-pscope PATH` for rsync).
For example, on a server with a laptop receiving connection:

```sh
scope=$(syq persist on --ephemeral)
syq persist --pscope "$scope" auth-from @laptop
syq ssh --pscope "$scope" hostB -- hostname
syq cp --pscope "$scope" report --to hostB --as report
syq persist --pscope "$scope" status
syq persist --pscope "$scope" off
```

Fresh domains use default authorization choices and start with receiving off;
they do not copy your default domain's settings or approved connections. To
receive through one on your laptop, run
`syq persist --pscope PATH receive on --name project --connection server`,
choosing a receiving name that is not already connected to that server
account. Use the same `--pscope PATH` for its status, pending requests,
approvals, and remembered-permission management.

A domain does not isolate processes running as the same OS account; see
[Persistent connections](security.md#persistent-connections). Receiving names
are shared by all domains; see
[`persist destinations`](commands/persist.md#syq-persist-destinations).

Scoped `persist off` closes that domain's connections and receiving services,
then removes its settings and remembered permissions; the path cannot be
reused afterwards. Default `persist off` closes default-domain connections but
keeps its saved settings and remembered permissions.

## Setup and recovery

Linux desktop prompts need libnotify 0.7.10 or later and a running notification
service. macOS uses a native dialog. Start receiving from a terminal in your
desktop session. After changing sessions, run `syq persist receive off`, then
enable the profiles you need from a terminal in the new session.
`--notify off` selects terminal approval; `--notify desktop` restores prompts.
`syq persist receive pending` shows complete requests and prompt errors. A
prompt's note that a copy replaces existing files is advisory; destination
entries can change before copying.

Start the connection from your laptop with
`syq persist receive on --connection server`, or use `syq persist connect server`
to keep the current receiving configuration.
Opening a plain SSH session does not enable receiving, and connecting onward
from that server to another host does not carry your laptop's receiving name
with you.

For automatic reconnection to work, your SSH key or agent must be available and
the server's host key must already be trusted; the background service cannot
ask for a password. The server must allow remote Unix socket forwarding, and
OpenSSH 7.8 and later also require permission for remote TCP forwarding:
`AllowStreamLocalForwarding` and `AllowTcpForwarding` must both allow `remote`
or `yes`. When a server refuses forwarding, receiving through it stops. When a
server rejects your login or presents a host key that does not match,
receiving retries with growing waits of up to 10 minutes. In both cases
`syq persist status` shows the failure and its reason, and
`syq persist connect server` tries again at once.

The server command uses the matching helper installed by the receiving
connection. If that helper is missing or does not recognize an option, update
syq on both machines.

## Updating connections

After upgrading syq on both machines, run `syq persist connect server` on the
receiving machine for each server you use, adding `--pscope PATH` for a scoped
domain. The new version replaces the receiving service the older one left
running and keeps your settings. If receiving was disabled, enable it first
with `syq persist receive on`, or enable and connect together with
`syq persist receive on --connection server`. You do not need
`syq persist off` before upgrading; for a scoped domain it would also delete
that domain's settings and remembered permissions.

Requests that were waiting for approval do not carry over: run them again on
the server and approve the new requests. Session permissions (**Allow**) end
with the old receiving connection, so the next account access asks again
unless you chose **Remember**.

Manage receiving with the new version afterwards. An older binary may refuse
settings that a newer one wrote, does not manage scoped domains a newer version
created, and does not enforce receiving-name assignments, so use updated syq
commands on the server and stop older receiving services before switching
versions. Saved names, directories, and limits carry over. Settings using the
former `--approve always` now require approval; choose `--auto-approve-root`
explicitly to enable unattended downloads.
