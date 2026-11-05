# Persistence details

See [`syq persist`](commands/persist.md) for the option list.

For everyday setup, start with [Keep connections open](persistence.md) or
[Use your laptop from a server](receive.md).

Persistence commands use the default domain unless you select an isolated one
with `--pscope PATH`, before or after any `persist` subcommand. Each domain has
its own connections, authorization defaults, receiving profiles, and
remembered account permissions. See [Isolated script scopes](#isolated-script-scopes)
for creation, lifetime, and cleanup.

## Authorization defaults

On a server, choose the authorization provider for later SSH access:

```sh
syq persist auth-from @laptop
# Or use an ordinary SSH provider:
syq persist auth-from alice@provider:2222
syq persist auth-from ssh --for backup
syq persist auth-from
syq persist auth-from --reset --for backup
syq persist auth-from --reset
```

`@laptop` goes straight to that receiving machine without first trying the
server's SSH credentials, and the command fails if it is unavailable or
refuses. An ordinary SSH endpoint such as `alice@provider:2222` instead
connects to that account as an [authorization provider](receive.md#use-an-ssh-authorization-provider).
Either one reuses existing account access, and lets a command request access
when it has none. `ssh` uses the server's own access and ignores approved
account connections. `auto`, the default, also starts with native SSH; an
eligible copy can then ask an available receiving machine after an SSH failure
(see [Authorization selection](remote-reference.md#authorization-selection)),
while other commands run native SSH once.

A `--for HOST` override wins over the default. It matches the exact hostname
or SSH alias typed in the command, for every login and port, without expanding
aliases; `--for` takes no login or port. `SYQ_AUTH_FROM` in the environment
wins over both saved settings, for one shell or script; see
[Environment](environment.md#choose-authorization-through-the-environment).
An explicit `--auth-from` (`--syq-auth-from` for `syq rsync`), including `auto`,
wins over all of them.
`--reset --for HOST` removes one override; `--reset` restores the default to
`auto` while keeping host overrides. Omit the value to show saved choices, or
add `--for HOST` to show that host's effective choice. Both also show when
`SYQ_AUTH_FROM` overrides the saved choices.

Defaults apply to `syq ssh`, copies using approved account connections, and the
SSH endpoints of `rsync`, `rm`, `map`, and `clean-partials`. A copy explicitly
using `--coordinate-at local` selects access separately for each endpoint.
Custom `--rsh` routes, copies to receiving names, and object storage keep their
own authentication. The setting works whether or not native SSH persistence is
enabled.

Choices are saved in `auth-from.json` in the selected domain; the default
domain keeps it alongside `persistence.json`. If the file is invalid or from an
unsupported version, commands report its path without changing it: repair it,
or pass `--auth-from` (`--syq-auth-from` for rsync) to bypass it for one
command. Setting or resetting a choice keeps the other saved choices, so it
cannot repair an unreadable file; to discard all saved choices, remove the
file yourself.

## Approved account connections

Commands selecting `@NAME` or an ordinary SSH provider request an approved
account connection when needed.
`syq persist connect HOST --auth-from PROVIDER` prepares the same connection in
advance. Neither operation enables ordinary persistence or receiving on `HOST`.
`--pscope` selects the domain that owns the connection. Helper overrides do not
apply in this mode, and `--timeout`, which is for native receiving setup, is
rejected when account authorization is selected.

An ordinary SSH provider uses its default persistence domain and first
configured receiving profile, which must be enabled. A local `--pscope` does
not select a domain on the provider.

The requesting machine's SSH configuration determines the destination account,
host, port, identity selection, and route. `persist status --json` lists these
connections in [`authorized_ssh`](automation.md#connection-status).

Later commands that select the same provider reuse the approved connection,
including copies, SSH data with `--no-tcp`, `rsync`, `rm`, `map`,
`clean-partials`, and descriptor copies; for copies between two other servers,
see [Approved account copies](remote-reference.md#approved-account-copies). The
prompt grants the account's authority, not permission for only the displayed
operation. Remote path completion reuses a matching connection, but never
contacts the provider, requests approval, or opens a connection.

When TCP is unavailable or you use `--no-tcp`, data workers open their own SSH
connections under the same account permission. Your authorization provider
must remain available, but workers never request another syq approval:
missing or withdrawn permission stops the copy. An agent that requires
confirmation or a hardware-key touch can ask for each connection.

After a remote operation or path completion, syq can keep a helper ready on the
connection for the next one. It occupies one SSH session, so with the server's
`MaxSessions 1`, a shell or another tool sharing that connection has no session
left.

`syq persist ssh-config HOST [--auth-from auto|ssh|@NAME|HOST]` prints a
standalone OpenSSH configuration for one existing approved login. Use it with
`ssh`, `scp`, or `sftp` through `-F FILE`, or with Git and rsync's SSH command
option. The endpoint must match the user, host spelling, and port used to open
the approved connection. The command never requests approval or opens a login,
and native-only `ssh` selection cannot export approved access. Once its
connection closes, it fails without trying other authentication, so export it
again after reconnecting. It contains no private key.

## Account permissions

The laptop asks before granting access from a source server account to a
destination account. **Allow** lasts for its current receiving connection to
the source. **Remember** saves that permission for later connections through
the same profile. Both accounts, resolved endpoints, and trusted host keys are
part of the permission; changing them requires approval again. Permission is
shared by processes running as the requesting account.

With an ordinary SSH provider, see
[provider trust](security.md#ordinary-ssh-authorization-providers) for what
**Allow** and **Remember** cover.

For a pending account request, use the desktop controls or decide locally:

```sh
syq persist receive approve REQUEST_ID
syq persist receive approve REQUEST_ID --remember
syq persist receive deny REQUEST_ID
syq persist receive permissions list
syq persist receive permissions list --json
syq persist receive permissions remove PERMISSION_ID
```

`--remember` is accepted only for account-access requests. Removing a
remembered permission makes future authentication requests ask again. To close
syq's owned connections, run `syq persist off` on the requesting machine, with
`--pscope PATH` if they belong to an explicit domain. Run
`syq persist receive off` on the authorizing machine to end session permission
and prevent further authorization, selecting its domain with `--pscope` when
needed. See [account access](security.md#ssh-account-access) for what these
actions do not stop.

Remembered permissions belong to the authorizing laptop's selected domain and
are stored separately from receiving settings. A new domain on that laptop does
not inherit them, and creating a domain on the requesting server does not
revoke permissions already granted to that server account.

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
are shared too: `persist destinations list`, `wait`, and `forget` work across
the account even with `--pscope`, so forgetting an offline name releases it
for the whole account.

Scoped `persist off` closes that domain's connections and receiving services,
then removes its settings and remembered permissions; the path cannot be
reused afterwards. Default `persist off` closes default-domain connections but
keeps its saved settings and remembered permissions. Idle connection expiry
alone removes nothing, but a scope in a temporary or runtime directory, with
its remembered permissions, can disappear when the system cleans that
directory, including at reboot. A scope in a durable location survives,
though its SSH connections must be reopened.

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
syq on both machines and reconnect from your laptop.

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
