# Persistence details

See [`syq persist`](commands/persist.md) for the option list.

For everyday setup, start with [Keep connections open](persistence.md) or
[Use your laptop from a server](receive.md).

Persistence commands use the default domain unless you select an isolated one
with `--pscope PATH`. Each domain has its own connections, authorization defaults,
receiving profiles, and remembered account permissions. The option works before
or after any `persist` subcommand. See [Isolated script scopes](#isolated-script-scopes)
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

`@laptop` goes straight to that machine without first trying the server's SSH
credentials. If it is unavailable or refuses the request, the command fails.
New authorization still needs its normal approval; existing account access can
be reused. An ordinary SSH endpoint such as `alice@provider:2222` instead
connects to that account as an [authorization provider](receive.md#use-an-ssh-authorization-provider).
`ssh` uses the server's own access and ignores approved account connections.
`auto` starts with native SSH regardless of existing approved account connections.
Eligible native copies can ask an available receiving machine after an SSH
failure. Other commands run native SSH once; login and command failures never
trigger a retry. Save an authorizer or select it explicitly to use approved
account access.

A `--for HOST` override wins over the default. Matching uses the exact hostname
or SSH alias typed in the command, for every login and port; aliases are
not expanded through SSH configuration or DNS. `--for` takes no login or port.
An explicit `--auth-from` (`--syq-auth-from` for `syq rsync`), including `auto`,
wins over both saved settings.
`--reset --for HOST` removes one override; `--reset` restores the default to
`auto` while keeping host overrides. Omit the value to show saved choices, or
add `--for HOST` to show that host's effective choice.

Defaults apply to `syq ssh`, copies using approved account connections, and the
SSH endpoints of `rsync`, `rm`, `map`, and `clean-partials`. A copy explicitly
using `--coordinate-at local` selects access separately for each endpoint.
Selecting `@NAME` or an ordinary provider endpoint lets a command request
account access when it has no approved connection.
`persist connect HOST --auth-from PROVIDER` can prepare that access in advance.
Custom `--rsh` routes, copies to receiving names, and object storage keep their
own authentication. An explicit scope uses its own saved choices.
The setting works independently of whether native SSH persistence is enabled.
It is saved in `auth-from.json` in the selected domain; the default domain keeps
it alongside `persistence.json`. Older syq versions ignore it. Unversioned files
and `"version": 1` are supported; edits preserve additional top-level fields and
do not add a version to unversioned files. Invalid choices and unsupported
versions report the file's path without changing it. Repair the file or pass
`--auth-from` explicitly (`--syq-auth-from` for rsync) to bypass it for one command.
Setting or resetting a choice preserves the other saved choices, so neither can
repair an unreadable file. To discard all saved choices, remove that file yourself. The configuration
directory may be a symlink to a directory you own; `auth-from.json` itself must
be a regular file, not a symlink.

## Approved account connections

Commands selecting `@NAME` or an ordinary SSH provider request an approved
account connection when needed.
`syq persist connect HOST --auth-from PROVIDER` prepares the same connection in
advance. Neither operation enables ordinary persistence or receiving on `HOST`.
`--pscope` selects the domain that owns the connection. Helper overrides do not
apply in this mode; `--timeout` is for native receiving setup and is rejected
when account authorization is selected explicitly or through a saved choice.
Readiness means the approved SSH connection accepts sessions.

An ordinary SSH provider uses its default persistence domain and first
configured receiving profile, which must be enabled. There is no selector for
another remote profile or domain. A local `--pscope` selects this machine's
preferences, provider connections, and approved destination connections; it
does not select a domain on the provider. Destination aliases use the
requesting machine's SSH configuration.

`persist status --json` adds an `authorized_ssh` array alongside the usual
`connections`. Each entry contains the `authorizer`, requested and resolved
endpoints, `control` socket path, and `connected` state. `authorizer` is a name
string for `@NAME`, or an object containing an `ssh` endpoint for an ordinary
SSH provider. If an individual account record cannot be inspected, the output
keeps the readable entries in `authorized_ssh` and lists the inspection errors
in `authorized_ssh_errors`. Status then exits unsuccessfully; damaged records
do not hide healthy connections.

The requesting machine's SSH configuration determines the destination account,
host, port, identity selection, and route. Syq resolves that configuration before
looking for a reusable connection. Changing an alias therefore affects the next
command whether or not a connection already exists; existing sessions keep
their original destination. Different configurations can leave multiple
connections visible in status.

The provider independently checks trusted host keys and approves the selected
account. Repeated commands reuse that authorization and connection without a
provider round trip to resolve the destination. Completion checks local SSH
configuration within a short deadline and reuses a matching connection; it
never contacts the provider, requests approval, or opens a connection. Slow
configuration lookups yield no remote path suggestions.
A closed connection can request another login under the current session or
remembered permission. A failure after execution starts ends that command
without retrying it.

Copies selecting the matching provider, explicitly or through a saved choice,
can reuse the login, including SSH data in either direction with `--no-tcp`.
Copies between this machine and one server use full account access without a
per-copy grant. `--receiver-receipt` applies only to direct copies between two
remote endpoints. Direct copies between two other servers can use approved
connections to both endpoints and give the source only
[this copy's destination access](remote-reference.md#approved-account-copies).
An explicit `--coordinate-at local` can also reuse account connections for both
endpoints. An explicit scope selects account connections in that domain.
Custom shell routes and detached copies keep their separate connection requirements.
Without an approved login, the selected provider requests account access. With `auto`,
eligible native copies can use restricted per-copy approval after a native SSH
failure.

`rsync`, `rm`, `map`, `clean-partials`, and descriptor copies also request or
reuse account access selected through an authorization provider. Its prompt
grants the account's authority, not permission for only the displayed operation. Remote
path completion uses existing approval and never prompts for access.

When TCP is unavailable or you use `--no-tcp`, data workers open independent
SSH connections under the same account permission. They keep the selected
account, trusted host keys, and route. Your authorization provider must remain
available, but workers never request another syq approval: missing or withdrawn
permission stops the copy. An agent that requires confirmation or a hardware-key
touch can require it for each connection. TCP workers do not need these extra
SSH authentications.

As with ordinary persistence, syq can prepare a helper after a remote operation
or path completion, keeping it ready for the next operation. A warm completion
lookup uses one network round trip for names and metadata.
That ready helper occupies one session on the shared connection; shells and
other tools using the same connection still share its server session limit.
With `MaxSessions 1`, a ready helper leaves no session slot for a shell or
another tool on that connection. Independent SSH data workers do not occupy
sessions on that shared connection.

`syq persist ssh-config HOST [--auth-from auto|ssh|@NAME|HOST]` prints a standalone
OpenSSH configuration for one existing approved login. Use it with `ssh`,
`scp`, or `sftp` through `-F FILE`, or with Git and rsync's SSH command option.
The endpoint must match the user, host spelling, and port used to open
the approved connection; the configuration then supplies the host, account,
and port selected when that connection was opened. It never requests approval or opens a login. Native-only
`ssh` selection cannot export approved account access.

The exported configuration is a snapshot. Its socket is bound to the resolved
host, account, and port; changing those options does not select the approved
socket. Missing or closed connections fail without attempting other
authentication. Export again after reconnecting. The output contains no private
key; syq writes only a temporary socket alias inside the connection's scope.

Connection records and resolution metadata live in the selected domain's
runtime directory, separately from ordinary SSH connections.

## Account permissions

The laptop asks before granting access from a source server account to a
destination account. **Allow** lasts for its current receiving connection to
the source. **Remember** saves that permission for later connections through
the same profile. Both accounts, resolved endpoints, and trusted host keys are
part of the permission; changing them requires approval again. Permission is
shared by processes running as the requesting account.

With an ordinary SSH provider, **Allow** lasts for the current connection to
that provider account. **Remember** permits later logins to the provider to
authorize the destination through the same receiving profile. Syq does not
verify which source machine opened that login; see
[provider trust](security.md#ordinary-ssh-authorization-providers).

For a pending account request, use the desktop controls or decide locally:

```sh
syq persist receive approve REQUEST_ID
syq persist receive approve REQUEST_ID --remember
syq persist receive deny REQUEST_ID
syq persist receive permissions list
syq persist receive permissions list --json
syq persist receive permissions remove PERMISSION_ID
```

`--remember` is accepted only for account-access requests. Removing a remembered
permission makes future authentication requests ask again. Existing authenticated
connections may continue, including new commands using an existing connection.
To close syq's owned connections, run `syq persist off` on the requesting machine,
with `--pscope PATH` if they belong to an explicit domain. Run
`syq persist receive off` on the authorizing machine to end session permission
and prevent further authorization, selecting its domain with `--pscope` when needed.
Neither action guarantees termination of already running remote commands or
detached processes; stop those on the destination when necessary. See
[account access](security.md#ssh-account-access) for the limits of account approval.

Remembered permissions belong to the authorizing laptop's selected domain and
are stored separately from receiving settings. They are not inherited by a new
domain on that laptop. Creating a domain on the requesting server does not revoke
permissions already granted to that server account by the laptop. Older versions
leave the default domain's permission file untouched and do not use it.
An unreadable or unknown permission format reports its path and requires repair
or a matching version. New account requests need a receiving helper that
supports account approval; update syq on the laptop and reconnect if necessary.

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
allowed server.
New profiles start with the usual defaults, including asking for approval; they
do not inherit another profile's trust or confinement settings. Up to 32 profiles
can be saved.

### Change or stop a profile

`receive on --name NAME` creates a profile or updates that name's settings;
omitted options keep their saved values. It enables persistence in the selected
domain and applies the profile to allowed active and future connections. Only
endpoints supplied with `--connection` in this invocation are connected explicitly; the
command waits for receiving to become ready on those endpoints. If one fails,
the settings stay saved and healthy connections keep running, but the command
exits unsuccessfully. Without `--connection`, saved endpoints remain the
profile's allowed connections and are not dialed. Use `persist connect HOST`
to start one, or `receive wait HOST` to wait for readiness without starting it.
Without `--name`, `receive on` updates the first saved profile, shown first by
`receive status`. The initial hostname profile becomes a saved profile when
persistence first connects; adding a new name then keeps that original profile.
If no preferences have been saved yet, the first explicitly chosen name replaces
the implicit hostname default.

```sh
syq persist receive status
syq persist receive status --name project
syq persist receive off --name project
syq persist receive on --name project
syq persist receive remove project
syq persist receive wait server --name laptop --timeout 30
```

Changing a profile's access settings, stopping it, or removing it cancels only
that profile's copies, commands, and pending approvals. Changing `--notify` or
repeating `receive on` with unchanged settings preserves them. Other profiles
keep working. `receive off`
without a name stops all profiles; `receive on` enables the first profile, and
`receive on --name NAME` enables another. Removing the first profile makes the
next saved profile the default. The last profile can be disabled but cannot be
removed. `pending`, `approve`, and `deny` work across the selected domain's profiles,
and `pending` names the receiving profile of each request. Without `--name`,
`receive wait` waits for every enabled profile on that server.

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

Profiles default to all SSH connections in their domain.
`receive on --name NAME --connection ENDPOINT` restricts a profile to the exact SSH destination used on the receiving machine.
Use the endpoint shown by `persist status`: for example `work`, `alice@work`,
or `alice@work:2222`. Matching includes an explicitly selected user and port;
it does not expand SSH aliases or equate omitted ports with explicit ports.
An alias uses the account and host configured for it in your local SSH settings.
The server cannot select its own identity for this check. Changing your local
SSH configuration can change which account an allowed alias reaches.

Repeat `--connection` to supply several endpoints. Each supplied list replaces
the saved list and connects the supplied endpoints. Omitting `--connection`
keeps the restriction without connecting dormant endpoints.
`--all-connections` clears the restriction and starts receiving on active
connections; it does not discover additional servers. Changes apply to existing
persistent connections too. `receive wait HOST` waits only for profiles allowed
on HOST in the selected domain.

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
persistence domains, and syq versions. It lives in `~/.syq-receiver-identity/identity_ed25519` and is
independent of your SSH login keys and profile settings. Keep that directory
across upgrades; include it in private backups if you want to restore the same
identity. Losing it requires releasing the old names on each server. Copying it
to another machine gives that machine the same receiver identity. If the old
connection is still responsive, the replacement is rejected; use different
profile names to receive on both machines at once. An unresponsive connection
must time out before its name can reconnect.

## Directories

The three directory settings are independent:

| Setting | Purpose | Clear it with |
|---|---|---|
| `--cwd DIR` | Starting directory for relative paths | `--auto-cwd` |
| `--root DIR` | Hard boundary for downloads, even with approval | `--no-root` |
| `--auto-approve-root DIR` | Downloads confined here skip approval | `--no-auto-approve-root` |

Each requires an existing directory with a UTF-8 path; neither root can be `/`.
An explicit cwd must be inside the hard root, if set. Otherwise the starting
directory is the hard root, the automatic approval root, or your home directory,
in that order. Status reports the effective cwd and whether it is explicit.

Downloads outside the automatic approval root ask for approval, provided they
stay within the hard root if one is set. Symlinks cannot grant automatic writes
outside the approval root. Replacing the automatic root directory itself requires approval, and is
prohibited when it is also the hard root. These roots do not restrict approved
commands or the destinations of approved copies to other servers.

Invalid settings leave the saved configuration unchanged. If a saved directory
disappears, you can still inspect, disable, or reconfigure the profile.
Filenames inside it may use normal Unix filename bytes.

## Copy limits

Named copies use encrypted TCP workers initiated by the receiving machine,
falling back to SSH when TCP is unreachable. `--no-tcp` forces SSH;
`--tcp-ports` selects the listening port range on the sending server.
The receiving connection must stay open throughout the copy.

Copies support directories, symlinks, modification times, filters, hashing,
resume, mappings, `--copy-metadata=permissions`, and the
[overwrite policies](reference.md#choose-which-existing-files-to-update).
Ownership preservation, special-file preservation, and `--inplace` are
unsupported. Timestamp comparisons trust the source's reported modification
times.

Each copy is limited to 100 GiB and one million touched entries by default.
Change these ceilings with `syq persist receive on --max-bytes 20G --max-entries 100000`.
Lower limits requested by the sender also apply. Limits are per copy; repeated
copies can fill the disk. Copies support at most 128 workers each.

Pruning is disabled unless the laptop sets a positive `--max-delete`.
A sending `--prune` command must also supply its own `--max-delete` ceiling,
no higher than the laptop's. Validation failures leave the copy unstarted.
Errors during copying fail visibly and may leave partial files for retry.
The sender verifies a signed receipt before reporting success.

## Connection lifetime and waits

`persist on` enables persistence for subsequent syq SSH connections.
`persist connect server` enables it and connects immediately. With receiving
enabled, it waits until receiving is ready. `--timeout 30` limits that wait
after SSH and helper setup, not authentication or installation. Failure leaves
persistence enabled; a healthy connection is reused without cancelling requests.

Default-domain connections have no idle expiry. In an explicit domain, idle
SSH connections expire after five minutes; native helper sessions can extend
the total idle lifetime to ten minutes. An enabled receiving service keeps its
connection active until you stop it. Receiving reconnects after interruptions;
other SSH logins reopen on their next use. Syq installs no login service, so
connect again after reboot. Copies are not queued or retried automatically.

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
`syq persist --pscope PATH receive on --name project --connection server`.
Choose a receiving name that is not already connected to that server account.
Use the same `--pscope PATH` for its status, pending requests, approvals, and
remembered-permission management.

SSH configuration, keys, agents, and the local account's receiving identity
remain shared. Names advertised by other receiving machines are also available
regardless of the requesting domain. `persist destinations list`, `wait`, and
`forget` use this shared registry even with `--pscope`: forgetting an offline name
releases it for the whole account. A domain separates syq's saved policy and
owned connections; it does not isolate processes running as the same OS account.

Scoped `persist off` closes that domain's connections and receiving services,
then removes its settings and remembered permissions. The path cannot be reused
after cleanup; create a new domain. Other domains are unchanged. Default
`persist off` closes default-domain connections but preserves its saved settings
and remembered permissions. Idle connection expiry alone does not remove a
domain's settings. Temporary scopes and their remembered permissions can also
be lost when the system cleans its runtime or temporary directory, including at
reboot. A scope stored in a durable location may survive, but its SSH connections
must be reopened.

## Setup and recovery

Linux desktop prompts need libnotify 0.7.10 or later and a running notification
service. macOS uses a native dialog. Start receiving from a terminal in your
desktop session. After changing sessions, run `syq persist receive off`, then
enable the profiles you need from a terminal in the new session.

`syq persist receive pending` shows complete requests and prompt errors.
A prompt's note that a copy replaces existing files is advisory; destination
entries can change before copying.
`--notify off` selects terminal approval; `--notify desktop` restores prompts.

Start the connection from your laptop with
`syq persist receive on --connection server`, or use `syq persist connect server`
to keep the current receiving configuration.
Opening a plain SSH session does not enable receiving, and connecting onward
from that server to another host does not carry your laptop's receiving name
with you.

For automatic reconnection to work, your SSH key or agent must be available and
the server's host key must already be trusted. The background service cannot
ask for a password. The server must allow remote Unix socket forwarding;
OpenSSH 9.2 also requires permission for remote TCP forwarding.

The server command uses the matching helper installed by the receiving
connection. If that helper is missing or does not recognize an option, update
syq on both machines and reconnect from your laptop.

## Updating connections

Before upgrading, run `syq persist off` on the receiving machine to stop its
background services. Replacing the executable alone does not update running
services. Close script scopes with `syq persist off --pscope PATH` too.
After upgrading both machines, run `syq persist connect server` for each server
you want to use. If receiving was disabled, enable it first with
`syq persist receive on`, or enable and connect together with
`syq persist receive on --connection server`.

Use the current binary to close explicit domains. An older binary may stop their
services but refuse to remove newer settings; rerun scoped `off` with the current
binary to finish cleanup. Older global receiving commands do not manage newly
created domains. If you enable receiving in a scope created by an older version,
avoid using that older version's global receiving commands at the same time.

Saved names, directories, and limits carry over. Existing working directories
remain explicitly selected. Settings using the former `--approve always` now
require approval; choose `--auto-approve-root` explicitly to enable unattended
downloads. Older binaries reject the updated preferences; use the newer binary
to manage receiving.

Connections created before persistent receiver identities remain discoverable.
Their names become assigned when an updated receiving machine reconnects.
Updated commands verify assigned names even when their connection uses an older
helper; a receiver without a matching identity is rejected. Older binaries do
not enforce these assignments, so use updated syq commands on the server and
stop older receiving services before switching versions. The receiver key and
assignments are independent of the helper build and survive later upgrades.
