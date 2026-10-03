# Persistence details

See [`syq persist`](commands/persist.md) for the option list.

For everyday setup, start with [Keep connections open](persistence.md) or
[Use your laptop from a server](receive.md).

## Authorization defaults

On a server, choose the receiving machine for later SSH access:

```sh
syq persist auth-from @laptop
syq persist auth-from ssh --for backup
syq persist auth-from
syq persist auth-from --reset --for backup
syq persist auth-from --reset
```

`@laptop` goes straight to that machine without first trying the server's SSH
credentials. If it is unavailable or refuses the request, the command fails.
New authorization still needs its normal approval; existing account access can
be reused.
`ssh` uses the server's own access and ignores approved account connections.
`auto` first reuses an existing approved account login for the exact typed
endpoint. If more than one receiving name has approved that endpoint, choose
one explicitly. Without an approved login, native copies try SSH and can ask
an available receiving machine after an eligible SSH failure. Other commands
run native SSH once; login and command failures never trigger a retry.

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
Selecting `@NAME` lets a command request account access when it has no approved
connection. `persist connect --auth-from @NAME` can prepare that access in advance. Custom `--rsh` routes, explicit persistence
scopes, copies to receiving names, and object storage keep their own
authentication. The setting works independently of `persist on`
and `off`. It is saved in `auth-from.json` alongside `persistence.json`; older
syq versions ignore it. If it is unreadable or has an unknown format, repair the
file or pass `--auth-from` explicitly for that command.

## Approved account connections

Commands selecting `@NAME` request an approved account connection when needed.
`syq persist connect HOST --auth-from @NAME` prepares the same connection in
advance. Neither operation enables ordinary persistence or receiving on `HOST`.
Helper and `--pscope` overrides do not apply to `persist connect` in this mode;
`--timeout` is for native receiving setup and is rejected with `--auth-from`.
Readiness means the approved SSH connection accepts sessions.

`persist status --json` adds an `authorized_ssh` array alongside the usual
`connections`. Each entry contains the authorizer name, requested and resolved
endpoints, `control` socket path, and `connected` state. A matching receiving
name, login, typed host/alias, and port selects the same approved login.
A closed connection can request another login under the current session or
remembered permission. A failure after execution starts ends that command
without retrying it.

Copies can reuse the login with `auto` or the matching `@NAME`, including SSH
data in either direction with `--no-tcp`. Copies between this machine and one
server use full account access without a per-copy grant; asking for a receiver
receipt selects per-copy authorization instead. Direct copies between two other
servers can use approved connections to both endpoints and give the source only
[this copy's destination access](remote-reference.md#approved-account-copies).
An explicit `--coordinate-at local` can also reuse account connections for both
endpoints. Custom shell routes, explicit persistence scopes, and detached copies
keep their separate connection requirements.
Without an approved login, `@NAME` requests account access. With `auto`,
eligible native copies can use restricted per-copy approval after a native SSH
failure.

`rsync`, `rm`, `map`, `clean-partials`, and descriptor copies also request or
reuse account access selected through `@NAME`. The laptop prompt grants the
account's authority, not permission for only the displayed operation. Remote
path completion uses existing approval and never prompts for access.

SSH data through one approved account connection shares the server's session
limit with its control connection and any other tools using that login. Leave
room for the control session when choosing a worker ceiling with
`--resource-limits workers=N`. A server configured with `MaxSessions 1` can use
TCP data, but cannot open the concurrent SSH data workers needed by larger
copies or byte streams. Syq does not bypass the selected approval with another
SSH login when the session limit is reached.

`syq persist ssh-config HOST [--auth-from auto|ssh|@NAME]` prints a standalone
OpenSSH configuration for one existing approved login. Use it with `ssh`,
`scp`, or `sftp` through `-F FILE`, or with Git and rsync's SSH command option.
The endpoint must match the user, host spelling, and port used to open
the approved connection; the configuration then supplies the laptop-resolved host,
account, and port. It never requests approval or opens a login. Native-only
`ssh` selection cannot export approved account access.

The exported configuration is a snapshot. Its socket is bound to the resolved
host, account, and port; changing those options does not select the approved
socket. Missing or closed connections fail without attempting other
authentication. Export again after reconnecting. The output contains no private
key; syq writes only a temporary socket alias inside the connection's scope.

Connection records live in syq's temporary runtime directory, separately from
ordinary SSH connections. Existing records remain readable; new session state
does not change saved persistence settings. Use a current syq client to close
these connections: older clients may not manage account connections opened
while ordinary persistence is off.

Copies between two other servers need the trusted host information saved with
the approved connection. A connection opened by a build that did not save it
still works for ordinary commands; reconnect it to use this copy route.

## Account permissions

The laptop asks before granting access from a source server account to a
destination account. **Allow** lasts for its current receiving connection to
the source. **Remember** saves that permission for later connections through
the same profile. Both accounts, resolved endpoints, and trusted host keys are
part of the permission; changing them requires approval again. Permission is
shared by processes running as the requesting account.

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
connections may continue. Session permission ends when the laptop's receiving
connection closes. Stopping receiving prevents further authorization through
that connection; [account access](security.md#ssh-account-access) explains its limits.

Remembered permissions are stored on the laptop separately from receiving and
persistence settings. Older versions leave them untouched and do not use them.
An unreadable or unknown permission format reports its path and requires repair
or a matching version. New account requests need a receiving helper that
supports account approval; update syq on the laptop and reconnect if necessary.

## Names and profiles

Give a project its own receiving name and directory:

```sh
mkdir -p ~/work/project
syq persist receive on --name laptop --cwd ~
syq persist receive on --name project --root ~/work/project
syq persist connect server
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
omitted options keep their saved values.
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

Updating, stopping, or removing a profile cancels only that profile's copies,
commands, and pending approvals. Other profiles keep working. `receive off`
without a name stops all profiles; `receive on` enables the first profile, and
`receive on --name NAME` enables another. Removing the first profile makes the
next saved profile the default. The last profile can be disabled but cannot be
removed. `pending`, `approve`, and `deny` work across all profiles, and
`pending` names the receiving profile of each request. Without `--name`,
`receive wait` waits for every enabled profile on that server.

<a id="choose-allowed-servers"></a>

### Choose allowed connections

To give one server account an inbox for downloads that do not need approval:

```sh
mkdir -p ~/Downloads/work
syq persist receive on --name work-inbox --connection work \
  --auto-approve-root ~/Downloads/work
syq persist connect work
```

On `work`, use `syq cp results --to @work-inbox`. Other connections cannot
use that profile. Your general profile can still ask for approval on every
download.

Profiles default to all SSH connections. `receive on --name NAME --connection ENDPOINT`
restricts a profile to the exact SSH destination used on the receiving machine.
Use the endpoint shown by `persist status`: for example `work`, `alice@work`,
or `alice@work:2222`. Matching includes an explicitly selected user and port;
it does not expand SSH aliases or equate omitted ports with explicit ports.
An alias uses the account and host configured for it in your local SSH settings.
The server cannot select its own identity for this check. Changing your local
SSH configuration can change which account an allowed alias reaches.

Repeat `--connection` to supply several endpoints. Each supplied list replaces
the saved list; `--all-connections` clears the restriction. Changes apply to existing
persistent connections too. `receive wait HOST` waits only for profiles allowed
on HOST.

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

Syq generates one receiver key per local account, shared by receiving profiles
and syq versions. It lives in `~/.syq-receiver-identity/identity_ed25519` and is
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

Connections have no idle expiry. Receiving reconnects after interruptions;
other SSH logins reopen on their next use. Syq installs no login service, so
connect again after reboot. Copies are not queued or retried automatically.

Use `syq persist receive wait server --timeout 30` to wait without starting or
restarting a connection. On the server:

```sh
syq persist destinations list
syq persist destinations wait laptop --timeout 30
syq persist destinations forget laptop
```

`forget` releases the name assignment while its connection is stopped. For structured
status and approval requests, see [connection status](automation.md#connection-status).

## Isolated script scopes

`syq persist on --ephemeral` prints a scope path. Pass it as `--pscope PATH`
to `syq persist connect server` and subsequent copy commands, then close it
with `syq persist off --pscope PATH`. This does not change your user setting.

These scopes reuse SSH logins only. They do not enable receiving, authorization
through your machine, or commands on it. Idle connections close within ten
minutes, including helper sessions. Explicitly closing the scope ends reuse
immediately. For return copies or commands, use persistence without `--pscope`.

## Setup and recovery

Linux desktop prompts need libnotify 0.7.10 or later and a running notification
service. macOS uses a native dialog. Start receiving from a terminal in your
desktop session. After changing sessions, run `syq persist receive off`, then
enable the profiles you need from a terminal in the new session.

`syq persist receive pending` shows complete requests and prompt errors.
A prompt's note that a copy replaces existing files is advisory; destination
entries can change before copying.
`--notify off` selects terminal approval; `--notify desktop` restores prompts.

Start the connection from your laptop with `syq persist connect server`.
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
After upgrading both machines, run `syq persist connect server` for each server.

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
