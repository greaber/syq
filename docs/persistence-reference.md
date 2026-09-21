# Persistence details

See [`syq persist`](commands/persist.md) for the option list.

For everyday setup, start with [Keep connections open](persistence.md) or
[Use your laptop from a server](receive.md).

## Names and profiles

Give different receiving locations their own names:

```sh
syq persist receive on --name laptop --cwd ~
syq persist receive on --name project --root ~/work/project
syq persist connect server
```

Both names work from the same server account: `syq cp results --to @project`
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
removed. `pending`, `approve`, and `deny` work across all profiles; prompts name
the receiving profile. Without `--name`, `receive wait` waits for every enabled
profile on that server.

### Choose allowed servers

Profiles default to all connected servers. `receive on --name NAME --server HOST`
restricts a profile to the exact SSH destination used on the receiving machine.
Use the endpoint shown by `persist status`: for example `work`, `alice@work`,
or `alice@work:2222`. Matching includes an explicitly selected user and port;
it does not expand SSH aliases or equate omitted ports with explicit ports.
An alias uses the account and host configured for it in your local SSH settings.
The server cannot select its own identity for this check. Changing your local
SSH configuration can change which account an allowed alias reaches.

Repeat `--server` to supply several destinations. Each supplied list replaces
the saved list; `--all-servers` clears the restriction. Changes apply to existing
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
resume, mappings, `--preserve=permissions`, and the
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
Overwrite warnings are advisory; destination entries can change before copying.
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
