# Persistence details

For everyday setup, start with [Send files home from a server](receive.md).

## Names and profiles

Give different receiving locations their own names:

```sh
syq persist receive on --name laptop --cwd ~
syq persist receive on --name project --root ~/work/project
syq persist connect server
```

Both names work from the same server account: `syq cp results --to @project`
and `syq cp report.pdf --to @laptop`. Each profile has its own directory, copy
root, limits, approval policy, and background connection to each connected server.
New profiles start with the usual defaults, including asking for approval; they
do not inherit another profile's trust or confinement settings. Up to 32 profiles
can be saved.

`receive on --name NAME` creates a profile or updates that name's settings.
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

Names belong to a server account. Different laptops can receive through the same
account under different names. If a name already has a live connection, another
client's attempt is rejected without disturbing the existing connection. Other
profiles remain usable. Choose a different name, or stop the original connection
and run `syq persist connect server` on the waiting client to retry.

## Directories

`--cwd` chooses the starting directory; `--root` also contains copies within it.
Both require an existing directory with a UTF-8 path. Invalid settings leave the
saved configuration unchanged. If a saved directory disappears, you can still
inspect, disable, or reconfigure the profile. Filenames inside it may use normal
Unix filename bytes.

## Copy limits

Copies support directories, symlinks, modification times, filters, hashing,
resume, mappings, `--preserve=permissions`, `--verify-only`, and the
[overwrite policies](reference.md#choose-which-existing-files-to-update).
Ownership and special-file preservation, `--inplace`, and `--min-size` are
unsupported. Timestamp comparisons trust the source's reported modification
times.

Each copy is limited to 100 GiB and one million touched entries by default.
Change these ceilings with `syq persist receive on --max-bytes 20G --max-entries 100000`.
Lower limits requested by the sender also apply. Limits are per copy; repeated
copies can fill the disk. Copies support at most 32 workers each.

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
A return copy must finish within seven days of approval.

Use `syq persist receive wait server --timeout 30` to wait without starting or
restarting a connection. On the server:

```sh
syq persist destinations list
syq persist destinations wait laptop --timeout 30
syq persist destinations forget laptop
```

`forget` removes a stale entry while its connection is stopped. For structured
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

Saved names, directories, and limits carry over. Settings predating approval
prompts require approval after upgrading. Older binaries may not read updated
preferences; use the newer binary to manage receiving.
