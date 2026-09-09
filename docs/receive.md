# Send files home from a server

Inspect files on your server, then copy them to your laptop from the same shell.
The laptop opens and maintains the connection. It needs no SSH server, public
address, or incoming network port.

With syq installed on both machines, connect from your laptop:

```sh
syq persist connect server
```

This enables persistence and waits until receiving is ready. You can run it
again to reuse a working connection or recover a stopped service. Alternatively,
`syq persist on` starts receiving with later ordinary syq connections.

When syq connects to an SSH server, it also starts a background return
connection. The default destination name is your laptop's short hostname,
and files go into your home directory. No receiving terminal needs to stay open.
To choose a name and a different starting directory:

```sh
mkdir -p ~/Downloads/server
syq persist receive on --name laptop --cwd ~/Downloads/server
syq persist connect server
```

On the server, use the name from any shell, including an existing tmux session:

```sh
ls -lh results
syq cp results --to laptop
syq cp report.pdf --to laptop --as reports/latest.pdf
```

Each incoming copy waits for approval **on your laptop** before it can inspect
or change destination entries. Review the destination and permissions, then
choose **Allow once** or **Deny**. Use **Details** on macOS or
`syq persist receive pending` in a local terminal to see the complete request.
Approving a copy trusts the server to supply its contents.

You can also [run commands on the receiving machine](exec.md), with separate
local approval, to build a project there or open a copied artifact.

## Multiple receiving profiles

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

## Approving copies

Desktop approval needs a running notification service on Linux (libnotify
0.7.10 or later); macOS uses a native dialog. Start receiving from a terminal
in your desktop session. After changing sessions, run `syq persist receive off`,
then enable the profiles you need from a terminal in the new session.

An overwrite warning means the destination exists or could not be checked.
The check is only advisory: files can change before the copy runs. Review
**Details** or `persist receive pending` for the full permissions and limits,
especially before allowing overwrites or deletion.

You can also decide from any local terminal:

```sh
syq persist receive pending
syq persist receive pending --wait --timeout 30 --json
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

Use the complete ID printed by `pending`. Each ID works once for that request.
Requests expire after five minutes. Disconnecting the sender, losing the return
connection, changing receiving settings, or stopping receiving cancels pending
requests. An approval cannot carry over to a reconnected or retried copy.
One request may await approval per profile per server connection; other senders must retry.

If a desktop prompt is unavailable or dismissed without a decision, the copy
stays pending for a local command until it expires. `persist receive pending` shows prompt
errors. A missing notification service never grants permission. To use only
terminal approval, set `syq persist receive on --notify off`; `--notify desktop` restores
prompts.

For unattended copies from trusted server accounts, explicitly enable automatic
approval:

```sh
syq persist receive on --approve always
syq persist receive on --approve ask   # require approval again
```

Automatic approval trusts every process running as those server accounts,
including for overwrites. An approved copy can inspect destination entries
needed for copying, write unwanted content, or consume disk space within its
limits. The server does not receive your SSH agent. [Command requests](exec.md) require
a separate local decision for every execution, including when copies are
automatically approved.

To send files from that server to another SSH host using this machine's
permission, use `syq cp results --to hostB`. Eligible copies discover a live
receiving machine automatically; `--auth-from @laptop` selects one explicitly
and `--auth-from ssh` uses the server's own SSH access. These requests always
need a local decision. See [Start a copy from the source server](remote-to-remote.md#start-a-copy-from-the-source-server).

## Names and paths

A bare name uses a live return connection before trying an SSH host of the same
name. When the laptop is offline, the name falls back to ordinary SSH resolution
and authentication. Use `--to @laptop` to require a return connection: that form
fails while offline and never tries SSH. After selecting a return connection,
a denied or interrupted copy fails; it does not switch destinations.

`--cwd` chooses the starting directory. Destination `--into` and `--as` paths
are relative to it, but absolute paths and `..` can select other locations.
With no placement, `--to laptop` means `--into .` there.

To contain copies within a directory instead:

```sh
syq persist receive on --name laptop --root ~/Downloads/server
```

`--root` sets both the starting directory and the boundary. It rejects absolute
paths and `..`, and copies cannot traverse symlinks to escape that directory.
The root itself cannot be replaced with `--as .`. Changing to `--cwd` removes
containment. Changing a profile’s settings closes its existing return copies
before restarting that profile with the new settings. Other profiles keep running.

Explicit `--cwd` and `--root` paths must name existing directories with UTF-8
paths; invalid paths leave saved settings unchanged. If a saved directory later
disappears, you can still inspect, disable, or reconfigure its profile. Names
inside receiving directories may use normal Unix filename bytes. Syq protects its own receiving control files,
executable, and SSH authority files from return copies even without `--root`.

## Copy permissions and limits

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

## Background connections

```sh
syq persist status
syq persist status --json
syq persist connect server
syq persist receive off
syq persist receive on
syq persist off
```

`persist receive off` stops receiving while keeping SSH persistence enabled.
`persist receive on` enables it again. `persist off` closes both directions.
You can also enable persistence ahead of your next copy with `syq persist on`.

Connections have no idle expiry. Receiving reconnects after network interruptions
or laptop sleep; other SSH connections reopen on their next use. Interrupted
copies fail and are not queued or retried automatically. Rerun the copy after
reconnection to resume it. A copy must finish within seven days of approval.
After reboot, run `syq persist connect server` again; syq does not install a
login service.

Other processes running as your local user can reuse an open SSH login without
another key touch or agent approval. Use `syq persist off` to close it.
Incoming requests still need their own approval.

If `syq persist status` reports a failure, correct the reported problem and run
`syq persist connect server` to retry. Healthy connections and their requests
keep working. `connect --timeout 30` limits the wait for receiving after SSH
and helper setup; it does not limit authentication or installation. A failed
connection leaves persistence enabled.

To wait without starting or restarting a connection:

```sh
syq persist receive wait server --timeout 30
```

On the server, `syq persist destinations list` shows availability and
`syq persist destinations wait laptop --timeout 30` waits for a destination.
`syq persist destinations forget laptop` removes a stale entry while its
connection is stopped. For scripts, see [JSON connection status](automation.md#connection-status).

### Persistence in scripts

`syq persist on --ephemeral` prints a scope path. Pass it as `--pscope PATH`
to `syq persist connect server` and subsequent copy commands, then close it
with `syq persist off --pscope PATH`. This does not change your user setting.

Ephemeral scopes reuse SSH logins only; they do not enable receiving,
authorization through your machine, or commands on it. Idle connections close
within ten minutes, including helper sessions. Close the scope explicitly to
end reuse immediately. For return copies or commands, use
`syq persist connect server` without `--pscope`.

## SSH setup

Automatic receiving applies to syq's managed persistent SSH connections.
Opening an unrelated plain `ssh` session does not start it. A second SSH hop
does not automatically carry the laptop's destination through to another host.

Reconnects require an available SSH key or agent and a trusted server host key.
No agent is forwarded. The server must permit remote Unix socket forwarding;
OpenSSH 9.2 also requires remote TCP forwarding permission. Syq does not change
server configuration. `persist receive status` reports setup errors; after correcting one,
run `syq persist connect server` to retry. A failed return setup does not
invalidate an ordinary copy.

The server can run a different syq build: it uses the matching helper installed
by your receiving connection. If that helper is missing or an option is
unsupported, update syq on both machines and reconnect from the receiving
machine.

### Updating receiving connections

Before upgrading, run `syq persist off` on the receiving machine to stop its
background services. Replacing the executable alone does not update running
services. Close any script scopes with `syq persist off --pscope PATH` too.
After upgrading both machines, run `syq persist connect server` for each server.

Saved receiving names, directories, and limits carry over. Settings that predate
approval prompts require approval after upgrading. Older binaries may be unable
to read updated preferences; use the newer binary to manage receiving.
