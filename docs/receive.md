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

Give a project its own receiving name and directory:

```sh
syq persist receive on --name project --root ~/work/project
syq persist connect server
```

Then run `syq cp results --to @project` on the server. The directory must already
exist. Each name has its own settings and approval policy, so you can keep a
project separate from your general `laptop` destination.

Use `syq persist receive status` to list profiles and
`syq persist receive off --name project` to stop one. See
[profile management](persistence-reference.md#names-and-profiles) for more options.

## Approving copies

Approve or deny from the desktop prompt, or from a terminal on your laptop:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

Requests expire after five minutes. If a prompt is missing or dismissed, the
request stays pending; it is never approved automatically. To use only terminal
approval, run `syq persist receive on --notify off`.

For unattended copies from trusted server accounts, explicitly enable automatic
approval:

```sh
syq persist receive on --approve always
syq persist receive on --approve ask   # require approval again
```

Automatic approval trusts all processes running as the connected server accounts,
including for overwrites. [Commands](exec.md) and
[copies to another server](remote-to-remote.md#start-a-copy-from-the-source-server)
still require separate approval. See [persistence security](security.md#persistent-connections)
for the trust boundary.

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

Syq also protects its own receiving files, executable, and SSH authority files
from incoming copies. See [directory requirements](persistence-reference.md#directories)
if a receiving location cannot be opened.

## Copy permissions and limits

By default, each copy is limited to 100 GiB and one million entries. Pruning
requires a positive deletion limit on both machines. Change limits with
`syq persist receive on --max-bytes SIZE --max-entries N --max-delete N`.

Most copy options work here; ownership and special-file preservation,
`--inplace`, and `--min-size` are unsupported. See
[copy limits](persistence-reference.md#copy-limits) for details.

## Background connections

Use `syq persist status` to inspect connections. `syq persist receive off`
stops receiving; `syq persist off` also closes reusable SSH logins.

Receiving reconnects after a network interruption or laptop sleep. Rerun an
interrupted copy to resume it. After reboot, run `syq persist connect server`
again. If status reports a failure, fix the reported problem and run that
command to retry.

### Persistence in scripts

Scripts can use isolated SSH connection scopes and wait for destinations to
become available. See [persistence details](persistence-reference.md).

## SSH setup

Start receiving with syq from your laptop; an unrelated `ssh` session does not
start it. Reconnection needs an available SSH key or agent and a trusted host
key. Background receiving cannot ask for a password.

The server must permit remote Unix socket forwarding. OpenSSH 9.2 also needs
remote TCP forwarding permission. If receiving cannot start, inspect
`syq persist receive status`; see [setup and recovery](persistence-reference.md#setup-and-recovery).

### Updating receiving connections

Stop persistence before upgrading, then reconnect with the updated syq.
See [updating connections](persistence-reference.md#updating-connections) for
script scopes and saved settings.
