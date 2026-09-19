# Send files home from a server

Inspect files on your server, then copy them to your laptop from the same shell.
The laptop opens and maintains the connection. It needs no SSH server, public
address, or incoming network port.

<a id="ssh-setup"></a>
<a id="persistence-in-scripts"></a>
<a id="updating-receiving-connections"></a>
<a id="background-connections"></a>

With syq installed on both machines, connect from your laptop:

```sh
syq persist connect server
```

This keeps a connection open so the server can send files back to your laptop.
Once the command finishes, you can close the terminal and continue working on
the server. By default, your laptop is available under its short hostname, and
received files go into your home directory.

To give it the name `laptop` and choose a different starting directory:

```sh
mkdir -p ~/Downloads/server
syq persist receive on --name laptop --cwd ~/Downloads/server
syq persist connect server
```

On the server, use the name from any shell, including an existing tmux session:

```sh
ls -lh results
syq cp results --to @laptop
syq cp report.pdf --to @laptop --as reports/latest.pdf
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
project separate from your general `laptop` destination. Names stay assigned to
their receiving machine while it is offline; see [replacing a receiver](persistence-reference.md#names-and-profiles)
when moving a name to another laptop.

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

For unattended downloads into a dedicated directory, choose an automatic approval
root:

```sh
syq persist receive on --auto-approve-root ~/Downloads/server
syq persist receive on --no-auto-approve-root   # ask for every download again
```

Downloads confined to that directory need no approval; downloads elsewhere ask.
Automatic approval trusts all processes running as the connected server accounts,
including for overwrites inside that directory. Limit a profile to particular
connections with `--server` (see below). [Commands](exec.md) and
[copies to another server](remote-to-remote.md#start-a-copy-from-the-source-server)
still require separate approval. See [persistence security](security.md#persistent-connections)
for the trust boundary.

## Names and paths

Use `--to @laptop` to select a receiving machine. The command fails if that
receiver is offline or fails its identity check. Without `@`, `--to laptop`
always names an SSH destination, resolved through SSH configuration or DNS.
Once a copy starts, it keeps the same destination even if the connection fails.

The starting directory is your explicit `--cwd`, otherwise `--root`, otherwise
`--auto-approve-root`, otherwise your home directory. You can
choose a path relative to it with `--into` or `--as`, or use an absolute path
to copy elsewhere. Without either option, files go into the starting directory.

To contain copies within a directory instead:

```sh
syq persist receive on --name laptop --root ~/Downloads/server
```

With `--root`, all incoming copies must stay inside that directory. Absolute
paths and `..` are rejected, and symlinks cannot lead outside it. A copy cannot
replace the root itself with `--as .`. Use `--no-root` to remove this restriction;
changing `--cwd` does not remove it. An explicit cwd must be inside the hard root.

`--cwd` pins the starting directory. Use `--auto-cwd` to return to automatic
selection; changes to either root then update the starting directory according
to the order above. `receive status` shows the effective directory and how it
was selected.

Changing a profile's settings stops its active copies so the new settings can
take effect. Other profiles keep working.

Syq also protects its own receiving files, executable, and SSH authority files
from incoming copies. See [directory requirements](persistence-reference.md#directories)
if a receiving location cannot be opened.

## Different settings for different servers

By default, each enabled profile is available through every connected server.
To give a particular server its own inbox:

```sh
syq persist receive on --name work-inbox --server work \
  --auto-approve-root ~/Downloads/work
syq persist connect work
```

On `work`, download with `syq cp results --to @work-inbox`. Other connections
cannot use that profile. Your general profile can still ask for approval on
every download. Repeat `--server` to allow several connections; a new list
replaces the previous list. `--all-servers` removes the restriction. See the
[profile reference](persistence-reference.md#names-and-profiles) for how SSH
destination names match.

## Copy permissions and limits

By default, each copy is limited to 100 GiB and one million entries. Pruning
requires a positive deletion limit on both machines. Change limits with
`syq persist receive on --max-bytes SIZE --max-entries N --max-delete N`.

Most copy options work here; ownership and special-file preservation,
`--inplace`, and `--min-size` are unsupported. See
[copy limits](persistence-reference.md#copy-limits) for details.
