# Send files home from a server

Receiving lets you do three things from a connected server:

- **Copy files to your laptop**, as shown below.
- **Run commands on your laptop** with [`syq exec`](exec.md).
- **Authorize copies between servers** using your laptop's SSH credentials.
  File data travels directly between the servers; see
  [Run the copy from a server](remote-to-remote.md#run-the-copy-from-a-server).

All three use the same receiving connection. Your laptop opens and maintains
it; it needs no SSH server, public address, or incoming network port.

With syq installed on both machines, run these commands on your laptop to
receive files as `@laptop` in `~/Downloads/server`:

```sh
mkdir -p ~/Downloads/server
syq persist receive on --name laptop --cwd ~/Downloads/server
syq persist connect server
```

Once `connect` finishes, you can close that terminal. On the server, use the
name from any shell, including an existing tmux session:

```sh
ls -lh results
syq cp results --to @laptop
syq cp report.pdf --to @laptop --as reports/latest.pdf
```

## Approving copies

Each incoming copy waits for approval **on your laptop**. Review the destination
and permissions, then choose **Allow once** or **Deny**. To see the complete
request, use **Details** on macOS or `syq persist receive pending` in a local
terminal. You can also approve or deny there:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

Approving a copy trusts the server to supply its contents. Requests expire after
five minutes. If a prompt is missing or dismissed, the request stays pending;
it is never approved automatically. To use only terminal approval, run `syq persist receive on --name laptop --notify off`.

## Names and paths

Use `--to @laptop` for your connected receiving machine. Without `@`,
`--to laptop` names an SSH destination instead.

The directory you set with `--cwd` is where incoming copies start. You can
choose a path relative to it with `--into` or `--as`, or use an absolute path
to copy elsewhere. Without either option, files go into the starting directory.

To contain copies within a directory instead:

```sh
syq persist receive on --name laptop --root ~/Downloads/server
```

With `--root`, incoming paths must be relative and stay inside that directory,
even when following symlinks. Switching back to `--cwd` allows copies elsewhere.

Changing a profile's settings stops its active copies so the new settings can
take effect. Other profiles keep working.

See [Directories](persistence-reference.md#directories) if a
receiving location cannot be opened.

## Multiple receiving profiles

Give a project its own receiving name and directory:

```sh
syq persist receive on --name project --root ~/work/project
syq persist connect server
```

Then run `syq cp results --to @project` on the server. The directory must already
exist. Each name has its own settings and approval policy, so you can keep a
project separate from your general `laptop` destination. See
[Names and profiles](persistence-reference.md#names-and-profiles) when moving
a name to another laptop.

Use `syq persist receive status` to list profiles and
`syq persist receive off --name project` to stop one. See
[Names and profiles](persistence-reference.md#names-and-profiles) for more options.

## Unattended copies

For unattended copies from trusted server accounts, explicitly enable automatic
approval:

```sh
syq persist receive on --name laptop --approve always
syq persist receive on --name laptop --approve ask   # require approval again
```

Automatic approval trusts all processes running as the connected server accounts,
including for overwrites. Commands and copies to another server still require
separate approval. See [Persistent connections](security.md#persistent-connections)
for the trust boundary.

## Copy permissions and limits

By default, each copy is limited to 100 GiB and one million entries. Pruning
requires a positive deletion limit on both machines. Change limits with
`syq persist receive on --name laptop --max-bytes SIZE --max-entries N --max-delete N`.

Most copy options work here; ownership preservation, special-file preservation,
and `--inplace` are unsupported. See
[copy limits](persistence-reference.md#copy-limits) for details.

<a id="ssh-setup"></a>
<a id="persistence-in-scripts"></a>
<a id="updating-receiving-connections"></a>

## Background connections

You can inspect your connections with `syq persist status`. To stop receiving
while keeping SSH connections open for your own copies, run
`syq persist receive off`. Use `syq persist off` to close both directions.

After a network interruption or laptop sleep, syq reconnects automatically.
An interrupted copy still needs to be rerun so it can resume. After rebooting
your laptop, run `syq persist connect server` again.

If a connection fails to start, `syq persist receive status` shows the error.
[Persistence details](persistence-reference.md) covers troubleshooting,
upgrading, and using connections in scripts.
