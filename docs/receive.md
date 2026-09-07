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

Receiving is enabled by default with persistence. Each incoming copy waits for
approval **on your laptop** before it can inspect or change destination entries.
The prompt puts the destination first, followed by the connected server account
and permission to change files. A positive deletion limit is shown too. Choose
**Allow once** or **Deny**. On macOS, **Details** shows the full explanation,
including size and entry limits; **Back** returns to the short view. On either
platform, `syq persist receive pending` shows the complete request. Allowing a
copy trusts the server to supply its contents: syq cannot prove what you typed in the remote
shell or that the files contain what you intended.

You can also [run commands on the receiving machine](exec.md), with separate
local approval, to build a project there or open a copied artifact.

## Approving copies

On Linux, desktop prompts use `/usr/bin/notify-send` with action support
(libnotify 0.7.10 or later) and your desktop notification service. On macOS,
syq opens a native dialog through `/usr/bin/osascript`; Deny is the default
button in both the short and detailed views. Opening Details does not approve
the request or extend its five-minute deadline. The background connection
inherits the desktop session in which you start it. After changing desktop sessions, run `syq persist receive on` from a terminal
in the current session to restart it.

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
One request may await approval per server connection; other senders must retry.

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

Names belong to live connections, not permanent registrations. A second live
connection cannot advertise the same name on the same server account. When a
connection closes, its name becomes available again. Choose distinct names for
different laptops.

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
containment. Settings apply globally to receiving connections; changing them
closes existing return copies before restarting with the new settings.

The receiving directory must exist and have a UTF-8 path. Names inside it may
use normal Unix filename bytes. Syq protects its own receiving control files,
executable, and SSH authority files from return copies even without `--root`.

## Copy permissions and limits

Each request is checked on the laptop before syq issues permission for that
copy. The restricted filesystem executor then checks individual operations.
Directory recursion, symlinks, modification times, filters, hashing, resume,
and staged publication work as in other syq copies. `--preserve=permissions`,
`--verify-only`, `--ignore-existing`, and `--existing` are supported. Ownership,
special-file preservation, `--inplace`, `--update`, mappings, and `--min-size`
are refused. `--update` depends on timestamps supplied by the source that the
laptop cannot independently verify.

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

`persist receive off` stops receiving while keeping ordinary SSH persistence enabled.
`persist receive on` enables it again and can restart previously connected endpoints.
`persist off` stops both kinds of connection. Ephemeral scopes selected with
`--pscope` only reuse forward SSH connections; they do not enable receiving.

To wait for receiving without starting or restarting a connection, use:

```sh
syq persist receive wait server --timeout 30
```

Return connections have no idle expiry. After a network interruption or laptop
sleep, the laptop reconnects with delays of one to thirty seconds, including
when a return-connection heartbeat times out. Ordinary
reusable SSH logins in durable persistence also have no idle expiry and reconnect on the next use.
An interrupted copy fails: rerun it after reconnection to reuse eligible partial files. Copies are
not queued while offline. A copy must open its control channel within sixty
seconds of authorization and finish within seven days. Closing that control
channel revokes its workers and prevents further requests.

If `syq persist status` reports a failed return connection, fix the reported
configuration or permission problem and run `syq persist connect server` to retry
that endpoint. A healthy connection is reused without cancelling its copies,
commands, or pending approvals. There is no need to toggle receiving or persistence.

On the server, `syq persist destinations list` shows availability and
`syq persist destinations wait laptop --timeout 30` waits with a deadline. Stale records
left by a crash do not reserve a name; `syq persist destinations forget laptop` removes
one while its connection is stopped.

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

The server command can be a different syq build from the receiving machine.
It automatically hands the command to the matching helper already installed
by the receiving machine's connection, including an explicit `--syq-path`.
Arguments, working directory, stdin, and output streams are preserved.
`--ignore-from` inputs are read once by the executing build after handoff,
before requesting approval or opening result files. Inline patterns and input
files keep their command-line order. The helper then requests approval and runs
the copy using the receiving machine's build. A missing or replaced helper produces an error; reconnect with syq from
the receiving machine to refresh it. An option unknown to that helper is
rejected before approval.

Handoff requires support in both installations. When upgrading from a build
that required matching server and client commands, run `syq persist off` on
the receiving machine before replacing the binaries on both machines. Then
run `syq persist on` and connect to the server with syq again. This refreshes
the helper and return registration without deleting preferences or enrollments.

Receiving preferences live in `receive.json` beside the ordinary persistence
preferences, under `$XDG_CONFIG_HOME/syq` or `~/.config/syq`. Runtime services
belong to their persistence scope. Transient server advertisements live in the
private directory `~/.syq-destinations-v3`. These files do not change restricted
receiver enrollments or signed-grant replay records.

Receiving settings from the earlier automatic-only format keep their name,
directory, and limits when upgraded, but require approval. Syq saves the new
format before starting or reusing a return service. After upgrading, run
`syq persist receive on` to stop old receiving services, then connect to each server with
the new syq build. Merely replacing the executable or inspecting status does
not change a service that is already running. Older binaries reject the new
preferences; use the newer binary to manage receiving, including `persist receive off`, before
switching versions. Pending requests and approval decisions exist only in the
running service, never in preference files.
