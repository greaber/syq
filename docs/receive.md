# Send files home from a server

Inspect files on your server, then copy them to your laptop from the same shell.
The laptop opens and maintains the connection. It needs no SSH server, public
address, or incoming network port.

On your laptop, turn on persistence:

```sh
syq persist on
```

When syq connects to an SSH server, it also starts a background return
connection. The default destination name is your laptop's short hostname,
and files go into your home directory. No receiving terminal needs to stay open.
To choose a name and a different starting directory:

```sh
mkdir -p ~/Downloads/server
syq recv on --name laptop --cwd ~/Downloads/server
syq cp --from server report.pdf
syq recv wait server --timeout 30
```

On the server, use the name from any shell, including an existing tmux session:

```sh
ls -lh results
syq cp results --to laptop
syq cp report.pdf --to laptop --as reports/latest.pdf
```

Receiving is enabled by default with persistence. Each incoming copy waits for
approval **on your laptop** before it can inspect or change destination entries.
The prompt identifies the connected server account, destination, overwrite
permission, and limits. Choose **Allow once** or **Deny**. Allowing a copy trusts
the server to supply its contents: syq cannot prove what you typed in the remote
shell or that the files contain what you intended.

## Approving copies

On Linux, desktop prompts use `/usr/bin/notify-send` with action support
(libnotify 0.7.10 or later) and your desktop notification service. On macOS,
syq opens a native dialog through `/usr/bin/osascript`; Deny is the default
button. The background connection inherits the desktop session in which you
start it. After changing desktop sessions, run `syq recv on` from a terminal
in the current session to restart it.

You can also decide from any local terminal:

```sh
syq recv pending
syq recv pending --wait --timeout 30 --json
syq recv approve REQUEST_ID
syq recv deny REQUEST_ID
```

Use the complete ID printed by `pending`. Each ID works once for that request.
Requests expire after five minutes. Disconnecting the sender, losing the return
connection, changing receiving settings, or stopping receiving cancels pending
requests. An approval cannot carry over to a reconnected or retried copy.
One request may await approval per server connection; other senders must retry.

If a desktop prompt is unavailable or dismissed without a decision, the copy
stays pending for a local command until it expires. `recv pending` shows prompt
errors. A missing notification service never grants permission. To use only
terminal approval, set `syq recv on --notify off`; `--notify desktop` restores
prompts.

For unattended copies from trusted server accounts, explicitly enable automatic
approval:

```sh
syq recv on --approve always
syq recv on --approve ask   # require approval again
```

Automatic approval trusts every process running as those server accounts,
including for overwrites. An approved copy can inspect destination entries
needed for copying, write unwanted content, or consume disk space within its
limits. The server receives neither your SSH agent nor an interface for running
arbitrary laptop commands.

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
syq recv on --name laptop --root ~/Downloads/server
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
Change these ceilings with `syq recv on --max-bytes 20G --max-entries 100000`.
Lower limits requested by the sender also apply. Limits are per copy; repeated
copies can fill the disk. Copies support at most 32 workers each.

Pruning is disabled unless the laptop sets a positive `--max-delete`.
A sending `--prune` command must also supply its own `--max-delete` ceiling,
no higher than the laptop's. Validation failures leave the copy unstarted.
Errors during copying fail visibly and may leave partial files for retry.
The sender verifies a signed receipt before reporting success.

## Background connections

```sh
syq recv status
syq recv status --json
syq recv wait server --timeout 30
syq recv off
syq recv on
syq persist off
```

`recv off` stops receiving while keeping ordinary SSH persistence enabled.
`recv on` enables it again and can restart previously connected endpoints.
`persist off` stops both kinds of connection in its scope. Explicit ephemeral
persistence scopes also own return connections and end them when closed.

Return connections have no idle expiry. After a network interruption or laptop
sleep, the laptop reconnects with delays of one to thirty seconds. Ordinary
reusable SSH logins still expire after ten idle minutes. An interrupted copy
fails: rerun it after reconnection to reuse eligible partial files. Copies are
not queued while offline. A copy must open its control channel within sixty
seconds of authorization and finish within seven days. Closing that control
channel revokes its workers and prevents further requests.

On the server, `syq destination list` shows availability and
`syq destination wait laptop --timeout 30` waits with a deadline. Stale records
left by a crash do not reserve a name; `syq destination forget laptop` removes
one while its connection is stopped.

## SSH setup

Automatic receiving applies to syq's managed persistent SSH connections.
Opening an unrelated plain `ssh` session does not start it. A second SSH hop
does not automatically carry the laptop's destination through to another host.

Reconnects require an available SSH key or agent and a trusted server host key.
No agent is forwarded. The server must permit remote Unix socket forwarding;
OpenSSH 9.2 also requires remote TCP forwarding permission. Syq does not change
server configuration. `recv status` reports setup errors; after correcting one,
connect with syq again or run `recv on` to retry. A failed return setup does not
invalidate an ordinary copy.

Both machines must use the same syq build. The return connection uses the
helper selected by the ordinary connection, including an explicit `--syq-path`.
The server's `syq cp` executable must match it too.

Receiving preferences live in `receive.json` beside the ordinary persistence
preferences, under `$XDG_CONFIG_HOME/syq` or `~/.config/syq`. Runtime services
belong to their persistence scope. Transient server advertisements live in the
private directory `~/.syq-destinations-v2`. These files do not change restricted
receiver enrollments or signed-grant replay records.

Receiving settings from the earlier automatic-only format keep their name,
directory, and limits when upgraded, but require approval. Syq saves the new
format before starting or reusing a return service. After upgrading, run
`syq recv on` to stop old receiving services, then connect to each server with
the new syq build. Merely replacing the executable or inspecting status does
not change a service that is already running. Older binaries reject the new
preferences; use the newer binary to manage receiving, including `recv off`, before
switching versions. Pending requests and approval decisions exist only in the
running service, never in preference files.
