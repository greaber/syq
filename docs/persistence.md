# Keep connections open

Persistence keeps SSH connections ready for repeated copies and other syq
commands. It is off by default. Enable it and connect to a server without
copying files:

```sh
syq persist connect server
```

You can close the terminal afterward. To enable persistence for connections
opened by later syq commands instead, run `syq persist on`. Persistence also
applies to an `--rsh` (or rsync `-e`) command that runs `ssh` with its own
options, such as `-e 'ssh -p 2222 -i key'`. Each set of options keeps its own
connection, so a login made with one key, jump host, or configuration file is
never reused by a command that asked for another. A relative path to a file in
the options, such as `-F ssh.conf`, names a different file in each directory,
so it counts as different options there. So does an option that runs a local
command, such as `ProxyCommand`, because the command may use files in the
directory it runs in. Receiving and the pool of ready sessions use only
connections made with your plain `ssh`. With `-v` or a debug `LogLevel`, a
command shares its connection only while it runs, so debug output does not
outlive it. Options that set up SSH connection sharing themselves (`-M`, `-S`,
`-O`, `ControlMaster`, `ControlPath`, or `ControlPersist`), and remote shells
other than `ssh`, connect with that command each time instead.

Persistence also speeds up [remote path completion](install.md#shell-completion):
completion reuses the open connection, avoiding a new SSH login for each lookup.

Receiving starts automatically with persistent connections unless you have
turned it off. It lets connected servers request file copies to your machine,
commands on it, and authorization for copies between servers,
with approval on your machine. See [Use your laptop from a server](receive.md)
for setup and approval controls.

To keep SSH connections open only for commands you start locally, turn
receiving off with `syq persist receive off`. The persistent SSH login remains
usable by processes running as your local user even if your SSH key or agent
is no longer available. See [Persistent connections](security.md#persistent-connections)
for the security implications.

Inspect connections with `syq persist status`. Close them, including receiving
connections, with `syq persist off`.

Receiving reconnects after a network interruption or laptop sleep; native SSH
connections reopen on their next use. An interrupted copy still needs to be
rerun to resume. After rebooting, run `syq persist connect server` again.

## Reuse laptop-authorized account access

On a server connected to your laptop, explicitly keep an approved login open:

```sh
syq persist connect hostB --auth-from @laptop
syq ssh --auth-from @laptop hostB -- hostname
syq ssh --auth-from @laptop hostB
syq persist off
```

The laptop asks for **reusable account access**: commands and copies may use
that account's full authority while the laptop connection remains open.
This is broader than approving one copy. Later commands using the same
receiving name and typed endpoint reuse the login without another approval.
An ordinary `syq ssh` invocation never creates a reusable login automatically.
The laptop needs the [SSH account authorization requirements](commands/ssh.md#account-access-requires-approval).

`syq persist status` shows the connection and its SSH control socket.
Other OpenSSH tools can use that socket too. For example, copy the printed
path into `SOCKET` and use:

```sh
ssh -F /dev/null -S "$SOCKET" -o ProxyCommand=false hostB hostname
scp -F /dev/null -o "ControlPath=$SOCKET" -o ProxyCommand=false report hostB:report
```

`ProxyCommand=false` makes these commands fail if the master is gone instead
of attempting another login. These commands use the account already connected
through the socket. They need no forwarded agent.

`syq persist off`, stopping the laptop's receiving profile, or losing its
connection closes this login and its active sessions. Reconnecting the laptop
does not reopen it: run `persist connect --auth-from @NAME` again to approve
another reusable login. See [SSH account access](security.md#ssh-account-access)
for the authority this grants.

See [Persistence details](persistence-reference.md) for troubleshooting,
upgrading, and isolated connections for scripts, or [`syq persist`](commands/persist.md)
for all commands and options.
