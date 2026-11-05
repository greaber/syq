# Keep connections open

Persistence keeps SSH connections ready for repeated copies and other syq
commands. It is off by default. Enable it and connect to a server without
copying files:

```sh
syq persist connect server
```

You can close the terminal afterward. To enable persistence for connections
opened by later syq commands instead, run `syq persist on`. Open connections
also make [remote path completion](install.md#shell-completion) faster.

Persistence also applies to an `--rsh` (or rsync `-e`) command that runs `ssh`
with its own options, such as `-e 'ssh -p 2222 -i key'`. Each set of options
keeps its own connection, so a login made with one key, jump host, or
configuration file is never reused by a command that asked for another.
Options that manage SSH connection sharing themselves, such as `-S` or
`ControlMaster`, and remote shells other than `ssh` connect each time instead.

In the default persistence domain, copies, remote file operations, and
`persist connect` also start receiving, unless you have turned it off.
Receiving lets connected servers request file copies to your machine, commands
on it, and authorization for copies between servers, each with approval on
your machine; see [Use your laptop from a server](receive.md). It starts only
on connections made with your plain `ssh`.

To keep SSH connections open only for commands you start locally, turn
receiving off with `syq persist receive off`. The persistent SSH login remains
usable by processes running as your local user even if your SSH key or agent
is no longer available. See [Persistent connections](security.md#persistent-connections)
for the security implications.

Inspect connections with `syq persist status`. Close them, including receiving
connections, with `syq persist off`; your saved settings stay. For an
independent set of connections and settings, create an
[isolated domain](persistence-reference.md#isolated-script-scopes) and pass its
path with `--pscope`; fresh domains start with receiving off.

Receiving reconnects after a network interruption or laptop sleep, and other
SSH connections reopen on their next use. An interrupted copy still needs to be
rerun to resume. After rebooting, run `syq persist connect server` again.

## What keeps running

With persistence on, a command that connects to a server leaves these running
so that the next command to that server starts sooner:

- The SSH connection, until `syq persist off` or until the network drops it.
  In an isolated domain, it closes after a few idle minutes.
- A ready syq session on the server, with a small syq process on your machine,
  until five minutes pass without a command using it.
- Receiving through the server, when receiving is on, until `syq persist off`
  or `syq persist receive off`.

The command that starts them says so in one line that names `syq persist off`.
`syq persist status` shows what is running.

## Reuse laptop-authorized account access

On a server connected to your laptop, select it for authorization and start work:

```sh
syq persist auth-from @laptop
syq ssh hostB -- hostname
syq cp report --to hostB --as report
syq ssh hostB
syq persist off
```

The first SSH command asks for access to the destination account, including
arbitrary commands and file access. See
[account permissions](persistence-reference.md#account-permissions) to choose
how long that approval lasts and manage it on the laptop.

Later `ssh`, `cp`, `rsync`, `rm`, `map`, and `clean-partials` commands reuse
the approved connection. This does not enable ordinary persistence or receiving
on the server. To prepare a connection before using it, run
`syq persist connect hostB --auth-from @laptop`.
See the [SSH authorization requirements](commands/ssh.md#account-access-requires-approval).

For ordinary SSH tools, export a configuration on the server:

```sh
syq persist ssh-config hostB > hostB.ssh
ssh -F hostB.ssh hostB hostname
scp -F hostB.ssh report hostB:report
sftp -F hostB.ssh hostB
GIT_SSH_COMMAND='ssh -F hostB.ssh' git clone hostB:project.git
rsync -e 'ssh -F hostB.ssh' report hostB:report
```

The configuration uses the approved connection to that host and account and
needs no forwarded agent. It stops working when the connection closes; export
again after approving a new one. Use the file's absolute path when a tool runs
from a different directory.

`syq persist off` closes the server's approved connections. It does not remove
permissions on the laptop: a later command can request another login under the
same session or remembered permission. Ending the laptop's receiving connection
ends its session permissions; reconnecting asks again unless you chose Remember.
See [SSH account access](security.md#ssh-account-access) for the authority granted
and the limits of stopping access.

See [Persistence details](persistence-reference.md) for troubleshooting,
upgrading, and isolated connections for scripts, or [`syq persist`](commands/persist.md)
for all commands and options.
