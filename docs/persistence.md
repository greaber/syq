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

In the default persistence domain, copies, remote file operations, and
`persist connect` start receiving automatically unless you have turned it off.
`syq ssh` reuses persistent connections but does not start receiving itself.
Receiving lets connected servers request file copies to your machine,
commands on it, and authorization for copies between servers,
with approval on your machine. See [Use your laptop from a server](receive.md)
for setup and approval controls.

To keep SSH connections open only for commands you start locally, turn
receiving off with `syq persist receive off`. The persistent SSH login remains
usable by processes running as your local user even if your SSH key or agent
is no longer available. See [Persistent connections](security.md#persistent-connections)
for the security implications.

Inspect connections with `syq persist status`. Close them, including receiving
connections, with `syq persist off`. This keeps your saved settings. For an
independent set of connections and settings, create an
[isolated domain](persistence-reference.md#isolated-script-scopes) and pass its
path with `--pscope`; fresh domains start with receiving off.

Receiving reconnects after a network interruption or laptop sleep; native SSH
connections reopen on their next use. An interrupted copy still needs to be
rerun to resume. After rebooting, run `syq persist connect server` again.

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

The approved connection is reused by `ssh`, `cp`, `rsync`, `rm`, `map`, and
`clean-partials`. SSH data workers authenticate separate connections under the
same permission, so transfers can use multiple network streams. Completion
reuses ready helpers without requesting approval. This reuse works independently of ordinary persistence and does not
enable receiving on the server. To prepare a connection before using it, run
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

The configuration uses this approved account connection and needs no forwarded
agent. It fails if the connection closes or the requested host, account, or
port changes. Export again after approving a replacement connection. Use the
configuration's absolute path when a tool runs from a different directory.
Syq does not edit your SSH configuration.

`syq persist off` closes the server's approved connections. It does not remove
permissions on the laptop: a later command can request another login under the
same session or remembered permission. Ending the laptop's receiving connection
ends its session permissions; reconnecting asks again unless you chose Remember.
See [SSH account access](security.md#ssh-account-access) for the authority granted
and the limits of stopping access.

See [Persistence details](persistence-reference.md) for troubleshooting,
upgrading, and isolated connections for scripts, or [`syq persist`](commands/persist.md)
for all commands and options.
