# Keep connections open

Persistence keeps SSH connections ready for repeated copies and other syq
commands. It is off by default. Enable it and connect to a server without
copying files:

```sh
syq persist connect server
```

You can close the terminal afterward. To enable persistence for connections
opened by later syq commands instead, run `syq persist on`.

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

Receiving reconnects after a network interruption or laptop sleep; other SSH
connections reopen on their next use. An interrupted copy still needs to be
rerun to resume. After rebooting, run `syq persist connect server` again.

See [Persistence details](persistence-reference.md) for troubleshooting,
upgrading, and isolated connections for scripts, or [`syq persist`](commands/persist.md)
for all commands and options.
