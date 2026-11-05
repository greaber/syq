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

With an `--rsh` (or rsync `-e`) command that runs `ssh` with its own options,
each set of options keeps its own connection, so a login is never reused by a
command that asked for another.

In the default persistence domain, copies, remote file operations, and
`persist connect` also start receiving on allowed servers, unless you have
turned it off. Receiving lets connected servers request file copies to your
machine, commands on it, and access to other servers, each with approval on
your machine; see [Use your laptop from a server](receive.md).
It starts only on connections made with your plain `ssh`.

To keep SSH connections open only for commands you start locally, turn
receiving off with `syq persist receive off`. The persistent SSH login remains
usable by processes running as your local user even if your SSH key or agent
is no longer available. See [Persistent connections](security.md#persistent-connections)
for the security implications.

Inspect connections with `syq persist status`. Close them, including receiving
connections, with `syq persist off`, which keeps your saved settings. For an
independent set of connections and settings, create an
[isolated domain](persistence-reference.md#isolated-script-scopes) and pass its
path with `--pscope`. A fresh domain starts with receiving off, and
`syq persist --pscope PATH off` removes it with its settings.

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

A copy or other file command that starts them says so in one line that names
`syq persist off`. `syq persist status` shows what is running.

<a id="reuse-laptop-authorized-account-access"></a>

On a server, connections opened with your laptop's SSH access, as by
`syq ssh --auth-from @laptop hostB`, are kept for later commands whether or not
persistence is on, and `syq persist off` closes them; see
[Open a shell on another server](receive.md#open-a-shell-on-another-server).

See [Persistence details](persistence-reference.md) for troubleshooting,
upgrading, and isolated connections for scripts, or [`syq persist`](commands/persist.md)
for all commands and options.
