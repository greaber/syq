# Keep connections open

Persistence keeps SSH connections open between syq commands, so the next
command to the same server starts without logging in again. It is off by
default. To turn it on and connect to a server without copying files:

```sh
syq persist connect server
```

You can close the terminal afterward. To have every later syq command keep
its connections open instead, run `syq persist on`. Use `syq persist status`
to see open connections, and `syq persist off` to close them all; your saved
settings stay.

After a network interruption or laptop sleep, connections reopen on their next
use, and receiving (below) reconnects on its own, but an interrupted copy
still needs to be rerun. After rebooting, run `syq persist connect server`
again.

## Receiving

Copies, other file commands, and `persist connect` also start *receiving* on
their connections, unless you turn it off. Receiving lets connected servers
request file copies to your machine, commands on it, and access to other
servers, each with your approval; see
[Use your laptop from a server](receive.md). If you don't need it, run
`syq persist receive off`.

Either way, processes running as your local user can use an open SSH login
even after your SSH key or agent is gone. See
[Persistent connections](security.md#persistent-connections) for the security
implications.

A custom `--rsh` (or rsync `-e`) command that runs `ssh` with its own options
gets a separate connection for each set of options, and doesn't start
receiving.

## What keeps running

With persistence on, a command that connects to a server leaves these running
so that the next command to that server starts sooner:

- The SSH connection, until `syq persist off` or until the network drops it.
- A ready syq session on the server, with a small syq process on your machine,
  until five minutes pass without a command using it.
- Receiving through the server, when receiving is on, until `syq persist off`
  or `syq persist receive off`.

The command that starts them says so, naming `syq persist off`.

<a id="reuse-laptop-authorized-account-access"></a>

On a server, connections opened with your laptop's SSH access, as by
`syq ssh --auth-from @laptop hostB`, are kept for later commands whether or not
persistence is on, and `syq persist off` closes them; see
[Open a shell on another server](receive.md#open-a-shell-on-another-server).

## Separate connections for scripts

A script can keep its own connections and settings, apart from yours, in an
[isolated domain](persistence-reference.md#isolated-script-scopes): pass a
directory with `--pscope PATH`. Its connections close after a few idle
minutes, receiving starts off, and `syq persist --pscope PATH off` removes the
domain with its settings.

See [Persistence details](persistence-reference.md) for troubleshooting, or
[`syq persist`](commands/persist.md) for all commands and options.
