# syq ssh

Open a shell on another server using SSH authorization from your laptop:

```sh
syq ssh --auth-from @laptop user@hostB
syq ssh --auth-from @laptop hostB -- hostname
```

Run these commands on the server you are working on. First
[connect your laptop to that server](../receive.md#set-up-receiving).
Your laptop resolves the destination through its own SSH configuration and
asks you to approve access to that account. The SSH connection and all
session traffic go directly between the two servers.

<!-- CLI: ssh -->
```text
syq ssh [OPTIONS] --auth-from <@NAME> <HOST> [-- [COMMAND]...]
```

## Arguments

| Argument / option | Meaning |
|---|---|
| `<HOST>` | SSH endpoint: [USER@]HOST[:PORT]; enclose IPv6 addresses in brackets |
| `[COMMAND]...` | Remote shell command and arguments, interpreted as with ssh |

## Options

| Argument / option | Meaning |
|---|---|
| `--auth-from <@NAME>` | Receiving machine that authorizes access to the destination |
| `-t` | Request a terminal, including when running a command |
| `-T` | Disable terminal allocation |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Account access requires approval

A new laptop-authorized login requires approval. This grants access to the
**destination account**, including permission to run arbitrary commands;
it does not restrict access to the command shown in the request. Copy approval
and automatic download approval do not approve SSH account access.
See [SSH account access](../security.md#ssh-account-access).

The laptop keeps its private keys and limits authentication to the approved
host and login account. Keep its receiving connection open while using the
session. An explicitly approved [persistent account login](../persistence.md#reuse-laptop-authorized-account-access) can serve later commands without another prompt. Stopping receiving, changing the profile, or losing that connection
stops the local SSH client. Commands are never retried automatically.

The destination must already be trusted by the laptop. This mode runs the native OpenSSH client and requires
OpenSSH 8.9 or newer and an exact plain host key in the laptop's known-hosts
files; host certificates are unsupported. The laptop's key must be loaded in its local SSH agent. That agent is not forwarded to the requesting server. The requesting server must be able
to reach the destination's SSH port directly.

## Commands and terminals

Without a command, OpenSSH opens a shell and uses its normal terminal selection.
Use `-t` to request a terminal for a command or `-T` to disable terminal
allocation. OpenSSH handles input, output, resizing, and terminal restoration.
Syq returns its exit status; SSH connection errors normally return 255.

Put `--` before a remote command. As with `ssh`, the destination's shell
interprets the command arguments joined with spaces. Preserve quoting needed
by that shell:

```sh
syq ssh --auth-from @laptop hostB -- "printf '%s\n' 'two words'"
```

This differs from [`syq exec --on @laptop`](exec.md), which runs a program on
your laptop with literal arguments and closed stdin.

`syq ssh` accepts the options listed above; it has no port-forwarding flags.
Shell completion suggests authorization choices without contacting a destination
or requesting approval.

## Authorization selection

Omitting `--auth-from` uses your [saved choice](../persistence-reference.md#authorization-defaults),
then `auto`. For `syq ssh`, both `auto` and `ssh` run native SSH once, using
its ordinary configuration and syq's native persistent connections when enabled.
A failed login or command is never retried through a receiving machine.
Use `--auth-from @NAME` or save that preference to ask your laptop directly.
An ordinary laptop-authorized invocation opens one login; it does not create
reusable account access by itself.
