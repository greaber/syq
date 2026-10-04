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
syq ssh [OPTIONS] <HOST> [-- [COMMAND]...]
```

## Arguments

| Argument / option | Meaning |
|---|---|
| `<HOST>` | SSH endpoint: [USER@]HOST[:PORT]; enclose IPv6 addresses in brackets |
| `[COMMAND]...` | Remote shell command and arguments, interpreted as with ssh |

## Options

| Argument / option | Meaning |
|---|---|
| `--auth-from <auto\|ssh\|@NAME>` | Authorization source; omitted uses the saved preference, then an approved account connection or native SSH |
| `--pscope <PATH>` | Use connections and authorization preferences from this persistence scope |
| `-t` | Request a terminal, including when running a command |
| `-T` | Disable terminal allocation |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Account access requires approval

The first laptop-authorized login asks permission for the source account to use
**the destination account**, including arbitrary commands and file access. The
shown command describes the requester's intent; it is not a restriction on that
permission. Copy roots and byte limits do not apply.

Choose **Allow** to permit logins between those accounts while the laptop's
current receiving connection to the source remains open. Commands and copies
reuse the approved SSH connection without another prompt. **Remember** permits
future logins between the same accounts through that profile while the laptop
is available. Different accounts or changed trusted host keys require new
approval. See [account permission controls](../persistence-reference.md#account-permissions).

The laptop's ordinary SSH agent is not forwarded. Syq limits its authentication
requests to the approved destination host keys and login account. The requesting
SSH client and destination SSH server need OpenSSH 8.9 or newer. Both servers
must have exact plain host keys trusted by the laptop; host-certificate-only
trust is unsupported. The laptop's key must be loaded in its local agent, and
the requesting server must reach the destination's SSH port directly.

Stopping receiving prevents new laptop-authorized logins. Syq also cleans up
its owned connections, but already authenticated sessions and commands are not
guaranteed to end. See [SSH account access](../security.md#ssh-account-access).

## Commands and terminals

Without a command, OpenSSH opens a shell and uses its normal terminal selection.
Use `-t` to request a terminal for a command or `-T` to disable terminal
allocation. OpenSSH handles input, output, resizing, and terminal restoration.
Syq returns the remote exit status. Its own connection, authorization, and
setup failures return 255; invalid arguments use the argument parser's status.

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
then `auto`. This first reuses an existing approved account connection for the
same typed endpoint. Without one, it runs native SSH once using its ordinary
configuration and syq's native persistent connections when enabled. Explicit
`ssh` selection always uses native authentication.
A failed login or command is never retried through a receiving machine.
Use `--auth-from @NAME` or save that preference to ask your laptop directly.
A laptop-authorized invocation opens or reuses an approved account connection.
You do not need to run `persist connect` first.
