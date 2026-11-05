# syq ssh

Open a shell or run a command on a server:

```sh
syq ssh user@hostB
syq ssh --auth-from @laptop hostB -- hostname
```

<a id="account-access-requires-approval"></a>
<a id="authorization-selection"></a>

Without `--auth-from`, syq uses your
[saved choice](../persistence-reference.md#authorization-defaults); `auto` and
`ssh` run native SSH. `@laptop` uses
[your laptop's SSH access](../receive.md#open-a-shell-on-another-server), and
an [SSH provider](../receive.md#use-an-ssh-authorization-provider) endpoint
uses that provider's. Both open or reuse an
[approved account connection](../persistence-reference.md#approved-account-connections),
which gives this machine
[full access to that account](../security.md#ssh-account-access).

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
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Authorization source; omitted uses SYQ_AUTH_FROM, then the saved preference, then native SSH |
| `--pscope <PATH>` | Use connections and authorization preferences from this persistence scope |
| `-t` | Request a terminal, including when running a command |
| `-T` | Disable terminal allocation |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Commands and terminals

Without a command, you get a shell. Use `-t` to request a terminal for a
command or `-T` to disable one. Syq returns the
remote exit status, or 255 for its own connection, authorization, and setup
failures.

Put `--` before a remote command. As with `ssh`, the remote shell interprets
the arguments joined with spaces, so keep the quoting it needs:

```sh
syq ssh --auth-from @laptop hostB -- "printf '%s\n' 'two words'"
```

To run a program on your laptop instead, use [`syq exec`](exec.md). `syq ssh`
has no port-forwarding options.
