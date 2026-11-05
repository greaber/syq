# syq ssh

Open a shell or run a command using your saved authorization choice, or native
SSH when none is configured:

```sh
syq ssh user@hostB
syq ssh hostB -- hostname
```

To authorize through your laptop while working on another server, first
[connect the laptop to that server](../receive.md#set-up-receiving), then run
`syq ssh --auth-from @laptop hostB`. The server's SSH configuration still
chooses the account, address, and route, and the session follows that route.

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

## Account access requires approval

The first laptop-authorized login asks permission for the source account to use
**the destination account**, including running any command and reading or
changing its files. The command shown describes what the requester intends; it
does not restrict the permission, and copy roots and byte limits do not apply.
Later commands and copies reuse the approved connection. See
[account permission controls](../persistence-reference.md#account-permissions)
for how long approvals last and how to revoke them, and
[SSH account access](../security.md#ssh-account-access) for the trust boundary.

This needs:

- OpenSSH 8.9 or newer for the requesting server's SSH client and the
  destination's SSH server.
- Exact plain host keys for both servers, trusted by the laptop; trust through
  host certificates alone is not supported.
- The laptop's key loaded in its SSH agent. The requesting server's
  `IdentityFile` and `IdentitiesOnly` settings choose which keys to offer: an
  `IdentityFile` naming a public key there selects the matching key in the
  laptop's agent, and a `CertificateFile` can pair a user certificate with it.

The laptop looks up the host key under the alias you typed, or your
`HostKeyAlias`, using its own SSH configuration. The same alias can therefore
use a private address between servers and a public one on the laptop, as long
as both reach the same trusted host. `ProxyJump` hosts need their own
approvals, and a custom `ProxyCommand` uses the requesting server's own
authentication.

Stopping receiving prevents new laptop-authorized logins, but sessions and
commands that already authenticated are not guaranteed to end.

## Commands and terminals

Without a command, OpenSSH opens a shell with its usual terminal handling. Use
`-t` to request a terminal for a command or `-T` to disable one. Syq returns the
remote exit status, or 255 for its own connection, authorization, and setup
failures.

Put `--` before a remote command. As with `ssh`, the destination's shell
interprets the arguments joined with spaces, so keep the quoting that shell
needs:

```sh
syq ssh --auth-from @laptop hostB -- "printf '%s\n' 'two words'"
```

This differs from [`syq exec --on @laptop`](exec.md), which runs a program on
your laptop with literal arguments and closed stdin. `syq ssh` has no
port-forwarding options.

## Authorization selection

Without `--auth-from`, syq uses your [saved choice](../persistence-reference.md#authorization-defaults),
or `auto` when none is saved. For `syq ssh`, `auto` and `ssh` both run native
SSH once, without using an approved account connection, and never fall back to
a receiving machine. To authorize through your laptop, use
`--auth-from @NAME`; to use an
[SSH authorization provider](../receive.md#use-an-ssh-authorization-provider),
give its endpoint, such as `--auth-from alice@provider:2222`. Either way, syq
opens or reuses an approved account connection, so you do not need to run
`persist connect` first.
