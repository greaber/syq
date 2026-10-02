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
<!-- /CLI -->

## Account access requires approval

Each invocation requires approval on your laptop. This grants access to the
**destination account**, including permission to run arbitrary commands;
it does not restrict access to the command shown in the request. Copy approval
and automatic download approval do not approve SSH account access.
See [SSH account access](../security.md#ssh-account-access).

The laptop keeps its private keys and limits authentication to the approved
host and login account. Keep its receiving connection open while using the
session. Stopping receiving, changing the profile, or losing that connection
stops the local SSH client. Commands are never retried automatically.

The destination must already be trusted by the laptop. This mode requires
OpenSSH 8.9 or newer and an exact plain host key in the laptop's known-hosts
files; host certificates are unsupported. The requesting server must be able
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

`syq ssh` accepts the options listed above. It does not reuse SSH control
connections or provide SSH port forwarding. Shell completion suggests
receiving names without contacting a destination or requesting approval.
