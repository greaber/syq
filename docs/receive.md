<a id="send-files-home-from-a-server"></a>

# Use your laptop from a server

Receiving lets you use your laptop from a connected server:

- [Copy files to your laptop](#copy-files-to-your-laptop).
- [Run commands on your laptop](#run-commands-on-your-laptop).
- [Open a shell on another server](#open-a-shell-on-another-server)
  using your laptop's SSH credentials.
- [Authorize copies between servers](#authorize-copies-between-servers)
  using your laptop's SSH credentials.
- [Authorize object-storage transfers](object-storage.md#authorize-from-your-laptop)
  using your laptop's storage credentials.

These use a [persistent connection](persistence.md) opened by your laptop.
It needs no SSH server, public address, or incoming network port.

<a id="ssh-setup"></a>
<a id="persistence-in-scripts"></a>
<a id="updating-receiving-connections"></a>
<a id="background-connections"></a>

## Set up receiving

Run this on your laptop with syq installed on both machines:

```sh
syq persist receive on --connection server
```

This enables persistence, saves the server as this profile's allowed connection,
and waits until receiving is ready. Repeat `--connection` to allow several
servers; each list you give replaces the saved one. An ordinary `ssh server`
session does not start receiving; use `syq persist connect server` to connect
without copying anything.

By default, your receiving name is your laptop's short hostname, and downloads
and commands start in your home directory. The command prints the receiving
name. The examples below use `@laptop`; replace it with your own name.

You can close that terminal and make requests from any shell on the server,
including an existing tmux session. Later persistent connections to allowed
servers start receiving too, unless you turn it off.

### Optional name and directory

To create a receiving profile named `laptop` with a different starting
directory, run these commands on your laptop:

```sh
mkdir -p ~/Downloads/server
syq persist receive on --name laptop --cwd ~/Downloads/server --connection server
```

`--cwd` sets the starting directory for downloads and commands. Settings you
leave out keep their saved values.

## Copy files to your laptop

On the server, send files to your receiving directory:

```sh
syq cp results --to @laptop
syq cp report.pdf --to @laptop --as reports/latest.pdf
```

File data uses encrypted TCP when your laptop can reach a data port on the
server, and SSH otherwise; see [Make TCP reachable](server-tuning.md#make-tcp-reachable).

### Approving copies

By default, each incoming copy waits for approval **on your laptop**. The prompt
shows the server, what is copied where, and a warning for each option that
lets the server do more than copy files, such as pruning or copying
permissions. Choose **Allow once** or **Deny**. You can also see the complete
request, and approve or deny it, in a local terminal:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

Approving a copy trusts the server to supply its contents. Requests expire after
five minutes. If a prompt is missing or dismissed, the request stays pending.
To use only terminal approval, run
`syq persist receive on --name laptop --notify off`.

### Names and paths

Use `--to @laptop` for your connected receiving machine. Without `@`,
`--to laptop` names an SSH destination instead.

Without `--into` or `--as`, files go into the profile's starting directory,
shown by `syq persist receive status`. Use either option to choose a path
relative to that directory, or an absolute path to copy elsewhere.

To contain copies within a directory instead:

```sh
syq persist receive on --name laptop --root ~/Downloads/server
```

With `--root`, incoming paths must be relative and stay inside that directory,
even when following symlinks. Use `--no-root` to remove this restriction. See
[Directories](persistence-reference.md#directories) for how the starting
directory and roots interact.

Changing a profile's settings, other than `--notify`, stops its active copies,
commands, and pending requests. Copies you approved between two servers keep
running; see [Copying between servers](security.md#copying-between-servers)
for how to stop them.

<a id="unattended-copies"></a>

### Skip approval for downloads

Choose a directory for downloads that do not need approval:

```sh
syq persist receive on --name laptop --auto-approve-root ~/Downloads/server
```

Downloads confined to that directory need no approval; downloads elsewhere,
and some options such as copying ACLs, still ask. `--root`, if configured,
remains a hard boundary. Automatic approval trusts all processes running as
the connected server accounts, including to overwrite files inside that
directory. You can [limit a profile to particular connections](persistence-reference.md#choose-allowed-connections).
Commands, restricted copies between servers, and storage authorization still
need their own approval; see [Receivers](security.md#receivers) for the trust boundary.

To require approval for every download again:

```sh
syq persist receive on --name laptop --no-auto-approve-root
```

### Copy permissions and limits

By default, each copy is limited to 100 GiB and one million entries (changes
it makes, such as files written and directories created). Pruning
is off until you set a deletion limit; a copy that would delete more removes
nothing. Change limits with
`syq persist receive on --name laptop --max-bytes SIZE --max-entries N --max-delete N`.
Copies are refused while syq runs as root. See
[copy limits](persistence-reference.md#copy-limits) for details.

## Run commands on your laptop

From the server, request a command in a project directory on your laptop:

```sh
syq exec --on @laptop --cwd /path/to/project -- make
syq exec --on @laptop --cwd /path/to/project -- open report.html
```

The second command opens a report with macOS's `open`; any program installed
on your laptop works.

Every command requires approval on your laptop and runs with your local user's
permissions, including access to files and credentials. **The download root
and copy limits do not restrict commands.** Build tools and scripts can execute
code from their input files, so consider those files when approving a command.

Output streams back to the server terminal, and syq returns the command's exit
code. Interrupting the request or stopping receiving stops the command;
completed changes are not rolled back. See [`syq exec`](commands/exec.md)
for arguments, working directories, and cancellation details.

## Open a shell on another server

From hostA, use your laptop's SSH credentials to open a direct connection to
hostB:

```sh
syq ssh --auth-from @laptop user@hostB
syq ssh --auth-from @laptop hostB -- hostname
```

Approve the destination account on your laptop. This permits arbitrary
commands as that account; the approval is not limited to the command shown.
Session traffic goes directly between the servers, and your ordinary SSH
agent is not forwarded. Keep the laptop connection open during the session.
See [`syq ssh`](commands/ssh.md) for commands, terminals, and requirements.

## Use an SSH authorization provider

An ordinary SSH server can supply authorization instead of a connected laptop.
Install the same syq build on both machines. On the provider, load the
destination keys into its SSH agent and enable receiving from that
environment; then save the provider's SSH endpoint where you work:

```sh
# On the provider:
syq persist receive on --notify off

# Where you work:
syq persist auth-from alice@provider:2222
syq ssh hostB -- hostname
```

Approve each destination account on the provider with
`syq persist receive pending` and `syq persist receive approve REQUEST_ID`.
Your agent is not forwarded, and commands and file data travel directly to
hostB. The provider's SSH server must allow local forwarding
(`AllowTcpForwarding` and `AllowStreamLocalForwarding` set to `local` or
`yes`), and the login key's `authorized_keys` entry must not block it with
`restrict` or `no-port-forwarding`. After updating syq, run
`syq persist receive on` on the provider again.

Anyone who can log in to the provider account can use its credentials without
going through syq's approval controls; see
[provider trust](security.md#ordinary-ssh-authorization-providers).

## Authorize copies between servers

Use your laptop's SSH access while working in hostA's shell:

```sh
syq cp results --to hostB --into /archive --auth-from @laptop
syq cp --from hostB /archive/results --into . --auth-from @laptop
```

Selecting `@laptop` asks for access to hostB's account on first use. The approval
permits arbitrary commands and file access as that account. See
[account permissions](persistence-reference.md#account-permissions) for the
approval's lifetime and how to manage it on the laptop. File data travels
directly between the servers, and you do not need to forward your agent.

`--auth-from` and the `SYQ_AUTH_FROM` [environment variable](environment.md#choose-authorization-through-the-environment)
choose how much to trust hostA:

- `auto`, the default, uses hostA's own SSH access. When that fails, it asks
  your laptop to approve just this copy; the approval names the permitted
  paths and applies your laptop's copy limits. If hostA's own credentials
  failed rather than being absent, syq first prints one line saying what went
  wrong.
- `@laptop` asks once for access to each destination account, as described
  above. Like forwarding your SSH agent, that access lets the server run any
  command as that account while it lasts.
- `ssh` uses only hostA's own SSH access and never asks your laptop.

An upload approved under `auto` finishes even if your laptop disconnects. The
first one to an account sets up hostB's
[enrollment](remote-reference.md#enrollment) over your laptop's SSH login. A
download approved this way needs a direct encrypted TCP connection between the
servers; account access with `@laptop` works over SSH too. See [authorization
selection](remote-reference.md#authorization-selection) for the options each
route supports.
