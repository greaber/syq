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
and waits until receiving is ready. Repeat `--connection` to allow and connect
several endpoints. A later `syq persist receive on` reconnects the saved list.
With no saved list, it uses tracked connections and future syq connections;
an ordinary `ssh server` session does not enable receiving.

By default, your receiving name is your laptop's short hostname, and downloads
and commands start in your home directory. The command prints the receiving
name. The examples below use `@laptop`; replace it with your own name.

You can close that terminal and make requests from any shell on the server,
including an existing tmux session. In the default persistence domain, receiving
also starts automatically with persistent connections unless you have turned it
off or restricted the profile. Fresh [isolated domains](persistence-reference.md#isolated-script-scopes)
start with receiving off; add `--pscope PATH` to configure and manage one.

### Optional name and directory

To create a receiving profile named `laptop` with a different starting
directory, run these commands on your laptop:

```sh
mkdir -p ~/Downloads/server
syq persist receive on --name laptop --cwd ~/Downloads/server --connection server
```

This configures the profile and connects it. `--cwd` sets the starting directory
for downloads and commands. Omitted settings retain their saved values.

## Copy files to your laptop

On the server, send files to your receiving directory:

```sh
syq cp results --to @laptop
syq cp report.pdf --to @laptop --as reports/latest.pdf
```

File data uses encrypted TCP when your laptop can reach a data port on the
server, with SSH as a fallback. Your laptop opens both connections; it still
needs no incoming port. Use `--no-tcp` to send all data through SSH.
See [Make TCP reachable](server-tuning.md#make-tcp-reachable) for server setup.

### Approving copies

By default, each incoming copy waits for approval **on your laptop**. The prompt
names the server and the directory the command ran in, then shows what is
copied where and the server's syq command; choose **Allow once** or **Deny**.
To see the complete request, including its limits, run
`syq persist receive pending` in a local terminal. You can also approve or
deny there:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

Approving a copy trusts the server to supply its contents. Requests expire after
five minutes. If a prompt is missing or dismissed, the request stays pending;
it is never approved automatically. To use only terminal approval, run `syq persist receive on --name laptop --notify off`.

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
even when following symlinks. Use `--no-root` to remove this restriction;
changing `--cwd` does not remove it. Unless you set `--cwd`, the starting
directory follows the hard root, then the automatic approval root, then your
home directory. See [Directories](persistence-reference.md#directories) for
changing or resetting these settings.

Changing a profile's settings stops its active copies, commands, and pending
requests. Other profiles keep working.

<a id="unattended-copies"></a>

### Skip approval for downloads

Choose a directory for downloads that do not need approval:

```sh
syq persist receive on --name laptop --auto-approve-root ~/Downloads/server
```

Downloads confined to that directory need no approval; downloads elsewhere ask.
`--root`, if configured, remains a hard boundary even with approval.
Automatic approval trusts all processes running as the connected server accounts,
including for overwrites inside that directory. You can
[limit a profile to particular connections](persistence-reference.md#choose-allowed-connections).

Commands on your laptop, restricted copies between servers, and storage
authorization require their own approval. SSH account access can use a current
session permission or an explicitly remembered permission. See
[Receivers](security.md#receivers) for the trust boundary.

To require approval for every download again:

```sh
syq persist receive on --name laptop --no-auto-approve-root
```

### Copy permissions and limits

By default, each copy is limited to 100 GiB and one million entries. Pruning
requires a positive deletion limit on both machines. Change limits with
`syq persist receive on --name laptop --max-bytes SIZE --max-entries N --max-delete N`.

Most copy options work here; ownership preservation, special-file preservation,
and `--inplace` are unsupported. See
[copy limits](persistence-reference.md#copy-limits) for details.

## Run commands on your laptop

From the server, request a command in a project directory on your laptop:

```sh
syq exec --on @laptop --cwd /path/to/project -- make
syq exec --on @laptop --cwd /path/to/project -- open report.html
```

The second command uses macOS's `open` program to display a report. Replace
it with any program installed on your laptop.

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
On the provider, load the destination keys into its local SSH agent and enable
receiving from that environment:

```sh
syq persist receive on --notify off
```

On the machine where you work, save the provider's SSH endpoint:

```sh
syq persist auth-from alice@provider:2222
syq ssh hostB -- hostname
syq cp results --to hostB
```

The first operation connects to the provider using your machine's native SSH
credentials. Your machine's SSH configuration determines `hostB`'s address,
account, and route. The provider checks trusted host keys and asks for
destination-account approval. Inspect and approve requests there with
`syq persist receive pending` and `syq persist receive approve REQUEST_ID`.
Later commands reuse both connections; `persist connect` is optional.
Your agent is not forwarded, and commands and file data travel directly to hostB.
The provider's SSH server must allow local forwarding: both
`AllowTcpForwarding` and `AllowStreamLocalForwarding` must allow `local` or `yes`.
Syq uses the provider's first configured receiving profile in its default
persistence domain; that profile must be enabled. Remote profile and domain
selection are not supported. See [provider selection](persistence-reference.md#approved-account-connections)
for how this differs from a local `--pscope`.

This uses a full SSH login to the provider account. Anyone who can log in to
that account can use its credentials independently of syq's approval controls.
It centralizes credentials but does not make that account a restricted shared
authorization service. See [provider trust](security.md#ordinary-ssh-authorization-providers).

## Authorize copies between servers

Use your laptop's SSH access while working in hostA's shell:

```sh
syq cp results --to hostB --into /archive --auth-from @laptop
syq cp --from hostB /archive/results --into . --auth-from @laptop
```

Selecting `@laptop` asks for access to hostB's account on first use. The prompt
permits arbitrary commands and file access as that account. **Allow** covers
later copies and commands while the laptop's receiving connection to hostA
remains open; **Remember** permits future logins for the same accounts.
[Manage those permissions on the laptop](persistence-reference.md#account-permissions).

Uploads and downloads reuse the approved login and support `--no-tcp`, helper
overrides, and `--inplace`. File data travels directly between the servers.
You do not need to run `persist connect` first or forward your agent.

With `auto`, eligible copies can instead ask for restricted per-copy approval
after native SSH fails. That approval names permitted paths and applies transfer
limits. Restricted uploads use direct TCP or SSH; both explicit `--no-tcp` and
automatic TCP-to-SSH fallback temporarily add a copy-restricted key to hostB's
`authorized_keys`. Restricted source-read downloads require direct TCP and do
not write SSH authorization on the source. Account-approved downloads can use
SSH in either direction. See [authorization selection](remote-reference.md#authorization-selection)
for routing details.
