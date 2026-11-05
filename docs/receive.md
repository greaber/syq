<a id="send-files-home-from-a-server"></a>

# Use your laptop from a server

Receiving lets you work in a server's shell and still use your laptop: copy
files to it, run commands on it, and let the server use your laptop's SSH or
storage credentials with your approval. It runs over a
[persistent connection](persistence.md) that your laptop opens, so your laptop
needs no SSH server, public address, or incoming network port.

Start with [Set up receiving](#set-up-receiving). Each later section is a
separate task, so read only the one you need:

- [Copy files to your laptop](#copy-files-to-your-laptop).
- [Run commands on your laptop](#run-commands-on-your-laptop).
- [Authorize copies between servers](#authorize-copies-between-servers) when
  the server can't log in to the other server itself.
- [Open a shell on another server](#open-a-shell-on-another-server) with your
  laptop's SSH credentials.
- [Use an SSH authorization provider](#use-an-ssh-authorization-provider)
  instead of a laptop.
- [Authorize object-storage transfers](object-storage.md#authorize-from-your-laptop)
  with your laptop's storage credentials.

<a id="ssh-setup"></a>
<a id="persistence-in-scripts"></a>
<a id="updating-receiving-connections"></a>
<a id="background-connections"></a>
<a id="optional-name-and-directory"></a>

## Set up receiving

With syq installed on both machines, and the server's SSH server allowing
remote forwarding (see
[Setup and recovery](persistence-reference.md#setup-and-recovery)), run this
on your laptop:

```sh
syq persist receive on --connection server
```

This turns on receiving for `server`, waits until it's ready, and prints your
receiving name: your laptop's short hostname, unless you choose another with
`--name`. The examples below use `@laptop`. You can then close that terminal
and make requests from any shell on the server, including an existing tmux
session.

After your laptop restarts, run `syq persist connect server` again; logging
in with `ssh server` doesn't restart receiving.

To allow several servers, repeat `--connection`; a new list replaces the saved
one. See [Names and profiles](persistence-reference.md#names-and-profiles) to
use separate names and settings for different projects.

<a id="approving-copies"></a>
<a id="names-and-paths"></a>

## Copy files to your laptop

On the server:

```sh
syq cp results --to @laptop
syq cp report.pdf --to @laptop --as reports/latest.pdf
```

Write the `@`: without it, `--to laptop` names an SSH server. Files go to the
profile's starting directory (your home directory unless you set `--cwd`,
`--root` or `--auto-approve-root`), or to a path you give with `--into` or
`--as`, relative to that directory or absolute.

Each copy waits for approval **on your laptop**. The prompt shows the server,
what is copied where, and a warning for each option that lets the server do
more than copy files, such as pruning or copying permissions. Choose
**Allow once** or **Deny**. Approving a copy trusts the server to supply its
contents. Requests expire after five minutes; if no prompt appears, approve in
a terminal on your laptop:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
```

<a id="unattended-copies"></a>
<a id="skip-approval-for-downloads"></a>
<a id="copy-permissions-and-limits"></a>

By default, each copy can write at most 100 GiB and make at most one million
changes, and it can't delete files. If you need to, change these and other
optional settings with `syq persist receive on` on your laptop:

- `--max-bytes`, `--max-entries` and `--max-delete` change the limits; see
  [Copy limits](persistence-reference.md#copy-limits).
- `--cwd DIR` changes where downloads start, and `--root DIR` confines them to
  a directory; see [Directories](persistence-reference.md#directories).
- `--auto-approve-root DIR` lets downloads into that directory skip approval.
  This trusts every process running as any server account the profile
  allows to write there, including overwriting files; see
  [Receivers](security.md#receivers).
- `--notify off` turns off desktop prompts, so you approve only in a terminal.

Changing any of these except `--notify` cancels active copies, commands and
pending requests. Copies you approved between two servers keep running; see
[Copying between servers](security.md#copying-between-servers) to stop them.

## Run commands on your laptop

From the server, run a command in a directory on your laptop:

```sh
syq exec --on @laptop --cwd /path/to/project -- make
syq exec --on @laptop --cwd /path/to/project -- open report.html
```

The second command opens a report with macOS's `open`; any program installed
on your laptop works. Output streams back to the server terminal, and syq
exits with the command's exit code. Interrupting the request or stopping
receiving stops the command, but doesn't undo what it changed.

Every command needs approval on your laptop and runs with your local user's
permissions, including access to files and credentials. **The download root
and copy limits don't restrict commands.** Build tools and scripts can run
code from their input files, so consider those files when approving a
command. See [`syq exec`](commands/exec.md) for arguments and working
directories.

## Authorize copies between servers

In hostA's shell, copy to or from hostB as usual:

```sh
syq cp results --to hostB --into /archive
syq cp --from hostB /archive/results --into .
```

If hostA can't log in to hostB itself, syq asks your laptop to approve just
this copy, within your laptop's copy limits. File data goes directly between
the servers, so hostA must reach hostB directly, without a `ProxyJump`; see
[What you need](remote-to-remote.md#what-you-need). Once approved, an upload
finishes even if your laptop disconnects. A download needs the laptop
connection throughout, and a direct encrypted TCP connection between the
servers. See [Authorization selection](remote-reference.md#authorization-selection)
for the options this supports, and add `--auth-from ssh` to use only hostA's
own SSH access.

## Open a shell on another server

From hostA, log in to hostB with your laptop's SSH credentials, without
forwarding your SSH agent:

```sh
syq ssh --auth-from @laptop user@hostB
syq ssh --auth-from @laptop hostB -- hostname
```

Your laptop asks once for access to the hostB account. **Approving lets hostA
run any command as that account while the approval lasts**, whatever command
the prompt shows; see [SSH account access](security.md#ssh-account-access).
Keep the laptop connection open while you work.

Later commands reuse the approval, including copies with `--auth-from @laptop`.
To make your laptop the default on hostA, run `syq persist auth-from @laptop`.
See [Account access](persistence-reference.md#account-access) for how long
approval lasts,
[Approved account connections](persistence-reference.md#approved-account-connections)
to use `scp`, Git or other SSH tools through it, and
[`syq ssh`](commands/ssh.md) for terminals and exit status.

## Use an SSH authorization provider

Instead of a laptop, a server you can log in to over SSH can supply the
authorization. Install the same syq build on both machines. On the provider,
load the destination keys into an SSH agent and turn on receiving in a shell
that uses that agent; then save the provider's SSH address where you work:

```sh
# On the provider:
syq persist receive on --notify off

# Where you work:
syq persist auth-from alice@provider:2222
syq ssh hostB -- hostname
```

Approve each destination account on the provider with
`syq persist receive pending` and `syq persist receive approve REQUEST_ID`.
The provider's SSH server must allow local forwarding; see
[SSH authorization providers](persistence-reference.md#ssh-authorization-providers).
Anyone who can log in to the provider account can use its credentials without
going through syq's approval; see
[provider trust](security.md#ordinary-ssh-authorization-providers).
