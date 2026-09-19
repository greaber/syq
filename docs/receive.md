<a id="send-files-home-from-a-server"></a>

# Use your laptop from a server

Receiving lets you do three things from a connected server:

- [Copy files to your laptop](#copy-files-to-your-laptop).
- [Run commands on your laptop](#run-commands-on-your-laptop).
- [Authorize copies between servers](#authorize-copies-between-servers)
  using your laptop's SSH credentials.

All three use a [persistent connection](persistence.md) opened by your laptop.
It needs no SSH server, public address, or incoming network port.

## Set up receiving

<a id="ssh-setup"></a>
<a id="persistence-in-scripts"></a>
<a id="updating-receiving-connections"></a>
<a id="background-connections"></a>

Receiving starts automatically when syq opens a persistent SSH connection,
unless you have turned it off or restricted its profiles to other servers.
To enable persistence and connect to a server now, run this on your laptop
with syq installed on both machines:

```sh
syq persist connect server
```

This opens the connection and waits until receiving is ready. An ordinary
`ssh server` session does not enable receiving. If you already have a persistent
connection to this server, you do not need to connect again. For example, after
`syq persist on`, a syq copy or remote path completion can open that connection.
If you previously turned receiving off, run `syq persist receive on` first.

By default, your receiving name is your laptop's short hostname, and downloads
and commands start in your home directory. `connect` prints the receiving name.
The examples below use `@laptop`; replace it with your own name.

Once `connect` finishes, you can close that terminal and make requests from any
shell on the server, including an existing tmux session.

### Optional name and directory

To create a receiving profile named `laptop` with a different starting
directory, run these commands on your laptop:

```sh
mkdir -p ~/Downloads/server
syq persist receive on --name laptop --cwd ~/Downloads/server
```

Here, `receive on` configures the profile; it is not required to use the default
settings. `--cwd` sets the starting directory for downloads and commands.

## Copy files to your laptop

On the server, send files to your receiving directory:

```sh
syq cp results --to @laptop
syq cp report.pdf --to @laptop --as reports/latest.pdf
```

### Approving copies

By default, each incoming copy waits for approval **on your laptop**. Review the destination
and permissions, then choose **Allow once** or **Deny**. To see the complete
request, use **Details** on macOS or `syq persist receive pending` in a local
terminal. You can also approve or deny there:

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
[limit a profile to particular servers](#different-settings-for-different-servers).

Commands on your laptop and authorization for copies between servers still
require approval every time. See [Receivers](security.md#receivers) for the
trust boundary.

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

## Authorize copies between servers

Use your laptop's SSH access to [copy directly between servers](remote-to-remote.md),
while running the command in your source server's shell:

```sh
# Run on hostA, including in an existing tmux shell.
syq cp results --to hostB --into /archive --auth-from @laptop
```

Your laptop asks for approval for each copy, then uses its SSH access to hostB
to authorize it without giving the source server your private SSH keys.
Trust hostB's SSH host key on the laptop beforehand. Relative destination paths
start in the hostB account's home directory; your laptop's receiving root does
not contain this copy, but its transfer limits still apply.

Files go directly from hostA to hostB over encrypted TCP. HostB needs a
reachable data port; see [Make TCP reachable](server-tuning.md#make-tcp-reachable).
This route cannot use SSH for file data. Keep the laptop connection and source
command running until completion. See
[Authorization selection](remote-reference.md#authorization-selection) for
automatic selection, other authorizers, and supported options.

## Multiple receiving profiles

Give a project its own receiving name and directory:

```sh
syq persist receive on --name project --root ~/work/project
syq persist connect server
```

Then run `syq cp results --to @project` on the server. The directory must already
exist. Each name has its own settings and approval policy, so you can keep a
project separate from your general `laptop` destination.

Use `syq persist receive status` to list profiles and
`syq persist receive off --name project` to stop one. See
[Names and profiles](persistence-reference.md#names-and-profiles) for more options
and for moving a name to another laptop.

### Different settings for different servers

By default, each enabled profile is available through every connected server.
To give a particular server its own inbox:

```sh
mkdir -p ~/Downloads/work
syq persist receive on --name work-inbox --server work \
  --auto-approve-root ~/Downloads/work
syq persist connect work
```

On `work`, download with `syq cp results --to @work-inbox`. Other connections
cannot use that profile. Your general profile can still ask for approval on
every download. Repeat `--server` to allow several connections, or use
`--all-servers` to remove the restriction. See the
[profile reference](persistence-reference.md#names-and-profiles) for how SSH
destination names match.
