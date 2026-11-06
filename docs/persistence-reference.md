# Persistence details

This page answers questions that come up after setup. To set up, start with
[Keep connections open](persistence.md) or
[Use your laptop from a server](receive.md);
[`syq persist`](commands/persist.md) lists every option. Commands use the
default persistence domain unless you pass `--pscope PATH` for an
[isolated one](#isolated-script-scopes).

## Account access

These sections cover choosing, setting up, and ending a server's use of your
laptop's SSH access, as in
[Open a shell on another server](receive.md#open-a-shell-on-another-server).
See [SSH account access](security.md#ssh-account-access) for what approving it
grants.

### Authorization defaults

`--auth-from` chooses who authorizes a command's SSH logins:

| Value | Meaning |
|---|---|
| `auto` (default) | This machine's own SSH access. If that fails, a copy between this machine and one other server can ask a receiving machine to approve just that copy; see [Authorization selection](remote-reference.md#authorization-selection). |
| `ssh` | Only this machine's own SSH access |
| `@NAME` | Only access to the destination account through that receiving machine, never this machine's own |
| `[USER@]HOST[:PORT]` | The same, through an [SSH authorization provider](#ssh-authorization-providers) |

To avoid typing the option on a server, save a choice there:

```sh
syq persist auth-from @laptop                # default for all hosts
syq persist auth-from ssh --for backup       # choice for one host
syq persist auth-from                        # show saved choices
syq persist auth-from --reset --for backup   # remove one host's choice
syq persist auth-from --reset                # restore the default to auto
```

A command uses the first of these that is set:

1. Its `--auth-from` option (`--syq-auth-from` for `syq rsync`).
2. The `SYQ_AUTH_FROM` environment variable; an empty value counts as unset.
3. The saved choice for the host name exactly as typed in the command, without
   expanding aliases.
4. The saved default.
5. `auto`.

Saved choices apply to every command that takes `--auth-from`, whether or not
persistence is on, so with `@laptop` saved, `syq persist connect hostB` opens
an approved account connection. They do not affect a custom `--rsh` command,
copies to receiving names, or object storage; S3 needs an explicit
`--auth-from @NAME`.

### Approved account connections

After you approve account access, the server keeps an approved account
connection to that account and reuses it for later commands that select the
same provider, including copies, `rsync`, `rm`, and `map`. To open one in
advance, run `syq persist connect HOST --auth-from @NAME`. `syq persist off`
closes them, and `persist status --json` lists them in
[`authorized_ssh`](automation.md#connection-status).

To use an approved connection with plain `ssh`, `scp`, Git, or rsync, export
an OpenSSH configuration for it:

```sh
syq persist ssh-config hostB > hostB.ssh
ssh -F hostB.ssh hostB hostname
scp -F hostB.ssh report hostB:report
GIT_SSH_COMMAND='ssh -F hostB.ssh' git clone hostB:project.git
```

The host you export must match the login, host, and port that opened the
connection. The file contains no private key and works only while the connection
is open, so export it again after reconnecting.

Account access needs:

- OpenSSH 8.9 or newer for the requesting server's SSH client and the
  destination's SSH server.
- Your laptop's key in its SSH agent.
- Plain host keys for both servers that your laptop trusts; host certificates
  alone are not enough. Your laptop looks up each key under the host name typed
  on the server, or the `HostKeyAlias` its own SSH configuration gives that
  name.

The requesting server's SSH configuration chooses the destination account,
address, port, and route. An `IdentityFile` there that names a public key
selects the matching key in your laptop's agent.

When a copy carries file data over SSH, each SSH connection logs in under the
same permission without another prompt, so the laptop or provider must stay
available. An agent that requires confirmation or a touch asks for each one.

### SSH authorization providers

An [SSH authorization provider](receive.md#use-an-ssh-authorization-provider)
needs the same syq build as the machines that use it. The first receiving
profile in its default domain (the one `receive status` lists first) must be
enabled. Its SSH server must allow local forwarding (`AllowTcpForwarding` and
`AllowStreamLocalForwarding` set to `local` or `yes`), and the login key's
`authorized_keys` entry must not disable it with `restrict` or
`no-port-forwarding`.

### Account permissions

**Allow** lasts until the laptop's receiving connection to the requesting
server ends, or for a provider, until that provider login ends. **Remember**
lasts until you remove it:

```sh
syq persist receive approve REQUEST_ID --remember
syq persist receive permissions list
syq persist receive permissions remove PERMISSION_ID
```

To cut off access, run `syq persist off` on the requesting server and
`syq persist receive off` on the laptop; see
[SSH account access](security.md#ssh-account-access) for what this does not
undo. Remembered permissions belong to the laptop's domain. Creating a new
domain on the server does not revoke what that server account was already
granted.

## Names and profiles

To use different receiving names, directories, or approval rules for different
work, create receiving profiles. Each has its own name, starting directory,
roots, limits, and allowed servers, and a new one starts with the usual
defaults rather than another profile's settings:

```sh
mkdir -p ~/work/project
syq persist receive on --name laptop --cwd ~ --connection server
syq persist receive on --name project --root ~/work/project --connection server
```

On the server, `syq cp results --to @project` and
`syq cp report.pdf --to @laptop` then use different profiles.

### Change or stop a profile

`receive on --name NAME` creates or updates a profile; options you omit keep
their saved values. Without `--name`, it updates the first profile that
`receive status` lists. It connects to the servers you give with
`--connection` and waits until receiving is ready on them. If one connection
fails, the settings stay saved and the others keep running, but the command
exits unsuccessfully.

Changing a profile's access settings, stopping it, or removing it cancels that
profile's running copies, commands, and pending approvals; changing only
`--notify` cancels nothing. Copies it approved between two servers keep running
until they finish, someone interrupts them on the server, or you revoke the
destination's enrollment with `syq receiver revoke`. `receive off` without a
name stops every profile.

<a id="choose-allowed-servers"></a>

### Choose allowed connections

To give one server account an inbox for downloads that need no approval:

```sh
mkdir -p ~/Downloads/work
syq persist receive on --name work-inbox --connection work \
  --auto-approve-root ~/Downloads/work
```

On `work`, use `syq cp results --to @work-inbox`. Other servers cannot use
that profile, and your general profile can still ask before every download.

Without `--connection`, a profile accepts every SSH connection in its domain.
Each `--connection` matches the destination exactly as your laptop connects to
it, as `persist status` shows it (`work`, `alice@work`, or `alice@work:2222`),
without expanding aliases. Because the match uses your laptop's name for the
server, changing your SSH configuration can change which account an allowed
name reaches. Each list you give replaces the saved one, and
`--all-connections` removes the restriction.

### Move a name to another machine

A receiving name stays with the machine that claimed it, even while that
machine is offline, so another laptop cannot take it over. To move it, stop
receiving on the old laptop, run `syq persist destinations forget laptop` on
the server, then run `syq persist connect server` on the new laptop.

### Back up the receiving identity

Your receiving names are tied to the key in `~/.syq-receiver-identity/`, which
all profiles, domains, and syq versions share. Keep it in private backups; if
you lose it, you have to `forget` your names on each server. Another machine
with a copy of it has the same identity, but only one machine can hold a name at
a time, so give machines that receive at the same time different profile names.

## Directories

To control where downloads land and which need approval, use these
independent settings:

| Setting | Purpose | Clear it with |
|---|---|---|
| `--cwd DIR` | Starting directory for relative paths | `--auto-cwd` |
| `--root DIR` | Hard boundary for downloads, even with approval | `--no-root` |
| `--auto-approve-root DIR` | Downloads confined here, including pruning up to `--max-delete`, skip approval, except with `--widen-dirs all` | `--no-auto-approve-root` |

Each must be an existing directory, and neither root can be `/`. Without
`--cwd`, downloads start in the hard root if set, otherwise the automatic
approval root if set, otherwise your home directory.

Downloads outside the hard root are refused, even with approval; inside it,
downloads outside the automatic approval root ask. Symlinks cannot extend
automatic approval outside its root, and replacing that root directory itself
asks, or is refused when it is also the hard root. Neither root restricts
approved commands or copies you approve between servers.

<a id="copy-limits"></a>

## Copy limits and restrictions

Each copy to a receiving name may write up to 100 GiB and one million entries
by default. Entries are the changes it makes, such as files written,
directories created, metadata changes, and deletions. Change the limits with
`syq persist receive on --max-bytes 20G --max-entries 100000`; the sender can
only lower them. They apply per copy, so repeated copies can still fill the
disk.

A pruning copy is refused until you set a positive `--max-delete`. After that, a
pruning copy that plans more deletions than your `--max-delete` or
`--max-entries`, or its own `--max-delete`, deletes nothing and exits 25, and so
does its dry run, so you can check first.

Copies to a receiving name are refused while syq runs as root on the receiving
machine. They cannot preserve hard links, ACLs, extended attributes, or access
or birth times, and cannot use `--open-noatime` or `--sparse`; the other
`--copy-metadata` options work as for any copy by an account other than root.
They never follow a destination symlink, even with `--follow-dst`; name the
link's target instead.

## Connection lifetime and waits

`syq persist connect server` connects right away and, with receiving on, waits
until receiving is ready. `--timeout 30` limits that wait, not the SSH login
or installing syq on the server. `syq ssh` reuses or opens a persistent login
but does not start receiving.

In an isolated domain, idle SSH connections close after five to ten minutes;
in the default domain they stay open. Syq installs no login service, so
connect again after a reboot. After you update syq, receiving and the SSH
authorization provider switch to the new version once no copy, command, or
approval is in progress, by themselves or when you next run syq.
`syq --self-update`, `syq persist status`, `syq persist on`,
`syq persist connect`, and `syq persist receive status` switch idle receiving
at once, logging in as `syq persist connect` does, but not with `--json`.
`syq persist status` says why receiving still runs an older version.
`syq persist receive on`, `receive off NAME`, and `receive remove NAME` switch
it even when busy, which cuts off copies and approvals in progress. If
receiving needs you to unlock or touch your SSH key, it waits until you next
run a syq copy or ssh command, or `syq persist status`, in a terminal. An
account connection you approved keeps the old version until that connection
closes; `syq persist status` shows the command that switches at once and
closes it. Session permissions (**Allow**) end at the switch, as at any
reconnect.

To wait in a script without starting a connection, run
`syq persist receive wait server --timeout 30` on the laptop, or
`syq persist destinations wait laptop --timeout 30` on the server. For
structured status, see [connection status](automation.md#connection-status).

## Isolated script scopes

To keep a script's connections and settings apart, create an isolated domain
and pass its path to each command with `--pscope PATH` (`--syq-pscope PATH`
for rsync):

```sh
scope=$(syq persist on --ephemeral)
syq persist --pscope "$scope" auth-from @laptop
syq ssh --pscope "$scope" hostB -- hostname
syq cp --pscope "$scope" report --to hostB --as report
syq persist --pscope "$scope" off
```

A new domain starts with receiving off and default authorization choices, and
shares none of the default domain's settings or connections. To receive
through one on your laptop, run
`syq persist --pscope PATH receive on --name project --connection server` with
a name not already connected to that server account.

`persist off` on an isolated domain closes its connections and deletes its
settings and remembered permissions; the path cannot be reused. On the default
domain, it only closes connections. A domain does not isolate processes of the
same account from each other (see
[Persistent connections](security.md#persistent-connections)), and all domains
share receiving names.

<a id="updating-connections"></a>

## Setup and recovery

If approval prompts do not appear, start receiving from a terminal in your
desktop session; after logging in to a new session, run
`syq persist receive off` and enable your profiles again from there. Linux
prompts need libnotify 0.7.10 or later and a notification service.
`syq persist receive pending` shows requests and prompt errors, and
`--notify off` switches to terminal approval. A prompt's note that a copy
replaces existing files is only advisory, because files can change before the
copy runs.

If receiving does not reconnect, check that your SSH key or agent is available
and that the server's host key is already trusted; the background service
cannot ask for a password. The server must allow remote forwarding:
`AllowStreamLocalForwarding` and, from OpenSSH 7.8, `AllowTcpForwarding` set
to `remote` or `yes`. When a server refuses forwarding, receiving through it
stops; after a rejected login or changed host key, it retries with waits of up
to 10 minutes. `syq persist status` shows the reason, and
`syq persist connect server` retries at once.
