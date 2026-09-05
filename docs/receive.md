# Send files home from a server

Inspect files on your server, then copy them to your laptop from the same shell.
The laptop opens and maintains the connection. It needs no SSH server, public
address, or incoming network port.

On your laptop, choose an existing receiving directory:

```sh
mkdir -p ~/Downloads/server
syq receive --via server --name laptop --into ~/Downloads/server
```

Leave this command running. On the server, use the destination from any shell,
including a tmux session that was already open:

```sh
ls -lh results
syq cp results --to @laptop
syq cp report.pdf --to @laptop --as reports/latest.pdf
```

The laptop asks in the terminal running `syq receive` whether to allow each
copy. Type `y` or `yes` to allow it once; any other answer denies it. Requests
expire after five minutes. The prompt describes the destination and enforced
permissions and limits. It does not claim to have inspected the server's files.

`@laptop` is a name registered on that server account, independent of your
login shell. Use a different name for each laptop. Ordinary `--to server`
continues to mean an SSH host.

## Paths and permissions

Destination paths are relative to the receiving directory. With no placement,
`--to @laptop` means `--into .` there. Absolute paths and `..` are refused.
Copies cannot traverse destination symlinks to escape the receiving directory.
The receiving directory itself cannot be replaced with `--as .`.

An approved copy may create files and overwrite matching files within its
approved scopes. Standard directory recursion, symlinks, modification times,
filters, hashing, and staged publication use the same copy engine as other
syq copies. `--preserve=permissions` requests permission preservation as well.
Ownership, special-file preservation, `--inplace`, mappings, and `--min-size`
are not accepted by named destinations.

To permit copies automatically, including overwrites:

```sh
syq receive --via server --name laptop --into ~/Downloads/server --approve always
```

This authorizes requests from any process running as that server account.
Use a directory whose contents that account may change. A compromised server
can send unwanted files or invented data, and copy planning exposes information
about existing destination entries. It receives neither your SSH agent nor
permission to run arbitrary commands on the laptop.

Each transfer is limited to 100 GiB and one million touched entries by default.
These are permission ceilings, not estimates of the selected files' size.
Use `--max-bytes` and `--max-entries` on `syq receive` to change them. Lower
limits requested by the sending command also apply. Limits are per transfer;
repeated approved copies can fill the receiving disk.

Deletion is disabled unless the laptop permits a positive `--max-delete`.
A sending `--prune` command must also supply its own `--max-delete` ceiling,
no higher than the laptop's. Denial and validation errors leave the requested
copy unstarted. Errors during a copy are reported as failures; incomplete
files can remain for a later retry. The sending command verifies the laptop's
signed receipt before reporting successful completion.

## Connections and reconnects

The connection has no idle expiry while `syq receive` is running. It is separate
from `syq persist`; enabling or disabling ordinary persistence does not control
this receiver. Data and control channels both travel through encrypted SSH.
Named transfers do not open TCP data listeners on the laptop.

After a network interruption or laptop sleep, the laptop reconnects with delays
of one to thirty seconds. An interrupted copy fails visibly: rerun it after
reconnection to reuse eligible partial files through normal resume checks.
Copies are not queued while the laptop is offline. Approval allows the control
channel to open once within sixty seconds; the transfer must finish within
seven days. Closing the control channel ends that copy's authority.

Press Ctrl-C in the receiving terminal to close its connection and stop
availability. The server keeps an offline name record so another receiving
setup cannot silently take over the name. Restarting the same receiving
command on the laptop reuses its saved identity.

On the server:

```sh
syq destination list
syq destination wait laptop --timeout 30
syq destination forget laptop
```

`wait` exits successfully when the destination responds, or fails at its
deadline. `forget` requires the registration's SSH session to have ended. Use
it deliberately when replacing a laptop, changing the receiving configuration,
or recovering after losing the laptop's saved identity. A running registration
cannot be displaced by another receiver.

## SSH setup

The laptop needs ordinary SSH access to the server, with a trusted host key and
an available key or agent for noninteractive reconnects. Connect with ordinary
SSH first if authentication or host trust is not configured. No agent is
forwarded to the server.

The SSH server must permit remote Unix socket forwarding. OpenSSH 9.2 also
requires remote TCP forwarding permission for these requests. Administrators
control those settings; syq does not change SSH server configuration. A rejected
forward produces an SSH error and the receiver retries until stopped.

The configured receiving directory must have a UTF-8 path; filenames inside
it can use the normal Unix path bytes syq supports. Copies support at most
32 workers each.

Both machines must use the same syq build. The receiver uses syq's normal managed
helper setup; `--syq-path` selects an exact helper on the server. The server-side
`syq cp` executable must match it too. Upgrade both sides and restart the
receiver after an upgrade.

Private laptop identities live in `~/.syq-receive-v1`; server registrations live
in `~/.syq-destinations-v1`. Both directories must be owned by their user and
have mode 0700. These are separate from ordinary persistence preferences and
restricted receiver enrollments. Processes with access to the trusted laptop
account can change its authority; processes under the authorized server account
share that account's destination registrations.
