# Security

Syq often acts with more authority than the files or machines involved in a
copy. A backup account may read another user's directory, or your laptop may
authorize a copy between two servers. The protections below limit how those
files and servers can use that authority.

Report vulnerabilities through
[SECURITY.md](https://github.com/greaber/syq/blob/master/SECURITY.md).

## Filesystem safety

### Filesystem attacks

Suppose a backup account is copying an upload directory that another user can
change. That user could replace a subdirectory with a symlink to private files
elsewhere. A copy program that follows the link would read those files using
the backup account's permissions. At a destination, the same trick could
redirect writes or deletions into an unrelated directory.

Checking a path before starting is not enough: someone who can write its parent
directory may replace it while the copy is running. Syq therefore keeps
directories open and works on their entries through those open directories, so
renaming a directory or replacing its name with a symlink does not redirect
later operations. These checks assume the attacker can change directory
entries but does not control the account running syq.

The same principle applies to names supplied by a remote machine and to
removal:

- **A remote source tries to escape the destination.** If you are copying into
  `backup`, a peer cannot make an entry named `../private/key` or `/private/key`
  write outside it. Syq rejects those names.
- **A directory becomes a symlink during copying.** If `backup/photos` is
  replaced with a link to another directory, syq either continues through the
  directory it already opened or refuses to traverse the link. It does not
  start writing into the link's target.
- **An entry changes during removal.** If a file selected for removal becomes
  a symlink, removing the link leaves its target alone. If it becomes a
  directory, syq does not start recursively deleting that directory's contents.

### Which symlinks are followed?

Native syq distinguishes paths you explicitly select from entries discovered
inside a tree:

| Where the symlink appears | Treatment |
|---|---|
| In a source path you supply | `--follow-src` permits following; a named link otherwise copies as a link |
| In a destination path you supply | `--follow-dst` permits following; `--as PATH` always replaces the final entry itself |
| Inside a source directory being scanned | Copied as a link; its target is not scanned or read |
| Inside a destination directory being scanned | Inspected as a link; its target is not scanned or written through. A copied file can replace the link, but a copied directory cannot use it as a directory |

`--follow` enables both source and destination following. These options affect
supplied paths only; they do not change either scan rule. See [Symlinks](reference.md#symlinks) for examples.

### Relationship to rsync 3.5.0

Syq uses the same basic approach as
[rsync 3.5.0's security design](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md#symlink-race-safe-path-resolution):
keep directories open and resolve later operations relative to them. The
policy for following links in supplied paths differs:

| Command | When a symlink in a supplied path may be followed |
|---|---|
| Rsync 3.5.0 or `syq rsync` | The link belongs to root or the process's effective user, or `--insecure-links` is set (local paths only in `syq rsync`) |
| Native syq | You explicitly request following with the applicable follow option above |

<a id="limits-to-keep-in-mind"></a>
<a id="privileged-copies-and-hard-links"></a>

### Limits of path protection

These protections apply when running as root too. They prevent paths from
redirecting an operation; they do not make all changes within the selected
directory safe. The following risks require separate attention, especially
when syq has more permissions than the people who can modify that directory.

**Existing files and their other names.** Syq writes new contents only into
files the copy creates. It updates an existing file by building a new one
beside it and renaming that over the name, so a hard link to the old file
elsewhere, or someone who already has it open, keeps the old contents. This
does not hold for an `--as-fd` output, which syq writes into the descriptor it
is given, or for `--in-place=update` (`syq rsync --inplace`), which writes
into an existing file, so anyone who already has it open can read the new
contents. Syq does that only where it gives no one access the copy would not;
see [In-place writes](reference.md#in-place-writes).

Syq likewise changes an existing file's metadata in place only when that
cannot affect another name or grant privileges, and otherwise replaces the
file (see [Copy metadata](reference.md#how-syq-changes-existing-files-and-directories)). So a hard link planted
in the destination never takes the copy's metadata, and root never hands a
file another user planted there to another owner or group, or gives it
privileges, even when its size and time match the source's. Access times are
the exception: `--copy-metadata=atimes` (`-U` in `syq rsync`) restores them in
place on any file, and they show through all of its names, including names
outside the copy. Directories also have their metadata changed in place.
Narrowing a file's permissions in place does not cut off someone who already
has it open.

**Permissions supplied by the source.** Path protection does not decide
whether copied permissions are appropriate. For example,
`--copy-metadata=permissions` can make a copied file writable by everyone or
preserve its set-user-ID bit; `--copy-metadata=ownership` can give it to the account
identified by the source's user ID. When running as root, those choices can
grant other users access or privileges. Enable these options only when you
trust the source's ownership and permission settings.

**Partial files.** Someone could plant a symlink or hard link where an old
partial file should be, hoping that resuming will overwrite another file, or
rename a file into the place of one being written. Syq writes partial files,
and files `--in-place=new` creates, only through files it created or opened
itself, and reuses bytes from an old partial only when it is a regular file
owned by its user with no other names, after checking them against the source.
A planted file is left unchanged. A file swapped in during the copy gets none
of its data or metadata, and syq reports that file as failed instead of
publishing what is at its name.

**Concurrent replacement of directory entries.** Checking an entry and
removing it are separate operations. Someone able to rename files in that
directory can replace the entry in between, causing syq to remove the new
entry instead. Similarly, publishing a copied file can replace another
writer's new file. These races do not cause syq to follow a replacement
symlink, but they can lose a concurrent writer's changes. Use a destination
other processes cannot modify if those changes must be protected.

**Named pipes.** If someone replaces an input file with a named pipe just
before syq opens it, the open can briefly wake the pipe's writer before syq
detects the change and fails, and the writer's data is discarded. On macOS, a
pipe swapped for another pipe can go unnoticed when the filesystem reuses the
inode number. Keep pipes used by sensitive producers in directories untrusted
users cannot modify.

<a id="code-and-transport-integrity"></a>
<a id="encryption-and-authentication"></a>
<a id="tcp-data-connections"></a>
<a id="malformed-or-stalled-peers"></a>

## Network security

Remote copies encrypt and authenticate file data, whether it travels through
SSH or syq's direct TCP connections.

`--no-tcp-encryption` disables this protection for TCP: someone on the network
can read or alter the traffic, including its authentication token. Use it only
on a network you trust.

## Downloaded executables

Official releases provide executables for each supported operating system and
CPU architecture, published as GitHub release assets and served through
`dl.syq.christmas`. An installed syq downloads them for explicit self-updates,
explicit `--use-version` selections, and, when needed, to install a matching
helper on an SSH server.

A signed release manifest lists the size and SHA-256 hash of each archive and
executable. The installed client verifies the manifest's Ed25519 signature with
the release public key it carries, not one supplied by the download server,
and checks downloaded files against the signed sizes and hashes before using
them. Source builds carry the official key for `--use-version` too. When an SSH
server downloads its own helper, your client verifies the manifest and the
reported archive hash before authorizing installation, and uploads a locally
verified helper over SSH instead if the download cannot be verified. A
download host therefore cannot substitute executable code without a valid
release signature, as long as the release signing key, your installed client,
and the SSH account remain trusted.

A selected release is verified once, when it is stored in `~/.local/lib/syq`.
Later runs start it without hashing it again, but refuse it if its files or
directories in the store are not yours or others can write them. The store
trusts the directories above it: anyone who can write them can replace the
store, just as anyone who can write `~/.local/bin` can replace syq, so those
directories should be writable only by you.

The first installation establishes that trust. The standalone installer checks
the archive against a size and SHA-256 hash embedded in the script, but it does
not independently verify the release signature: you trust the script obtained
over HTTPS. Homebrew installations instead start with trust in Homebrew and the
tap. When using your own source build, you trust that build; by default syq
uploads the running executable as its remote helper. See [Install](install.md)
for the installation methods.

## HTTPS certificates

Release downloads and S3 connections trust the operating system's root
certificates; syq bundles no root list and does not check certificate
revocation online. Keep the system trust store up to date; minimal Linux
installations may need the `ca-certificates` package before HTTPS works.

For a private CA or a restricted trust store, set `SSL_CERT_FILE` to a PEM
bundle or `SSL_CERT_DIR` to a colon-separated list of directories containing
PEM certificates. A set `SSL_CERT_FILE` or a nonempty `SSL_CERT_DIR` replaces
the system roots, and missing files or empty bundles do not fall back to any
other list: even `SSL_CERT_FILE=""` loads no roots unless `SSL_CERT_DIR`
supplies them. Unset both variables to restore system trust, and restart a
running syq process to load changes. These settings do not change SSH host-key
checks or release signature checks.

## Copies between servers

Suppose your laptop can log into hostA and hostB, and you want hostA to send
files directly to hostB. Giving hostA a private key or unrestricted access to
your SSH agent would let a compromised hostA do more than the intended copy.
Syq's default direct-copy mode lets your laptop authorize the transfer while
limiting the access hostA receives.

### Destination permissions

The protection has several parts:

1. **Set up a restricted entry point on hostB.** The first copy uses your
   normal SSH login to install a receiver and add one `authorized_keys` line.
   That line's entry key permits only the receiver command, with SSH
   forwarding disabled. The receiver refuses to run as root.
2. **Give hostA only the entry key.** HostA receives the entry key with each
   copy you authorize and uses it to reach the receiver, checking hostB's host
   key as described [below](#how-hosta-checks-hostbs-key). The entry key
   authorizes nothing by itself: anyone holding it, including a server that
   ran an earlier copy, still needs a copy you newly signed to copy files.
   Such a server can, however, keep the receiver's connections busy, so that
   new copies fail and running ones cannot add connections, until you revoke
   the enrollment and enroll again, which replaces the entry key. Your login
   key and SSH agent stay on your laptop; no agent is forwarded. The entry key
   is stored unencrypted on your laptop. Keep it dedicated to the receiver:
   authorizing it elsewhere would give hostA that access too.
3. **Sign the particular copy with your login key.** Your laptop signs the
   copy's command, as you ran it, with its expiry, using the key you log in
   to hostB with. HostB's receiver checks the signature against that key,
   including a FIDO key's touch and PIN and a certificate's expiry, works out
   the permitted destination paths, write and deletion permissions, and
   limits from the command itself, and enforces them throughout the transfer.
   HostA cannot change the command or use it again for a later copy. The
   signature is made for syq copies alone and cannot pass as a login.
4. **Check the outcome with hostB.** The receiver reports each change it
   makes, protected by a key hostB created during setup. HostA passes the
   reports to your laptop, which checks that they are hostB's and that hostA
   left none out, added none, and did not cut them short.

An enrollment covers the whole account. Each copy's command names its
destination, which can be anywhere the account can write except the
receiver's protected paths: the account's SSH configuration, syq's stored
programs, enrollment state, and receiving state (see
[Enrollment](remote-reference.md#enrollment) for the list). A file written
elsewhere in the account, such as a shell startup file, can run code as the
account, so a signed copy is as strong as a login. That is acceptable because
only your login key can sign one, and you choose each destination.

The receiver refuses a destination inside a protected path, whatever names
lead to it, and does not follow symlinks beneath the destination. A protected
path that does not exist yet is known only by its name, so a copy that reaches
it under another name, such as through a bind mount or in another letter case
on a filesystem that ignores case, can create it. Renaming or replacing a
directory on the way to the destination during the copy does not redirect the
copy. With `--follow-dst`, the receiver follows a symlink at the destination
only to a directory inside the one the destination is in and outside the
protected paths.

An enrollment outlives removing or revoking your login key on hostB: end it
with `syq receiver revoke`. See
[Changing keys](remote-reference.md#changing-keys-and-updating-syq) for what
does and does not stop a signed copy.

File data travels directly from hostA to hostB, over encrypted TCP or SSH.
Your laptop provides authorization and verifies the result without carrying
the file data. See [Copy between servers](remote-to-remote.md) for setup and
revoking access.

Alternative authentication modes grant more authority. `--peer-auth broker`
limits authentication to the chosen host and user but allows that account's
full authority. `--peer-auth full-agent` exposes your SSH agent as `ssh -A`
would. See [Other authentication modes](remote-reference.md#other-authentication-modes).

### How hostA checks hostB's key

HostA connects to hostB with its own SSH configuration, which checks hostB's
host key as its own `ssh` would, with its known_hosts files, host certificate
authorities, and `StrictHostKeyChecking`. Syq allows this connection nothing
else: it logs in only with the entry key, with no agent, forwarding, proxy,
tunnel, remote command, or terminal, and it never prompts.

HostA also accepts the keys and host certificate authorities that your
laptop's known_hosts lists for hostB, and refuses the keys your laptop marks
revoked. A key that matches an entry on either machine is accepted, so a key
your laptop knows works even where hostA has an old one; a key that matches
nothing while either machine lists a plain key of the same type for hostB is
refused, as `ssh` refuses it. A listed host certificate authority does not
refuse a key presented without a certificate: hostA treats that key as it
would a host it has not seen. Where hostA's OpenSSH is older than 8.5 or its
configuration sets its own `KnownHostsCommand`, hostA can use your laptop's
entries only if its `GlobalKnownHostsFile` names a single file; otherwise the
copy says it checked without them.

When neither machine knows hostB, hostA follows its own
`StrictHostKeyChecking` setting, except that nobody can answer the question
`ask`, the default, would ask. So `ask` works like `accept-new`: hostA accepts
the key it is shown the first time, records it in its own known_hosts, and
checks later connections against it. Your laptop's own login to hostB, which
sets up restricted copying, does the same with your laptop's SSH
configuration, but asks you when it runs in a terminal.

Accepting a new key means that someone who can intercept that first
connection could present their own key. They could not use the entry key or
the signed copy against the real hostB, because an SSH key login cannot be
relayed to another connection, but they would receive the copy's data and
could report that it completed. For a copy started on your laptop, your
laptop checks hostB's reports (step 4) and would detect that.

To refuse a host neither machine has seen, set `StrictHostKeyChecking yes`
on hostA for the name hostA connects with, and trust hostB's key there or
on your laptop. For a copy a server started, that is the name in the
server's command. For a copy started on your laptop, it is the address your
laptop's SSH configuration gives hostB, not the name you typed: a `Host`
block on hostA for that name does not apply.

### A compromised source server

Suppose the signed copy permits hostA to copy into hostB's `/archive`. A
compromised hostA can misuse the access that copy requires, but cannot give
itself more:

HostA can:

- Supply false contents, names, sizes, or timestamps.
- Set any metadata the copy preserves, such as permissions, ACLs, or extended
  attributes, and with hard links give files in the scope new names.
- Overwrite files where the signed copy permits overwriting.
- Omit a source file and, if pruning is authorized, cause its destination copy
  to be deleted.
- Inspect destination entries for copy planning and consume the allowed space.
- Stop the transfer or withhold hostB's reports, which fails the copy.

HostA cannot:

- Change the signed destination scope to write into `/etc` or an SSH
  configuration directory.
- Overwrite existing files, change their permissions, owner or other
  metadata, or give them new names with hard links, when the signed copy
  permits only creating new ones, or delete files without permission.
- Exceed the signed byte, entry, or deletion limits.
- Reuse the signed copy for another copy, use the entry key it keeps to
  start a later copy without one you newly signed, or use that key to run a
  shell.
- Forge, alter, or cut short hostB's reports of its changes.

Some filesystems narrow the promise about existing files. A signed copy that
permits only creating new files refuses hard links on filesystems whose link
counts syq does not trust, such as SMB and SSHFS. On filesystems without an
atomic no-replace rename, such as NFS, hostB places a new file without a final
check at a name it found free while planning, so a file another program
creates there later in the copy can be replaced; hostA decides when the copy
looks names up and when it writes them. On FAT and exFAT on macOS and on
rclone mounts, hostB still refuses files that already exist, but one created
in the instant between its check and its rename can be replaced.

The filesystem limitations above still apply. HostB's account and receiver
remain trusted to enforce the signed copy and report accurately. HostB's reports
describe their work; they cannot prove that hostA supplied the right files. For
example, they can accurately report that hostB wrote false contents provided by
hostA.

<a id="file-contents"></a>
<a id="expected-contents-and-corruption-checks"></a>
<a id="consistency-and-durability"></a>

For checking contents against a trusted hash, see
[Expected hashes](integrity-checking.md#expected-hashes). General corruption,
consistency, and durability considerations are covered in
[Integrity checking](integrity-checking.md).

## Persistent connections

A persistent SSH login lets processes running as your local user access the
server without another key touch or agent approval, even with receiving turned
off. Separate SSH data connections authenticate on their own, so your agent may
ask for confirmation for each one. `syq persist off` closes the default
domain's persistent connections, including receiving; add `--pscope PATH` to
close an explicit domain instead.

Domains separate syq's connections, saved authorization choices, receiving
profiles, and remembered account permissions. They share your OS account's SSH
configuration, keys, agents, and receiver identity, and are not a security
boundary between processes running as that account.

## Receivers

With receiving enabled, servers you have persistent connections to can request
copies to or commands on your machine, SSH account access on another server,
or authorization for copies to or from another server or object storage.
Receiving is enabled by default in the default domain and disabled in a fresh
explicit domain. `syq persist receive off` disables these requests in the
selected domain while keeping SSH reuse.

Requests from a server are subject to local approval:

| Request | Approval on your machine |
|---|---|
| Send files to your machine | Required by default; `--auto-approve-root` permits unattended downloads confined to that directory |
| Authorize one copy to or from another server | Always required |
| Run a command on your machine | Always required |
| Authorize an SSH login to another server account | Required unless this source and destination account pair has a session or remembered permission |
| Use your storage credentials for a transfer | Always required |

The prompt shows the server account and the requested command. For copies and
authorizations, that is the syq command the server ran, including options from
its environment variables; your laptop derives what it enforces from that
command and rejects a request that does not match. It cannot prove who typed
the command. Approving a copy does not approve a later command. By default,
every connected server in a domain can use that domain's enabled profiles. A
profile's optional `--connection` list limits which locally selected SSH
connections may use it. Within each allowed server account, all processes
share this authority; choosing a different profile name does not isolate them.

<a id="named-receiving-destinations"></a>

### Receiving files on your laptop

Copy approval permits the destination, overwrite policy, and limits of the
shown command; syq enforces them on every filesystem operation. The server
supplies the command's ignore rules and mapping file contents, which your
laptop does not check; they can only narrow the copy. The server can supply false contents, inspect destination
entries during planning, and use disk space within those limits. The default
starting directory is your home, without containment;
`syq persist receive on --root DIRECTORY` confines copies to that directory.
See [Use your laptop from a server](receive.md) for setup and approval
controls. Automatic approval trusts those accounts to overwrite files inside
its root; some options still ask. Choose an inbox whose downloaded contents
are not automatically executed or loaded as trusted configuration.

A receiving name is tied to a public key, and reconnecting requires proof of
the matching private key. This prevents another client from claiming your
name, but the server account can replace its stored name assignments. The
receiver's private key stays on your machine and grants no SSH login access.

<a id="authorizing-copies-to-another-server"></a>

### Copying between servers

A connected server can ask your laptop to authorize a copy to another server.
Your laptop shows the command, sets up or updates the destination account's
enrollment when needed, signs the approved copy with your login key, and gives
the server the entry key and what your laptop's known_hosts lists for the
destination. The protection then works as in
[Copies between servers](#copies-between-servers), with the server that asked
in hostA's place, and the destination's receiver also enforces your laptop's
own limits. Two things differ. Your laptop does not check what the destination
reports it changed (step 4); the server reports the outcome itself, as for any
copy it runs. And the copy continues if your laptop disconnects or stops
receiving, until it finishes, someone interrupts it on the server, or you
revoke the enrollment. The server chooses the contents written within the
approval and keeps the entry key afterwards. Your laptop's credentials and
signing agent remain on the laptop.

A server can also request source-read approval to download files from another
server. The source helper confines reads to the approved files and directory
trees, applies the selected symlink behavior, accepts no writes or removals,
and limits returned file data, entries, and connections. Hashing approved
files for comparison and verification is permitted separately; the data limit
is not a limit on information that can be inferred from those hashes. File
data uses authenticated encrypted TCP directly between the servers, and the
copy fails if that is unavailable. Closing the approval connection stops
further reads.

<a id="approved-commands-on-receiving-machines"></a>

### Running commands on your laptop

With [`syq exec`](receive.md#run-commands-on-your-laptop), a connected server can request a command on your
laptop. An approved command runs with your local user's full permissions;
it is not sandboxed or confined to a copy destination directory.

### Storage authorization

[Storage authorization](object-storage.md#authorize-from-your-laptop) gives the
server signed URLs for approved paths and operations. The secret access key
stays on your laptop. Approval trusts the server to choose uploaded contents
and object settings, such as tags or Object Lock retention, within the
authorizing credentials' permissions: some services accept request headers that
a signature does not cover.
Anyone with the URLs can reuse them until expiry; stopping receiving does not
revoke them. Filesystem receiver roots, aggregate limits, and single-use
signed copies do not apply.

Upload approval is not a write-only grant. It includes reading object
contents and metadata within the approved destination paths, for comparisons
with existing files. When updates are allowed, it also permits reading
destination tags, updating tags on the current destination object, and
copying an object onto itself to update metadata. It does not authorize tag
changes on historical versions or copying a different destination object as
the source; bucket-to-bucket copies require a separate approved source scope.

## SSH account access

Selecting `--auth-from @laptop` for an SSH command or an ordinary remote file
operation requests access to the destination account. Approval grants that
account's authority, including arbitrary commands and access to its files.
The displayed command is context supplied by the requester, not an enforced
restriction, and copy paths, download roots, and byte limits do not constrain
account permission. Restricted copies you sign keep their own scope.

**Allow** approves the source-account/destination-account pair for the current
receiving connection from the laptop to the source. **Remember** permits
future authentications through the same profile in the same authorizing
domain while the laptop is available. The permission is bound to the selected
account and route and to the trusted host name and plain SSH host keys your
laptop knows for them; a changed identity requires fresh approval. The prompt
identifies hosts as your laptop knows them and shows the connection address
the requester supplied separately. Account authorization needs a trusted host
identity for the source server.

Commands and copies reuse the approved SSH connection. Any process running as
the requesting account can use its owner-only control socket, so trust extends
to that account's processes, not just the shell asking for permission. The
laptop signs authentication only for the approved destination host keys and
login account. Its agent is not forwarded, and this permission cannot
authenticate to a different destination account or sign arbitrary messages.

The requesting machine chooses the account and route through its SSH
configuration, but cannot make the laptop trust a host key by including it in
a request: the laptop checks its own trusted host information. `ProxyJump`
requires permission for each jump account as well as the final account.
Custom proxy commands use local authentication and do not receive the
laptop's agent socket.

A laptop agent key constrained with `ssh-add -h hostB` can authorize this
login, because the agent sees a direct login to hostB. Syq approves the
requesting source account itself; that approval does not imply an agent
constraint describing a forwarded hop from the source to hostB.

Stopping receiving ends further authorization through that connection, and
removing a remembered permission requires new approval for future
authentications. Already authenticated sessions may continue, including
additional commands within them. These actions cannot undo remote changes,
stop detached processes, or revoke independent access already created with the
approved account. See [account permission controls](persistence-reference.md#account-permissions).

### Ordinary SSH authorization providers

`--auth-from [USER@]HOST[:PORT]` opens a native SSH login to the provider account.
That account's local receiving service holds the agent environment and asks for
access to each destination account. It does not learn or verify which source
machine initiated the login, so the prompt identifies access through the
provider account rather than a source server. **Allow** lasts for the current
provider connection; **Remember** covers later logins to that provider account
through the same profile and authorizing domain.

The provider login has full account access. A caller with that access can run
programs there and use its credentials outside syq. Syq's prompts are useful
controls for its own operations, not an enforcement boundary against someone
who controls the provider account. Use a receiving connection from a laptop when
the requesting server must not have a full SSH login to the credential holder.
Stopping receiving prevents further syq authorizations but does not revoke the
caller's independent SSH access to the provider.
