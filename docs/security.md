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
directories open and accesses their entries through those open handles.
Renaming an opened directory does not change which directory the handle refers
to, and replacing its old name with a symlink does not redirect subsequent
operations through that handle. These checks assume the attacker can change
directory entries but does not control the account running syq.

The same principle applies to names supplied by a remote machine and to
removal:

- **A remote source tries to escape the destination.** If you are copying into
  `backup`, a peer cannot make an entry named `../private/key` or `/private/key`
  write outside it. Syq rejects those names.
- **A directory becomes a symlink during copying.** If `backup/photos` is
  replaced with a link to another directory, syq either continues through a
  handle it already opened or refuses to traverse the link. It does not start
  writing into the link's target.
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

**Hard links and `--inplace`.** Suppose `backup/report` and a file outside
`backup` are hard links to the same file. Copying over `backup/report` with
`--inplace` changes the contents visible through both names. Avoid `--inplace`
when you cannot trust the destination's existing files. Metadata changes,
such as permissions or timestamps, also affect every hard link to that file,
even without `--inplace`.

**Permissions supplied by the source.** Path protection does not decide
whether copied permissions are appropriate. For example,
`--copy-metadata=permissions` can make a copied file writable by everyone or
preserve its set-user-ID bit; `--copy-metadata=ownership` can give it to the account
identified by the source's user ID. When running as root, those choices can
grant other users access or privileges. Enable these options only when you
trust the source's ownership and permission settings.

**Files left by an interrupted copy.** Someone could plant a symlink or hard
link where an old partial file should be, hoping that resuming will overwrite
another file. Syq creates its own partial for the new copy. It only reuses
bytes from old partials that are regular files owned by its user with no extra
hard links, checks those bytes against the source, and leaves the old files
unchanged. It does not resume by writing through the planted link.

**Concurrent replacement of directory entries.** Checking an entry and
removing it are separate operations. Someone able to rename files in that
directory can replace the entry in between, causing syq to remove the new
entry instead. Similarly, publishing a copied file can replace another
writer's new file. These races do not cause syq to follow a replacement
symlink, but they can lose a concurrent writer's changes. Use a destination
other processes cannot modify if those changes must be protected.

**Named pipes.** If someone replaces an input file with a named pipe
just before syq opens it, the open can briefly wake the pipe's writer before
syq detects the change and fails. That writer may send data that is then
discarded. On macOS, rapidly replacing one pipe with another can also escape
syq's identity check if the filesystem reuses the same inode number. These limitations matter
when another process can replace the pipe or change a file's type during the
copy. Keep pipes used by sensitive producers in directories untrusted users
cannot modify.

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

Storage upload approvals include reading object contents and metadata within
the approved destination paths, for comparisons with existing files. When
updates are allowed, they also permit reading destination tags, updating tags on
the current destination object, and copying an object onto itself to update
metadata. They do not authorize tag changes on historical versions or copying a
different destination object as the source; bucket-to-bucket copies require a
separate approved source scope. Upload approval is not a write-only grant.

## Downloaded executables

Official releases provide executables for each supported operating system and
CPU architecture. They are published as GitHub release assets and served
through `dl.syq.christmas`. An installed syq downloads them for explicit
self-updates, explicit `--use-version` selections, and, when needed, to install
a matching helper on an SSH server.
Remote helpers use the same release as the client, even when the server needs
a different platform's executable.

A signed release manifest identifies the release and lists the size and
SHA-256 hash of each archive and executable. The installed client carries the
release public key. It verifies the manifest's Ed25519 signature with that key,
then checks downloaded files against the signed sizes and hashes before using
them. The verification key comes from the installed executable, not from the
server supplying the download. Source builds also carry the official public
key for explicit `--use-version` selections.

This also applies when the SSH server downloads its own helper: your client
verifies the manifest and checks the reported archive hash before authorizing
installation. If that download cannot be verified, syq discards it and uploads
a locally verified helper over SSH instead. A download host cannot substitute
arbitrary executable code without a valid release signature. This relies on
the release signing key, your installed client, and the SSH account remaining
trusted.

The first installation establishes that trust. The standalone installer checks
the archive against a size and SHA-256 hash embedded in the script, but it does
not independently verify the release signature. You trust the script obtained
over HTTPS. Homebrew installations instead start with trust in Homebrew and the
tap. When using your own source build, you trust that build; by default syq
uploads the running executable as its remote helper. See [Install](install.md)
for the installation methods.

## Copies between servers

Suppose your laptop can log into hostA and hostB, and you want hostA to send
files directly to hostB. Giving hostA a private key or unrestricted access to
your SSH agent would let a compromised hostA do more than the intended copy.
Syq's default direct-copy mode lets your laptop authorize the transfer while
limiting the access hostA receives.

### Destination permissions

The protection has several parts:

1. **Set up a restricted entry point on hostB.** Your laptop uses its normal
   SSH access to install a receiver and a dedicated public key. That key's
   `authorized_keys` entry permits only the receiver command, with SSH
   forwarding disabled. The key stays on your laptop or hardware token,
   matching the setup login's protection. Later copies reuse this setup. The
   receiver refuses to run as root.
2. **Authenticate hostA's connection without handing it the key.** A small
   signing service on your laptop answers hostA's SSH authentication requests.
   Before signing, it checks OpenSSH's cryptographic proof of which server
   the connection reaches, along with the requested login account. HostA
   cannot use it to authenticate
   to a different host or account, sign arbitrary messages, or access your
   other agent keys.
3. **Authorize the particular copy separately.** Your laptop signs a grant
   stating the permitted destination paths, write and deletion permissions,
   limits, and expiry. HostB's receiver verifies the signature, records that
   the grant has been used, and enforces it throughout the transfer. HostA
   cannot broaden the grant or redeem it again for a later copy.
4. **Check the outcome with hostB.** The receiver signs a receipt of its
   changes. Your laptop verifies it using hostB's receipt key, saved during
   setup. HostA can relay the receipt, but cannot forge it.

File data travels directly from hostA to hostB, over encrypted TCP or SSH.
Your laptop provides authorization and verifies the result without carrying
the file data. See [Copy between servers](remote-to-remote.md) for setup and
revoking access.

For passphrase-protected software logins, syq encrypts the receiver key on disk
and uses the original key's agent to unlock it locally. Anyone able to request
unrestricted signatures from that agent and read the encrypted file can also
unlock it. Syq's constrained signing service does not expose that operation.
The decrypted software key exists in local memory during a copy; a FIDO
receiver key continues to require its hardware device. See
[key matching and supported logins](remote-reference.md#enrollment).

Alternative authentication modes grant more authority. `--peer-auth broker`
limits authentication to the chosen host and user but allows that account's
full authority. `--peer-auth full-agent` exposes your SSH agent as `ssh -A`
would. See [Other authentication modes](remote-reference.md#other-authentication-modes).

### A compromised source server

Suppose the grant permits hostA to copy into hostB's `/archive`. A compromised
hostA can misuse the access that copy requires, but cannot grant itself more:

HostA can:

- Supply false contents, names, sizes, or timestamps.
- Set any metadata the copy preserves, such as permissions, ACLs, or extended
  attributes, and with hard links give files in the scope new names.
- Overwrite files where the grant permits overwriting.
- Omit a source file and, if pruning is authorized, cause its destination copy
  to be deleted.
- Inspect destination entries for copy planning and consume the allowed space.
- Stop the transfer or withhold its receipt.

HostA cannot:

- Change the signed destination scope to write into `/etc` or an SSH
  configuration directory.
- Overwrite existing files, or change their permissions, owner or other
  metadata, when the grant permits only creating new ones, or delete files
  without permission. Hard links can then give an existing file new names in
  the scope, but nothing more.
- Change in place a file that also has names outside the scope.
- Exceed the signed byte, entry, or deletion limits.
- Reuse the grant for another copy or use the restricted key to run a shell.
- Forge hostB's receipt.

The filesystem limitations above still apply to names inside the scope: a
change in place reaches every name a file has there. HostB's account and
receiver remain trusted to enforce the grant and report accurately. A verified receipt describes their
work; it cannot prove that hostA supplied the right files. For example, a
successful receipt can accurately report that hostB wrote false contents
provided by hostA.

<a id="file-contents"></a>
<a id="expected-contents-and-corruption-checks"></a>
<a id="consistency-and-durability"></a>

For checking contents against a trusted hash, see
[Expected hashes](integrity-checking.md#expected-hashes). General corruption,
consistency, and durability considerations are covered in
[Integrity checking](integrity-checking.md).

## Persistent connections

A persistent SSH login lets processes running as your local user access the
server without another key touch or agent approval. Independent SSH data
connections authenticate separately, even when syq account permission already
covers them; your agent may require confirmation for each one. This access remains
available even with receiving turned off. `syq persist off` closes the default
domain's persistent connections, including receiving; add `--pscope PATH` to
close an explicit domain instead.

Domains separate syq's connections, saved authorization choices, receiving
profiles, and remembered account permissions. They share your OS account's SSH
configuration, keys, agents, and receiver identity. They are not a security
boundary between processes running as that account. Closing an explicit domain
also removes its saved policy; closing the default domain preserves its policy.

## Receivers

With receiving enabled, servers you have persistent connections to can request
copies to or commands on your machine, SSH account access on another server,
or authorization for copies to or from another server or object storage.
Receiving is configured separately. It defaults to enabled in the default
domain and disabled in a fresh explicit domain. `syq persist receive off`
disables these requests in the selected domain while keeping SSH reuse.

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
the command. Approving a copy does not approve a later
command. By default, every connected server in a domain can use that domain's
enabled profiles.
A profile's optional `--connection` list limits which locally selected SSH
connections may use it. Within each allowed server account, all processes
share this authority; choosing a different profile name does not isolate them.

<a id="named-receiving-destinations"></a>

### Receiving files on your laptop

Copy approval permits the destination, overwrite policy, and limits of the
shown command; syq enforces them on every filesystem operation. The server
supplies the command's ignore rules and mapping file contents, which your
laptop does not check; they can only narrow the copy. The server can supply false
contents, inspect destination entries during planning, and use disk space
within those limits. The default starting directory is your home, without
containment; `syq persist receive on --root DIRECTORY` confines copies to that
directory. See [Use your laptop from a server](receive.md) for setup and
approval controls. Automatic approval trusts those accounts to overwrite files
inside its root; copies of ACLs, extended attributes, or hard links still ask.
Choose an inbox whose downloaded contents are not automatically executed or
loaded as trusted configuration.

A receiving name is tied to a public key; reconnecting requires proof of the
matching private key. This prevents another client from claiming your name,
but the server account can replace its stored name assignments. The receiver's
private key stays on your machine and grants no SSH login access.

<a id="authorizing-copies-to-another-server"></a>

### Copying between servers

A connected server can ask your laptop to authorize a copy to another server.
The copy uses your laptop's SSH access and the restricted receiver protections
described in [Copies between servers](#copies-between-servers). File data goes
directly between the servers over encrypted TCP or SSH. When SSH data is needed,
syq gives the source a temporary key whose destination authorization forces it
into this copy's live worker connection, with terminal access, forwarding and
`~/.ssh/rc` disabled (the account's shell may still read its startup files). The destination still enforces the approved
copy scope. Closing the copy invalidates its worker connections and removes
the key entry; an entry left by an interrupted cleanup cannot join another
copy. Your laptop's credentials and signing agent remain on the laptop.

A server can also request source-read approval to download files from another
server. The source helper confines reads to the approved files and directory
trees, checks the selected symlink behavior, and limits returned file data,
entries, and connections. Hashing approved files for comparison and verification
is permitted separately; the data limit is not a limit on information that can
be inferred from those hashes. It accepts no writes or removal operations.
File data uses authenticated encrypted TCP directly between the servers;
metadata and control use the laptop connection. If direct TCP is unavailable,
the copy fails. Closing the approval connection stops further reads.

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
revoke them. Filesystem receiver roots, aggregate limits, one-use grants, and
signed receipts do not apply.

## SSH account access

Selecting `--auth-from @laptop` for an SSH command or an ordinary remote file
operation requests access to the destination account. Approval grants that
account's authority, including arbitrary commands and access to its files.
The displayed command is requester-supplied context; it is not an enforced
command restriction. Copy paths, download roots, and byte limits do not constrain
account permission. Explicit restricted-copy grants retain their own scope.

**Allow** approves the source-account/destination-account pair for the current
laptop-to-source receiving connection. **Remember** permits future authentications
through the same profile in the same authorizing domain while the laptop is
available. The permission binds
the selected account and connection route to the provider's trusted host name and
plain SSH host keys; changed identities require fresh approval. The approval
identifies the host using the provider's trust lookup and shows the
requester-supplied connection address separately. The source connection is pinned to
that identity when it starts. Unsupported source identity lookup does not affect
ordinary receiving, but account authorization requires a supported trusted identity.

Commands and copies reuse the approved SSH connection. Any process running as
the requesting account can use its owner-only control socket. Trust therefore
extends to that account's processes, not just the shell asking for permission.
The laptop restricts authentication signatures to the approved destination host
keys and login account. Its ordinary agent is not forwarded, and this permission
cannot authenticate to a different destination account or sign arbitrary messages.

The requesting machine chooses the account and route through its SSH
configuration. It cannot make the provider trust a host key merely by including
that key in a request: the provider checks its own trusted host information.
`ProxyJump` requires permission for each jump account as well as the final
account. Custom proxy commands use local authentication and do not receive
the provider's agent socket.

A laptop agent key constrained with `ssh-add -h hostB` can authorize this login:
the agent sees the real direct binding to hostB. Syq separately approves the
requesting source account; an agent constraint describing a forwarded A-to-B
hop is not implied by that approval.

Stopping receiving ends further authorization through that connection. Removing
a remembered permission requires new approval for future authentications. Syq
cleans up its owned connections, but already authenticated sessions may continue,
including additional commands within them. These actions cannot undo remote
changes, stop detached processes, or revoke independent access already created
with the approved account. See [account permission controls](persistence-reference.md#account-permissions).

### Ordinary SSH authorization providers

`--auth-from [USER@]HOST[:PORT]` opens a native SSH login to the provider account.
That account's local receiving service holds the agent environment and asks for
access to each destination account. It does not learn or verify which source
machine initiated the login. The prompt therefore identifies access through the
provider account, rather than asserting a source-server identity. **Allow** lasts
for the current provider connection; **Remember** covers later logins to that
provider account through the same profile and authorizing domain.

The provider login has full account access. A caller with that access can run
programs there and use its credentials outside syq. Syq's prompts are useful
controls for its own operations, not an enforcement boundary against someone
who controls the provider account. Use a receiving connection from a laptop when
the requesting server must not have a full SSH login to the credential holder.
Stopping receiving prevents further syq authorizations but does not revoke the
caller's independent SSH access to the provider.
