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

Rsync's [ownership policy](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md#symlink-defense-for-operator-supplied-paths)
trusts a root-owned link even if someone else moved it there. Where directory
permissions allow that move, a relative link can point somewhere new without
changing its owner. Rsync can therefore follow a trusted-owner link placed by
an untrusted user. This is why native syq requires an explicit follow option;
`syq rsync` retains rsync's policy for compatibility. See the
[rename rules](https://man7.org/linux/man-pages/man2/rename.2.html) for which moves
filesystem permissions permit.

<a id="limits-to-keep-in-mind"></a>
<a id="privileged-copies-and-hard-links"></a>

### Limits of path protection

These protections apply when running as root too. They prevent paths from
redirecting an operation; they do not make all changes within the selected
directory safe. The following risks require separate attention, especially
when syq has more permissions than the people who can modify that directory.

**Opt-in staging recycling.** `--recycle-staging=SIZE` permits syq to overwrite
retired destination inodes with data for other files. Anyone retaining an old
file handle may then observe the new data; changing permissions or moving the
inode into a private directory does not reliably revoke that access. Use this
option only with exclusive destination access and when these consequences
are acceptable. It is disabled by default and unavailable to command-restricted
receivers. See [staging storage](reference.md#reuse-staging-storage) for limits
and cleanup behavior.

**Hard links and `--inplace`.** Suppose `backup/report` and a file outside
`backup` are hard links to the same file. Copying over `backup/report` with
`--inplace` changes the contents visible through both names. Avoid `--inplace`
when you cannot trust the destination's existing files. Metadata changes,
such as permissions or timestamps, also affect every hard link to that file,
even without `--inplace`.

**Permissions supplied by the source.** Path protection does not decide
whether copied permissions are appropriate. For example,
`--preserve=permissions` can make a copied file writable by everyone or
preserve its set-user-ID bit; `--preserve=ownership` can give it to the account
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

`--tcp-plain` disables this protection for TCP: someone on the network can
read or alter the traffic, including its authentication token. Use it only
on a network you trust.

## Downloaded executables

Official releases provide executables for each supported operating system and
CPU architecture. They are published as GitHub release assets and served
through `dl.syq.christmas`. An installed syq downloads them for explicit
self-updates and, when needed, to install a matching helper on an SSH server.
Remote helpers use the same release as the client, even when the server needs
a different platform's executable.

A signed release manifest identifies the release and lists the size and
SHA-256 hash of each archive and executable. The installed client carries the
release public key. It verifies the manifest's Ed25519 signature with that key,
then checks downloaded files against the signed sizes and hashes before using
them. The verification key comes from the installed executable, not from the
server supplying the download.

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
   forwarding disabled. The private key stays on your laptop. Later copies
   reuse this setup.
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

Alternative authentication modes grant more authority. `--peer-auth broker`
limits authentication to the chosen host and user but allows that account's
full authority. `--peer-auth full-agent` exposes your SSH agent as `ssh -A`
would. See [Other authentication modes](remote-reference.md#other-authentication-modes).

### A compromised source server

Suppose the grant permits hostA to copy into hostB's `/archive`. A compromised
hostA can misuse the access that copy requires, but cannot grant itself more:

HostA can:

- Supply false contents, names, sizes, or timestamps.
- Overwrite files where the grant permits overwriting.
- Omit a source file and, if pruning is authorized, cause its destination copy
  to be deleted.
- Inspect destination entries for copy planning and consume the allowed space.
- Stop the transfer or withhold its receipt.

HostA cannot:

- Change the signed destination scope to write into `/etc` or an SSH
  configuration directory.
- Overwrite existing files when the grant permits only creating new ones,
  or delete files without permission.
- Exceed the signed byte, entry, or deletion limits.
- Reuse the grant for another copy or use the restricted key to run a shell.
- Forge hostB's receipt.

The filesystem limitations above still apply, including effects through
hard links. HostB's account and receiver remain trusted to
enforce the grant and report accurately. A verified receipt describes their
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
server without another key touch or agent approval. This access remains
available even with receiving turned off. `syq persist off` closes the
persistent connections, including receiving.

## Receivers

With receiving enabled, servers you have persistent connections to can request
copies to or commands on your machine, or authorization for copies to another
server. Receiving is configured separately and defaults to enabled. `syq persist receive off`
disables these requests while keeping SSH reuse.

Requests from a server are subject to local approval:

| Request | Approval on your machine |
|---|---|
| Send files to your machine | Required by default; `--auto-approve-root` permits unattended downloads confined to that directory |
| Use your SSH access for a copy to another server | Always required |
| Run a command on your machine | Always required |

The prompt identifies the server account and requested operation. It cannot
prove who typed the command there. Approving a copy does not approve a later
command. By default, every connected server can use every enabled profile.
A profile's optional `--server` list limits which locally selected SSH
connections may use it. Within each allowed server account, all processes
share this authority; choosing a different profile name does not isolate them.

<a id="named-receiving-destinations"></a>

### Receiving files on your laptop

Copy approval permits the shown destination, overwrite policy, and limits;
syq enforces them on every filesystem operation. The server can supply false
contents, inspect destination entries during planning, and use disk space
within those limits. The default starting directory is your home, without
containment; `syq persist receive on --root DIRECTORY` confines copies to that
directory. See [Use your laptop from a server](receive.md) for setup and
approval controls. Automatic approval trusts those accounts to overwrite files
inside its root. Choose an inbox whose downloaded contents are not automatically
executed or loaded as trusted configuration.

A receiving name is tied to a public key; reconnecting requires proof of the
matching private key. This prevents another client from claiming your name,
but the server account can replace its stored name assignments. The receiver's
private key stays on your machine and grants no SSH login access.

<a id="authorizing-copies-to-another-server"></a>

### Copying between servers

A connected server can ask your laptop to authorize a copy to another server.
The copy uses your laptop's SSH access and the restricted receiver protections
described in [Copies between servers](#copies-between-servers).

<a id="approved-commands-on-receiving-machines"></a>

### Running commands on your laptop

With [`syq exec`](receive.md#run-commands-on-your-laptop), a connected server can request a command on your
laptop. An approved command runs with your local user's full permissions;
it is not sandboxed or confined to a copy destination directory.
