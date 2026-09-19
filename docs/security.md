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
operations through that handle.

Syq also checks the names and operations within those directories:

- Names received from a peer must stay within the selected tree; absolute
  paths and escaping `..` components are rejected.
- Native syq follows symlinks only when you explicitly ask it to. Copying a
  symlink as a link does not grant access to its target.
- Deletion does not follow a replacement symlink or descend into an unexpected
  directory. If an entry changes just before removal, a single replacement
  entry can still be removed.

These protections assume the attacker controls files or directory entries,
not the account running syq. They do not stop someone with write access from
changing the contents of the selected tree.

### Relationship to rsync 3.5.0

Syq uses the same basic approach as
[rsync 3.5.0's security design](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md#symlink-race-safe-path-resolution):
keep directories open and resolve later operations relative to them. One
policy differs: whether to follow symlinks in paths you supply on the command
line.

| | Follow a symlink in a supplied path? |
|---|---|
| Rsync 3.5.0 | Yes if the link belongs to root or the process's effective user |
| Native syq | Only with an explicit follow option |

Rsync's [ownership policy](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md#symlink-defense-for-operator-supplied-paths)
allows familiar symlinked directory setups. Syq requires an explicit choice
because ownership does not always establish where a link came from. Someone
with permission to rename entries in the parent directories may move a link
they do not own. A relative link can then point somewhere different while
keeping its original owner. The [rename rules](https://man7.org/linux/man-pages/man2/rename.2.html)
include restrictions such as the sticky bit.

This is a stricter default for that case, not a claim of greater security
overall. `syq rsync` keeps rsync's ownership policy for compatibility. Its
local-only `--insecure-links` option also allows foreign-owned symlinks in
supplied local paths; it does not enable symlink traversal inside an opened
source tree.

<a id="limits-to-keep-in-mind"></a>
<a id="privileged-copies-and-hard-links"></a>

### Limits of path protection

A hard link is another name for the same file. If a destination file also has
a hard link outside the destination directory, changing its contents in place
or changing its metadata affects both names. Directory handles and symlink
checks cannot prevent this.

Do not copy as root into a directory writable by untrusted users. Leave
`--preserve=ownership` and `--preserve=permissions` off when copying from an
untrusted source. These options let source metadata determine who owns copied
files and who may access or execute them.

Temporary files need protection too. Syq writes private partial files. It
reuses data only from regular partial files owned by its effective user,
checks the reused bytes against source hashes, and leaves the old partial
unchanged. Those checks do not make a shared writable directory trusted.

On macOS, a named pipe (FIFO) has an additional limitation. Syq checks its
identity without opening a reader, but deleting and recreating it with the
same inode number can make the replacement indistinguishable. Replacing a
regular file with a FIFO just before it is opened can also briefly connect
a waiting producer before syq detects and rejects the change.

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

These protections limit what hostA can do to hostB. They do not make hostA's
files or claims trustworthy. It can omit files, supply invented contents or
metadata, or stop the copy. Policies such as `--skip-newer` depend on the
source's reported timestamps. The destination machine, receiver, and account
remain trusted to enforce the grant and report their work accurately.

A verified receipt tells you what the receiver did; it does not prove that the
source supplied every file you intended or the right contents.

<a id="file-contents"></a>
<a id="expected-contents-and-corruption-checks"></a>
<a id="consistency-and-durability"></a>

For checking contents against a trusted hash, see
[Expected digests](integrity-checking.md#expected-digests). General corruption,
consistency, and durability considerations are covered in
[Integrity checking](integrity-checking.md).

## Persistent connections

A persistent SSH login stays available to processes running as your local user
without another key touch or agent approval. `syq persist off` closes that
access. Persistence also enables requests from connected servers to your
machine; those requests have the separate protections below.

### Named receiving destinations

A compromised connected server can request copies to your machine. By default,
each request needs local approval for its destination, overwrite policy, and
limits. Syq then enforces those restrictions on every filesystem operation.
Approval permits that copy; it does not establish who typed the command on the
server or whether its files are trustworthy. Within the approved scope, the
server can inspect destination entries during planning and consume disk space.

The default receiving directory is your home, but it is not a containment
boundary. Use `syq persist receive on --root DIRECTORY` to contain copies.
`--approve always` removes the per-copy decision and trusts connected server
accounts for repeated copies. `syq persist receive off` disables receiving
while leaving SSH reuse available. See [Send files home from a server](receive.md)
for setup and approval controls.

A receiving name is tied to a public key, and reconnecting requires proof of
the matching private key. Another client cannot claim the name just by knowing
it. The server account controls the stored name assignments, however, so this
does not protect against that account replacing them. The receiver's private
key stays on the receiving machine and grants no SSH login access.

### Authorizing copies to another server

A server can also ask your receiving machine to authorize a copy to another
SSH destination. That always requires a local decision, even with automatic
copy approval enabled. Refusal ends the attempt.

Approval uses the receiving machine's SSH configuration and host trust to
connect and install a matching helper. The source gets access only to the
approved copy, enforced by the destination helper. It receives no private key,
SSH agent, or command-running interface. As with a direct copy authorized from
your laptop, you still trust the destination account and cannot trust a
compromised source's contents.

### Approved commands on receiving machines

A compromised server can request commands through [`syq exec`](exec.md), but
every command needs separate local approval, even when copies are approved
automatically. The prompt shows the requesting server account, arguments, and
working directory. It cannot prove that a particular person requested them.

Approval lets the program run with your local user's full authority, including
access to that user's credentials. Copy roots and transfer limits do not
constrain it. In particular, approving a build or script also trusts the code
it will run.

Disconnecting cancels the foreground process group, but cannot undo completed
effects; programs that start separate process sessions can survive cancellation.
Commands are not replayed automatically. See [Execution details](commands/exec.md#execution-details).
