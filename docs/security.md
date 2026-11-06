# Security

Syq often acts with more authority than the files or machines involved in a
copy. A backup account may read another user's directory, or your laptop may
authorize a copy between two servers. The protections below limit how those
files and servers can use that authority:

- Someone who can change a directory you copy cannot use symlinks or renames
  to redirect syq to other files.
- A server you let copy to another server gets only that copy, unless you
  choose a mode that grants more.
- Servers connected to your laptop act there only as your approvals allow.
- Syq checks the release signature of every executable it downloads.

Report vulnerabilities through
[SECURITY.md](https://github.com/greaber/syq/blob/master/SECURITY.md).

## Filesystem safety

### Filesystem attacks

People who can change a directory that syq copies from or into, but who do
not control the account running syq, cannot redirect its reads, writes, or
deletions to other files, even by swapping names while the copy runs.
[Limits of path protection](#limits-of-path-protection) lists what this does
not cover.

For example, a user who can change an upload directory that a backup account
copies could swap a subdirectory for a symlink to private files, which a
naive copy program would then read with the backup account's permissions.
Syq keeps directories open and works on their entries through them, so a
renamed directory or a swapped-in symlink does not redirect later operations.
In particular:

- **A remote source tries to escape the destination.** A peer cannot make an
  entry named `../private/key` or `/private/key` write outside the
  destination; syq rejects such names.
- **A directory becomes a symlink during copying.** Syq either continues
  through the directory it already opened or refuses to traverse the link. It
  does not write into the link's target.
- **An entry changes during removal.** If a file selected for removal becomes
  a symlink, removing it leaves the link's target alone. If it becomes a
  directory, syq does not delete that directory's contents.

### Which symlinks are followed?

<a id="relationship-to-rsync-350"></a>

Syq's own commands follow a symlink only in a path you supply, and only when you
ask; links found inside a directory are never followed. (`syq rsync` instead
follows the rule from
[rsync 3.5.0's security design](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md#symlink-race-safe-path-resolution):
it follows a link in a supplied path that root or the running user owns, or any
link with `--insecure-links`, which applies to local paths only.)

| Where the symlink appears | Treatment |
|---|---|
| In a source path you supply | Followed only with `--follow-src`. Without it, a link in the path, even a system one such as macOS's `/tmp`, stops the copy. To copy a link you name rather than what it points to, select it with `--src-non-dir` |
| In a destination path you supply | Followed only with `--follow-dst`; without it, a link in the path stops the copy. `--as PATH` replaces a link at its final entry instead of following it |
| Inside a source directory being copied | Copied as a link; its target is not read |
| Inside a destination directory | Not followed. A copied file can replace the link, but a copied directory cannot use it as a directory |

`--follow` enables both. See [Symlinks](reference.md#symlinks) for examples.

<a id="limits-to-keep-in-mind"></a>
<a id="privileged-copies-and-hard-links"></a>

### Limits of path protection

Path protection stops names from redirecting an operation, also when syq runs
as root, but it does not make every change inside the selected directory
safe. Watch for these risks, especially when syq has more permissions than the
people who can change that directory.

**Existing files and their other names.** Syq replaces an existing file by
renaming a new one over its name, so another name for the old file, or anyone
who has it open, keeps the old contents. `--in-place=update`
(`syq rsync --inplace`) instead writes into the existing file, so anyone who
has it open sees the new contents; syq does that only when it gives no one
access the copy would not, and replaces the file otherwise (see
[In-place writes](reference.md#in-place-writes)).

Syq changes an existing file's metadata in place only when that cannot affect
another name or grant privileges, and otherwise replaces the file (see
[How syq changes existing files](reference.md#how-syq-changes-existing-files-and-directories)).
So a hard link planted in the destination never takes the copy's metadata, and
root never gives a file another user planted there another owner, group, or
privileges. The exception is access times copied with `--copy-metadata=atimes`,
which are set in place on all of a file's names. Narrowing permissions in place
does not cut off someone who already has the file or directory open.

An `--as-fd` output is written, and given any copied metadata, through
whatever file the descriptor refers to, without these checks.

**Permissions supplied by the source.** Copied permissions are only as
trustworthy as the source. `--copy-metadata=permissions` can make a file
writable by everyone or keep its set-user-ID bit, and
`--copy-metadata=ownership` gives it to whatever account the source's user ID
names. As root, that can grant other users access or privileges, so use these
options only when you trust the source's settings.

**Partial files.** Syq writes partial files, and the files `--in-place=new`
creates, only through files it created or opened itself. A symlink or hard
link planted at a partial file's name is never followed or written into; syq
replaces it with its own file. Syq resumes only from a partial file that is
owned by the account running syq and has no other names, and only reads it.
Once it has published the file, it removes such a partial file when no program
has it open for writing. A
file swapped in during the copy gets none of the copy's
data or metadata, and when syq detects the swap, it reports the file as failed
instead of publishing it.

**Concurrent replacement of directory entries.** Someone who can rename
entries in a directory can swap in a new entry between syq's check and its
removal, so syq removes the new entry instead, and publishing a copied file
can replace another writer's new file. Syq never follows a swapped-in symlink,
but a concurrent writer's changes can be lost. If they matter, copy into a
destination other processes cannot modify.

**Named pipes.** Swapping an input file for a named pipe just before syq opens
it can discard data the pipe's writer sends. Keep pipes used by sensitive
producers in directories untrusted users cannot modify.

<a id="code-and-transport-integrity"></a>
<a id="encryption-and-authentication"></a>
<a id="tcp-data-connections"></a>
<a id="malformed-or-stalled-peers"></a>

## Network security

Remote copies encrypt and authenticate file data, over SSH and over syq's
direct TCP connections. `--no-tcp-encryption` turns this off for TCP, so
anyone on the network can read or alter the traffic, including its
authentication token. Use it only on a network you trust.

## Downloaded executables

Syq uses a downloaded executable only if it matches a release manifest signed
with the release key built into your installed syq, so a download server
cannot substitute code. This relies on the release signing key, your installed
syq, and the SSH accounts involved staying trustworthy.

Syq downloads official executables, served through `dl.syq.christmas`, for
self-updates, `--use-version`, and helpers on SSH servers, and checks each
against the size and SHA-256 hash the signed manifest lists. Source builds also
carry the release key for `--use-version`. When an SSH server downloads its own
helper, your machine checks the manifest and the archive hash the server reports
before allowing installation, and uploads a verified helper over SSH instead if
the download cannot be verified.

A release you select with `--use-version` is verified once, when syq stores it
in `~/.local/lib/syq`. Later runs on your machine start it without hashing it
again, but refuse it if its files or directories there are not yours, or if
their permission bits or a macOS access control list let others change them.
Anyone who can write the directories above the store can replace it, just as
anyone who can write `~/.local/bin` can replace syq, so keep them writable only
by you. On SSH servers, syq starts the stored helper without these checks, so
keep `~/.local/lib/syq` there writable only by you too.

Your first installation establishes this trust. The standalone installer
checks the archive against a size and SHA-256 hash embedded in the script, but
not the release signature, so you trust the script you fetched over HTTPS.
Homebrew installations trust Homebrew and the tap. A source build is trusted
as built, and by default syq uploads that executable as its helper on
servers. See [Install](install.md) for the installation methods.

## HTTPS certificates

Release downloads and S3 connections trust your operating system's root
certificates; syq bundles none and does not check revocation online. Keep the
system trust store up to date; minimal Linux installations may need the
`ca-certificates` package before HTTPS works.

To use a private CA or a restricted trust store, set `SSL_CERT_FILE` to a PEM
bundle or `SSL_CERT_DIR` to a colon-separated list of directories of PEM
certificates. Setting `SSL_CERT_FILE`, even to an empty value, or a non-empty
`SSL_CERT_DIR` replaces the system roots, and syq loads both when both are set.
A missing or empty file or directory does not fall back to the system roots.
Unset both to restore system trust, and restart running syq processes to load
changes. These settings do not affect SSH host-key checks or release signature
checks.

## Copies between servers

When your laptop starts a copy from hostA to hostB, syq's default mode gives
hostA permission for that one copy and nothing more: no private key, no access
to your SSH agent, and no shell on hostB. A compromised hostA can still misuse
that copy; see [A compromised source server](#a-compromised-source-server).

### Destination permissions

The protection has four parts:

1. **A restricted entry point on hostB.** The first copy uses your normal SSH
   login to install syq's receiver and add one `authorized_keys` line, whose
   entry key can only start the receiver, with SSH forwarding disabled. The
   receiver refuses to run as root.
2. **Only the entry key for hostA.** With each copy, hostA receives the entry
   key and uses it to reach the receiver, checking hostB's host key as described
   [below](#how-hosta-checks-hostbs-key). The entry key authorizes nothing by
   itself: anyone who holds it, including a server that ran an earlier copy,
   still needs a copy you newly signed. Such a server can, however, keep the
   receiver's connections busy so that new copies fail, until you revoke the
   enrollment and enroll again. Don't add the entry key to any other
   `authorized_keys` file: hostA holds it, so it would gain that access too.
   Your laptop stores it unencrypted.
3. **A signature on each copy.** Your laptop signs the copy's command, exactly
   as you ran it, with an expiry time, using the key you log in to hostB with.
   The receiver checks the signature, requiring the touch and PIN your login
   needs and, for a certificate, that it has not expired. From the command, it
   works out where the copy may write, whether it may overwrite or delete, and
   its limits, and it enforces them throughout. HostA cannot change the command
   or use it twice, and the signature cannot be used to log in.
4. **Reports from hostB.** The receiver reports each change it makes, protected
   by a key hostB created during setup. Your laptop checks that the reports
   hostA passes on are hostB's, and that hostA left none out, added none, and
   did not cut them short.

An enrollment covers the whole account. Each signed command names its own
destination, which can be anywhere the account can write except its SSH
configuration and syq's own programs and state (see
[Enrollment](remote-reference.md#enrollment)). The receiver does not follow
symlinks below the destination. Because a copy can write a file that runs code
as the account, such as a shell startup file, a signed copy is as strong as a
login. That is acceptable because only your login key can sign one, and you
choose each destination.

An enrollment outlives removing or revoking your login key on hostB; end it with
`syq receiver revoke`. See
[Changing keys](remote-reference.md#changing-keys-and-updating-syq) for what
does and does not stop a signed copy.

Other modes grant more: `--peer-auth broker` limits authentication to the
chosen host and user but grants that account's full authority, and
`--peer-auth full-agent` exposes your SSH agent as `ssh -A` does. See
[Other authentication modes](remote-reference.md#other-authentication-modes).

### How hostA checks hostB's key

HostA checks hostB's host key with its own SSH configuration, as its own `ssh`
would. It also trusts the keys and host certificate authorities your laptop's
known_hosts lists for hostB, and refuses keys marked `@revoked` there. Your
laptop's `RevokedHostKeys` and `KnownHostsCommand` settings are not passed on;
syq says so when it leaves them out. If your laptop trusts hostB only through a
certificate authority and hostB presents a plain key, hostA treats hostB as
unknown.

When neither machine knows hostB, nobody can answer a prompt on hostA, so its
default `StrictHostKeyChecking ask` works like `accept-new`: it accepts the key
it sees the first time and checks later connections against it. Your laptop's
own login does the same when it sets up restricted copying for a copy a server
asked it to approve. When you start the copy or `syq receiver enroll` on your
laptop, its login asks you as `ssh` would. Someone who can intercept that first
connection could receive the copy's data and report that it completed, though
they could not use the entry key or the signed copy against the real hostB. For
a copy started on your laptop, your laptop would detect that from hostB's
reports (step 4).

To refuse a host neither machine has seen, set `StrictHostKeyChecking yes` in
hostA's SSH configuration, and add hostB's key to your laptop's known_hosts,
which syq passes to hostA. HostA looks hostB up under the address your laptop's
SSH configuration gives it for a copy started on your laptop, and under the
name in the server's command for a copy a server started. For copies a server
asks your laptop to approve, also set `StrictHostKeyChecking yes` on your
laptop.

### A compromised source server

A compromised hostA can misuse the access a signed copy needs, but cannot give
itself more. Suppose the signed copy lets hostA copy into hostB's `/archive`.

HostA can:

- Supply false contents, names, sizes, or timestamps.
- Set any metadata the copy preserves, such as permissions, ACLs, or extended
  attributes, and with hard links give files in the scope new names.
- Overwrite files where the signed copy permits overwriting.
- Omit a source file and, if pruning is authorized, cause its destination copy
  to be deleted.
- Inspect destination entries, as copy planning requires, and use up the
  allowed space.
- Ignore `--where` and `--copy-if`; hostB enforces only the destination, the
  write and deletion permissions, and the limits.
- Stop the transfer or withhold hostB's reports, which fails the copy.

HostA cannot:

- Change the signed destination to write into `/etc` or an SSH configuration
  directory.
- Overwrite existing files, change their permissions, owner, or other
  metadata, or give them new names with hard links when the signed copy
  permits only creating new ones, or delete files without permission.
- Exceed the signed byte, entry, or deletion limits.
- Reuse the signed copy for another copy, use the entry key it keeps to start
  a later copy without one you newly signed, or use that key to run a shell.
- Forge, alter, or cut short hostB's reports of its changes.

On some filesystems, such as NFS, FAT and exFAT on macOS, and rclone mounts,
a copy permitted only to create new files can still replace a file that
another program creates at the same name while the copy runs, and hostA
controls how long the copy runs.

HostB's account and receiver remain trusted to enforce the signed copy and
report accurately. HostB's reports describe what hostB did; they cannot prove
that hostA supplied the right files, and can accurately report, for example,
that hostB wrote false contents hostA provided.

<a id="file-contents"></a>
<a id="expected-contents-and-corruption-checks"></a>
<a id="consistency-and-durability"></a>

To check contents against a trusted hash, see
[Expected hashes](integrity-checking.md#expected-hashes); for corruption,
consistency, and durability in general, see
[Integrity checking](integrity-checking.md).

## Persistent connections

While a persistent connection is open, any process running as your local user
can use it to reach the server without another key touch or agent approval, even
with receiving off. `syq persist off` closes the default domain's connections,
including receiving; add `--pscope PATH` for an isolated domain.

Persistence domains keep separate connections, authorization choices,
receiving profiles, and remembered account permissions, but share your
account's SSH configuration, keys, agents, and receiver identity. They are not
a security boundary between processes running as that account.

## Receivers

With receiving on, servers you have persistent connections to can make these
requests of your machine:

| Request | Approval on your machine |
|---|---|
| Send files to your machine | Required by default; `--auto-approve-root` permits unattended downloads confined to that directory |
| Copy files from your machine | Always required |
| Authorize one copy to or from another server | Always required |
| Run a command on your machine | Always required |
| Authorize an SSH login to another server account | Required unless this source and destination account pair has a session or remembered permission |
| Use your storage credentials for a transfer | Always required |

Receiving is on by default in the default domain and off in a fresh isolated
domain. `syq persist receive off` turns it off but keeps SSH reuse.

The prompt shows the server account and the requested command. For copies and
authorizations, that is the syq command the server ran, including options from
its environment variables. Your laptop derives what it enforces from that
command and rejects a request that does not match it, but it cannot prove who
typed the command. Approving a copy does not approve a later command.

The server also supplies the contents of the ignore files (`--ignore-from`)
and mapping file (`--mapping`) that the command names, and your laptop does
not check them. Ignore rules can only narrow a copy. A mapping file can only
name destinations inside the approved destination, but it can set the
permissions, including set-ID bits, the modification times, and the group of
the files it lists, even when the command copies no metadata.

By default, every connected server in a domain can use that domain's enabled
receiving profiles; a profile's `--connection` list limits it to the servers you
name, matched by the name your laptop connects with. All processes in an allowed
server account share this authority, and a different profile name does not
isolate them.

<a id="named-receiving-destinations"></a>

### Receiving files on your laptop

Approving a copy permits the destination, overwrite policy, and limits of the
command shown, and syq enforces them on every filesystem operation. Within
those limits, the server can supply false contents, inspect destination
entries during planning, and use disk space. Like any copy, it also removes
syq's leftover partial files beside the files it writes, even when the copy
may not otherwise delete; these are files named like
`.FILENAME.syq-tmp.RANDOM` that are owned by you, have no other names, and that
no program has open for writing.

By default, copies start in your home directory and are not confined to it;
`syq persist receive on --root DIRECTORY` confines them. Automatic approval
(`--auto-approve-root`) trusts the allowed server accounts to overwrite files
inside its root without asking and, when the profile sets `--max-delete`, to
delete up to that many entries per copy. These copies can also set the
permissions of files inside the root, including set-ID bits and write access
for others, and give them any group you belong to. A copy with
`--widen-dirs all`, or one that replaces the root directory itself, still asks.
Choose an inbox whose contents are not automatically executed or loaded as
trusted configuration.

Another client cannot claim your receiving name: reconnecting under it needs
your receiver's private key, which stays on your machine and grants no SSH
login. The server account itself can still change its stored name
assignments.

<a id="sending-files-from-your-laptop"></a>

### Sending files from your laptop

A server can ask for files from your laptop with `syq cp --from @laptop`. The
prompt lists the exact paths it would read and says that they will leave your
laptop. Once approved, the server can list and read only those files and
directory trees, with the symlink behavior the command chose, within the
profile's byte and entry limits and, when the profile sets `--root`, only
inside that root: symlinks can't lead out of it, and neither can a directory
replaced while the copy runs. When the command follows symlinks, the prompt
says so, since the files read may then be elsewhere than the paths shown. It
cannot write, rename or remove anything on your laptop. As with copies between
servers, the server can ask for hashes of approved files beyond the data
limit. File data travels over your laptop's receiving connection, as downloads
do, and reads stop when the copy ends or receiving stops.
`--auto-approve-root` never applies: every request asks.

<a id="authorizing-copies-to-another-server"></a>

### Copying between servers

A connected server can ask your laptop to authorize a copy to another server.
Your laptop shows the command, sets up or updates the destination account's
enrollment when needed, and signs the approved copy with your login key. It
gives the server the entry key and what your laptop's known_hosts lists for
the destination. The protection then works as in
[Copies between servers](#copies-between-servers), with the server that asked
in hostA's place, and the destination's receiver also enforces your laptop's
copy limits. Your credentials and signing agent stay on the laptop.

Two things differ. Your laptop does not check the destination's reports
(step 4); the server reports the outcome itself, as for any copy it runs. And
once approved, the copy continues even if your laptop disconnects or stops
receiving, until it finishes, someone interrupts it on the server, or you
revoke the enrollment. The server chooses the contents written within the
approval and keeps the entry key afterwards.

A server can also ask your laptop to approve a download from another server. Syq
on the source then reads only the approved files and directory trees, applies
the selected symlink behavior, accepts no writes or removals, and limits the
file data, entries, and connections it returns. The server can also ask for
hashes of approved files; these do not count toward the data limit, so that
limit does not bound what the server can learn from them. File data uses
authenticated, encrypted TCP directly between the servers, and the copy fails
without it. Closing the approval connection stops further reads.

<a id="approved-commands-on-receiving-machines"></a>

### Running commands on your laptop

A command a server runs with
[`syq exec`](receive.md#run-commands-on-your-laptop) runs, once approved, with
your local user's full permissions. It is not sandboxed or confined to a copy
destination.

### Storage authorization

[Storage authorization](object-storage.md#authorize-from-your-laptop) gives the
server signed URLs for the approved paths and operations, while the secret
access key stays on your laptop. Within the authorizing credentials'
permissions, approval trusts the server to choose uploaded contents and object
settings, such as tags or Object Lock retention, because some services accept
request headers that a signature does not cover. Anyone with the URLs can
reuse them until they expire; stopping receiving does not revoke them. The
protections for filesystem copies do not apply: receiving roots, per-copy
byte, entry, and deletion limits, and single-use signed copies.

Upload approval is not a write-only grant. It includes reading object
contents and metadata within the approved destination paths, to compare with
existing files. When updates are allowed, it also permits reading destination
tags, updating tags on the current destination object, and copying an object
onto itself to update metadata. It does not authorize tag changes on older
versions or copying a different destination object as the source;
bucket-to-bucket copies need a separately approved source.

## SSH account access

Approving SSH account access, as requested by
`syq ssh --auth-from @laptop` or a copy with `--auth-from @laptop`, gives the
requesting server that account's full authority: it can run any command and
read or change any file the account can. The command the prompt shows is
context from the requester, not a restriction, and copy paths, download roots,
and byte limits do not apply. Copies your laptop approves one at a time keep
their own narrower scope.

**Allow** covers this pair of source and destination accounts for the current
receiving connection from your laptop to the source. **Remember** also covers
later connections through the same receiving profile and domain, while your
laptop is available. Either is bound to both accounts, the route, and the host
names and plain host keys your laptop trusts for them; a request cannot add a
host key, and a changed one needs fresh approval. With `ProxyJump`, each jump
account needs its own approval.

Any process running as the requesting account can use the approved
connection, not just the shell that asked. Your laptop signs logins only for
the approved account and host keys; its agent is not forwarded, and the
permission cannot reach another account or sign anything else. Custom proxy
commands use the requesting machine's own authentication.

Stopping receiving ends further authorization through that connection, and
removing a remembered permission makes later logins ask again. Neither ends
sessions already authenticated, undoes remote changes, stops detached
processes, or revokes other access created with the account in the meantime.
See [Account permissions](persistence-reference.md#account-permissions) for
the commands.

### Ordinary SSH authorization providers

Anyone who can log in to a provider account can run programs there and use
its credentials outside syq; syq's prompts control only syq's own requests.
When the requesting server must not have a full login to the machine holding
the credentials, use a receiving connection from a laptop instead.

With `--auth-from [USER@]HOST[:PORT]`, the requesting machine logs in to the
provider account with its own SSH access, and the provider's receiving service
asks for access to each destination account. The provider cannot tell which
machine made that login, so its prompts name the provider account rather than
a source server. **Allow** lasts for the current provider connection;
**Remember** covers later logins to that provider account through the same
profile and domain. Stopping receiving prevents further syq authorizations but
does not revoke SSH access to the provider.
