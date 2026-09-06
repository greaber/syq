# Security

Syq is designed for copies where the tool has more authority than some of the
files or machines involved: a backup account reading another user's tree,
root copying an upload, or two servers transferring through your laptop.

Report vulnerabilities through
[SECURITY.md](https://github.com/greaber/syq/blob/master/SECURITY.md).

## Filesystem attacks

Assume an attacker can change files and directory entries inside a selected
tree, or in a parent directory they can write. They may act before the copy
starts or while it is running. They do not control the account running syq.

The attacks we aim to stop include:

- **Redirecting a read or write with a symlink.** A directory might be
  replaced with a link to a private source or unrelated destination.
- **Escaping through a supplied filename.** A peer might send an absolute
  path or `..` components to reach outside the selected tree.
- **Turning a deletion into a walk of another directory.** An entry might
  change type after syq has decided what to remove.

Native syq refuses symlink traversal unless you explicitly request it. It
keeps selected directories open and works through those handles, so later
renames cannot redirect the copy to another tree. Names received from the
other endpoint are validated; deletion does not follow replacement links or
recurse into unexpected directories.

These protections bound where the operation can go. They do not prevent an
authorized writer from changing the contents of that tree. In a removal race,
a single replacement entry can still be unlinked.

## Relationship to rsync 3.5.0

Syq's path protection is inspired by
[rsync 3.5.0's security design](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md#symlink-race-safe-path-resolution):
keep directories open, work relative to them, and distrust peer-supplied paths.

The default for paths you type is simpler in native syq:

| | Follow a symlink in a supplied path? |
|---|---|
| Rsync 3.5.0 | Yes if the link belongs to root or the process's effective user |
| Native syq | Only with an explicit follow option |

Rsync's [ownership policy](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md#symlink-defense-for-operator-supplied-paths)
preserves familiar symlinked directory setups. Our concern is that link
ownership alone does not prove who placed it there: rename permissions come
from its parent directories, subject to restrictions such as the sticky bit.
A relative link moved to another directory can point somewhere different
without changing its owner. See the [rename rules](https://man7.org/linux/man-pages/man2/rename.2.html).

Native syq avoids that implicit trust decision. This is a stricter default
for this case, not a claim that syq is more secure overall. `syq rsync`
keeps the ownership-based policy for compatibility. Its local-only
`--insecure-links` option permits foreign-owned symlinks in typed local source,
destination, and control paths. After opening a source root, scans and content
reads still use its directory handles and refuse descendant symlink traversal.

## TCP data connections

TCP workers authenticate with a token delivered through the control connection.
Their ten-second Hello deadline remains active across partial reads, including
when encryption is off. After Hello succeeds, it does not limit copy duration.
There is no general coordinator I/O deadline: a stalled peer can leave a copy
waiting until you cancel it.

TCP discovery accepts at most 64 advertised addresses plus the SSH target,
and at most 128 resolved socket addresses in total. Excessive replies fail
TCP setup visibly; ordinary copies can still fall back to SSH data.

Encrypted TCP rejects reused connection IDs and IDs outside its 24-bit nonce
space. If a copying process exhausts those IDs, it reports an error; restart the
copy to continue with a fresh session.

Framed input has a separate memory allowance from the signed transfer's disk
limits. Hello is limited to 1 MiB, ordinary metadata messages to 8 MiB, and
bulk-data or hash messages to 65 MiB. Compression cannot bypass these limits;
zstd windows are limited to 8 MiB. Both endpoints apply the smaller Hello
limit before reading or decompressing its body.

A shared 512 MiB allowance bounds decoded collection storage, including queued
collections, because a short frame can advertise a very large collection.
Exhaustion fails the connection visibly. Flat byte buffers, strings, and
compression workspace use the frame-size limits and each connection's bounded
queue instead of competing for that shared allowance. Their aggregate memory
use grows with the connection count, request size, and pipeline depth; reduce
those settings to use less memory. The collection allowance is not a limit on
total process memory or disk usage.

## A compromised source server

The coordinator rejects stat, apply, and partial-path replies whose entry
counts differ from their requests. It also checks each source data block's
offset and length against the outstanding read before forwarding it to the
destination. These checks expose malformed replies; they cannot establish
that a source's file listing or contents are truthful.

For a default direct remote-to-remote copy, the source gets permission for one
transfer, not your SSH agent or a reusable destination credential. The
restricted receiver enforces the destination, options, and limits independently.
The source cannot enlarge or replay that permission.

The receiver signs what it did, and your machine verifies the receipt. A
source cannot forge a clean account of destination changes. It can still omit
files, invent content or metadata, or stop. A receipt does not prove the
source supplied everything you intended.

The destination machine, receiver, and account remain trusted. Other
[authentication choices](remote-to-remote.md#other-routes-and-authentication)
have different boundaries: broker-only authentication permits that destination
account's full authority during the session; full agent forwarding exposes
your agent as `ssh -A` would.

## Named receiving destinations

A [named destination](receive.md) lets a server account request copies through
an outbound connection maintained by your laptop. `persist on` enables this
for syq's SSH connections by default. Each request requires approval on the
receiving machine through a desktop prompt or `recv approve`. Paths and limits
are validated before prompting; the restricted filesystem executor checks
every operation after approval. The server receives no SSH agent or
command-execution interface.

Approval permits that pending copy's destination, overwrite policy, and limits.
It does not authenticate what you typed on a remote server or attest to source
contents. The receiving user and desktop session remain trusted. Request IDs
are local, expire after five minutes, and cannot be reused. Disconnecting or
stopping receiving cancels pending decisions. Desktop failure never approves a
copy. `syq recv on --approve always` explicitly removes the per-copy decision
and trusts connected server accounts for repeated copies.

The default starting directory is your home directory, with no containment.
`syq recv on --root DIRECTORY` contains copies; `syq recv off` disables receiving
while keeping ordinary persistence. A compromised connected server account can
request more copies and invent their content. Once approved, it can inspect
destination entries during copy planning and consume disk space within the
approved limits. The laptop's receiving account is trusted.

Bare destination names fall back to ordinary SSH while the laptop is offline.
Use `@name` when you require a return connection and want failure instead of
host resolution. A copy never switches routes after selecting its destination.

## Limits to keep in mind

- **Privileged copies need trusted destination directories.** Resume uses
  predictable partial-file names. Do not copy as root into a directory
  writable by untrusted users. Syq only reuses partials owned by its effective
  user; foreign-owned leftovers are replaced without changing their contents
  or permissions. This does not make a shared writable directory trusted.
- **Copies are not snapshots or transactions.** Stop concurrent writers or
  use snapshots for consistent data. `--inplace` exposes incomplete updates.
  Syq does not `fsync` transfer data, so completion is not a power-loss
  durability guarantee.
- **Preserving authority is a choice.** Leave `--preserve=ownership` and
  `--preserve=permissions` off when copying from an untrusted source.
- **Persistent logins stay usable.** Processes running as your local user
  can reuse them until they close. Use `syq persist off` to end the window.
- **Protocol assurance is still developing.** Syq's process protocol has
  not been fuzzed as extensively as rsync's.

## Code and transport integrity

File data is encrypted and authenticated by default. `--tcp-plain` gives up
that protection. Downloaded code for remote operations and explicit
self-updates is verified against a signed release manifest before use.
That verification cannot protect a machine whose trusted account or programs
have already been compromised.

A server can also request a copy to another SSH host using a live receiving
machine's SSH access. Eligible copies discover that machine automatically;
`--auth-from @name` chooses it explicitly. This always needs a local decision,
even if automatic receiving is enabled. Refusing the request ends the attempt;
syq does not try another authorization source.
Approval authorizes a connection using the receiving machine's SSH access and
installation of a matching helper. The destination helper enforces one copy's
paths, permissions and limits. The server gets a restricted control stream
and encrypted TCP worker access for that copy; it gets no SSH agent, private
key, or command-running interface. Host trust and SSH configuration are those
of the approving machine. The destination account remains trusted, including
its interpretation of relative paths. A compromised source can substitute
content within the approved scope, just as with other return copies.

## Approved commands on receiving machines

[`syq exec`](exec.md) uses an existing return connection and always asks for a
local decision before starting a program. Command approval is separate from
copy approval, including when copies are automatically approved. The prompt
shows the server account, argument list and working directory. A server
account can request commands from any of its processes; syq cannot establish
what a person typed in a remote shell.

Approving execution grants the command your local user's authority. Copy root
confinement, file protection and transfer limits do not restrict that program.
Scripts and build files can change what it does. Commands receive the local
service environment and closed stdin. They do not expose a general SSH agent
forwarding interface, but an approved program can access credentials available
to the local user.

Disconnecting cancels the foreground process group; commands are never
replayed automatically. Completed effects cannot be rolled back, and programs
that create separate process sessions can outlive cancellation. See the
[command reference](exec.md#output-completion-and-cancellation) for execution
and interruption behavior.

Human copy listings escape control characters in filenames. Diagnostics also
escape terminal control sequences from peers; NDJSON keeps its JSON encoding.
