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

Two attackers are outside the design because no file tool can address them:
someone who already controls the account syq runs as, on either end, and
someone legitimately allowed to modify the result. A local user with write
access to a destination tree is the second kind. New protections are judged
against this list: a check has to stop one of the attackers above, and not
one of these two.

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
`--insecure-links` option relaxes source, destination, and control-path checks.

## A compromised source server

For a default direct remote-to-remote copy, the source gets permission for one
transfer, not your SSH agent or a reusable destination credential. The
restricted receiver enforces the destination, options, and limits independently.
The source cannot enlarge or replay that permission.

The receiver can enforce only what it can decide from its own disk and the
messages it receives. That rule sorts every option. Anything about the
destination's own state is enforced there: staying inside the enrolled
directory, whether that directory must already exist or must be new, ignore
rules, preservation, limits, deadlines, and single use of the permission.
Anything that depends on the source's account of itself, such as `--update`
comparing source times or `--mapping` supplying a manifest, is refused rather
than trusted. And because nothing from the destination reaches you except
through the source, enforcement alone cannot make the source's report
trustworthy; that is what the receipt is for.

The receiver signs what it did, and your machine verifies the receipt. A
source cannot forge a clean account of destination changes. It can still omit
files, invent content or metadata, or stop. A receipt does not prove the
source supplied everything you intended.

The destination machine, receiver, and account remain trusted. Other
[authentication choices](remote-to-remote.md#other-routes-and-authentication)
have different boundaries: broker-only authentication permits that destination
account's full authority during the session; full agent forwarding exposes
your agent as `ssh -A` would.

## Limits to keep in mind

- **Privileged copies need trusted destination directories.** Resume uses
  predictable partial-file names. Do not copy as root into a directory
  writable by untrusted users: file checks cannot establish who created a
  preexisting partial.
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
