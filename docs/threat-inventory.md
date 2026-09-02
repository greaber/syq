# Filesystem-transfer security threat inventory

Status: factual working inventory, not a plan or product decision  
Code snapshot inspected: `8a8dd2a` (`master`, 2026-09-01)  
Comparison reference: upstream rsync 3.5.0

This inventory backs the parity discussion in [Security](security.md). It
describes a specific code snapshot; re-inspect and update it when the
filesystem, protocol, or receiver code changes, and say so in the header.

## Purpose and limits

This note answers four factual questions:

1. What can an attacker or concurrent process do?
2. What harm could follow?
3. What does rsync 3.5.0 do about it?
4. What does the inspected SYQ code do, and what remains uncertain?

It does not select a threat model, rank implementation work, prescribe CLI
defaults, or propose a release gate. A listed risk is not necessarily an
exploitable bug. Some entries are documented limitations, some are ordinary
Unix semantics, and some need more investigation.

The code has several materially different filesystem paths. Statements about
one must not be generalized to all of SYQ:

- Native `cp` and `cp-prune` use the ordinary transfer engine. Their initial
  preservation bundle is rsync-like `-rlt`.
- `syq rsync` uses that ordinary engine with the selected compatibility flags.
- Native `rm` has a separate descriptor-rooted implementation in
  [`src/native_rm.rs`](../src/native_rm.rs).
- Signed restricted receivers and guarded destination operations use the
  descriptor-rooted primitives in [`src/rooted.rs`](../src/rooted.rs).

The maintainers' older root-anchored path confinement note is a design
proposal kept in planning files; this inventory is the factual snapshot of the
code named above.

## Threat models mentioned in this note

| Model | Attacker capability | Example |
| --- | --- | --- |
| Malicious protocol peer | Sends arbitrary well-formed or malformed protocol data but has no receiver filesystem authority | A compromised sending endpoint invents `../../etc/passwd` as a file name |
| Untrusted source tree | Can change names and objects inside a tree while SYQ reads it with greater authority | A tenant flips `tree/a` between a directory and a symlink while root copies it |
| Untrusted destination tree | Can change names and objects inside a tree while SYQ writes or deletes with greater authority | A user changes a destination parent to a symlink while root updates a backup |
| Untrusted sidecar storage | Can create, replace, open, or rename SYQ's partial-file names | A user pre-creates a deterministic `.name.syq-part.*` file before a privileged copy |
| Cooperative tree | Other processes may make ordinary changes, but do not deliberately race SYQ to redirect authority | Two backup jobs overlap accidentally |
| Same-identity or authorized writer | Has the same effective filesystem identity as SYQ, or will legitimately be allowed to modify the final file | A process running under the destination account edits a published mode-`0664` file |
| Compromised endpoint account | Can run arbitrary code with the endpoint login's OS authority | A compromised remote helper account reads anything that account itself can read |

These models are independent of local versus NFS storage. NFS may change the
cost and reliability of metadata observations, but it does not by itself say
whether another principal is malicious.

Two limits follow directly from the models:

- A file-transfer program cannot keep a final file unchanged after publication
  from an identity that is legitimately allowed to modify it.
- An unrestricted helper running as an endpoint account cannot confine an
  attacker who has already compromised that same account. A restricted
  receiver can reduce the authority granted to a different endpoint, but it
  does not repair compromise of its own executing identity.

## Risk concentration at the inspected snapshot

This is a description of evidence, not an implementation priority list.

| Area | Observed state at `8a8dd2a` |
| --- | --- |
| Ordinary-copy descendant destination paths | Known partial coverage: the destination root is retained, but ordinary descendant operations still include relative pathname calls. The regression ledger records this explicitly. |
| Restricted destinations | Descriptor-rooted descendant operations exist and reject descendant symlink traversal. The supported operation set is narrower than the unrestricted engine. |
| Native `rm` | Uses pinned directories, `fstatat`, and `unlinkat`; it does not recursively follow a symlink discovered in the selected tree. |
| Reusable partial files | Deliberately assumes their containing directory is not writable by an untrusted user. This is documented in the README. |
| Remote scan names | Syntactically validated as relative paths; absolute, NUL, empty, `.` and `..` components are rejected. |
| ACLs and xattrs | Not implemented, so rsync vulnerabilities in their application are not currently reachable through those features. |
| Owner, group, full modes, devices and specials | Not native-copy defaults. They remain available through explicit rsync-shaped preservation flags where supported. |
| Protocol robustness | Frames are length-bounded, and several request-specific bounds exist. There is no claim here of rsync-equivalent fuzzing or a complete malicious-peer audit. |

## Threats and current behavior

### 1. Peer-supplied lexical path escape

**Attack.** A sender reports an absolute name, `..`, an empty path component,
or another spelling intended to make the receiver address something outside
the transfer root.

**Possible effect.** Reading, creating, replacing, changing metadata on, or
deleting an object outside the operator-selected tree.

**Rsync 3.5.0.** Rsync treats peer file lists as untrusted, validates them, and
resolves accepted transfer paths beneath a retained root. Its security document
describes validation as necessary but distinct from race-safe path resolution.

**SYQ snapshot.** `validate_remote_scan_batch()` in
[`src/conn.rs`](../src/conn.rs) requires the root entry first and rejects
absolute descendant paths, NUL, empty components, `.` and `..`. The restricted
receiver independently validates relative paths. This blocks lexical traversal;
it does not by itself stop a valid component from being replaced by a symlink
later.

**Evidence status.** Implemented and tested for scan responses. This note does
not assert that every request variant accepting a path has received an
independent malicious-peer audit.

### 2. Source parent-component symlink race

**Attack.** After SYQ decides to read `source/a/file`, an attacker replaces
`a` with a symlink to another directory before enumeration, metadata lookup, or
content open.

**Possible effect.** A more-privileged sender may disclose a file outside the
selected source tree or copy an object the operator did not select.

**Rsync 3.5.0.** Source enumeration and content opens use a component walk from
a retained root. Each directory is opened without following an unexpected
symlink, and enumeration uses the opened descriptor.

**SYQ snapshot.** Selected compatibility regression cases for source races
pass, but the ordinary scanner in [`src/scan.rs`](../src/scan.rs) and several
ordinary source opens are not uniformly expressed through `Root`. The exact
guarantee of the ordinary source path therefore needs a code-level audit beyond
the existing tests. Restricted destination rooting does not protect an
ordinary source endpoint.

**Evidence status.** Partial/uncertain. No demonstrated escape is asserted
here; neither is complete confinement.

### 3. Destination parent-component symlink race

**Attack.** After SYQ plans `destination/a/file`, an attacker replaces `a`
with a symlink before an ordinary write, rename, metadata operation, or delete.
Protecting only `file` with `O_NOFOLLOW` does not protect `a`.

**Possible effect.** A privileged receiver may modify or delete an object
outside the selected destination tree.

**Rsync 3.5.0.** Rsync resolves transfer paths component by component, retains
the parent directory descriptor for an entry, and performs leaf work through
`*at()` calls. The mechanism covers temporary creation, publication, metadata,
and recursive deletion.

**SYQ snapshot.** The ordinary transfer engine securely selects and retains
the operator-named destination root in [`src/fsops.rs`](../src/fsops.rs), then
changes into it. It also rejects unsafe relative components. Many descendant
operations still use relative `std::fs` pathname calls, so a descendant parent
can be re-resolved after it changes. The current
[`tests/rsync-compat/REGRESSIONS.md`](../tests/rsync-compat/REGRESSIONS.md)
records this as partial confinement.

Guarded restricted destinations instead use `Root`, whose intermediate opens
are `O_DIRECTORY | O_NOFOLLOW` and whose leaf operations are relative to a held
parent. Native `rm` has its own equivalent descriptor-rooted walk.

**Evidence status.** Known gap for ordinary copy/`cp-prune`/rsync-shaped
deletion; implemented for the supported guarded and native-`rm` paths.

### 4. Replacement of the operator-named destination root

**Attack.** An attacker replaces a symlink or directory named directly by the
operator between initial resolution and worker activity.

**Possible effect.** Workers could enter a different destination from the one
the control connection approved.

**Rsync 3.5.0.** Operator-supplied paths use a component ownership walk. A
symlink is followed only when owned by root or by the process effective user,
unless the operator explicitly enables insecure link behavior.

**SYQ snapshot.** Ordinary copy implements the same ownership rule for the
operator destination, retains the opened directory, verifies device/inode
identity for workers, and exposes `--insecure-links` as an explicit opt-out.
Restricted receivers refuse destination-root symlinks and bind the signed root
to an opened identity.

**Evidence status.** Covered by local and rsync-compat regression tests. This
does not imply descendant confinement described in item 3.

### 5. Leaf replacement with a symlink, FIFO, device, or directory

**Attack.** An attacker changes the final path component after inspection so
an open follows a symlink, blocks on a FIFO, accesses a device, or unexpectedly
recurses into a directory.

**Possible effect.** Out-of-tree access, a hung privileged process, device I/O,
or deletion broader than the selected leaf.

**Rsync 3.5.0.** Leaf operations are performed relative to held parents;
regular-file opens use no-follow behavior, temporary files use exclusive
creation, and metadata is applied through opened descriptors where supported.

**SYQ snapshot.** Ordinary regular-file opens use `O_NOFOLLOW | O_NONBLOCK`
and verify the opened type. Sidecars must be singly linked regular files.
Planned deletion uses separate `Unlink` and `Rmdir` operations: a leaf that
becomes a directory is not recursively removed. Native `rm` pins the observed
identity and checks it again before `unlinkat`.

**Evidence status.** Substantial leaf coverage. An unsafe intermediate parent
can still redirect an ordinary pathname before these leaf checks run.

### 6. Deterministic reusable-sidecar pre-creation or replacement

**Attack.** A user who can write the destination directory creates or replaces
the predictable `.name.syq-part.<job-id>` pathname. A singly linked regular
file can pass the current type and link-count checks without proving that SYQ
created it.

**Possible effect.** The attacker may retain access to an inode used as resume
state, observe partial contents, race modifications into staged data, affect
the object eventually published, or cause repeated failure.

**Rsync 3.5.0.** Ordinary temporary files have random suffixes and are created
exclusively with only owner access. Persistent `--partial-dir` reuse has an
explicit manual warning: its directory must not be writable by other users.

**SYQ snapshot.** Automatic resume uses deterministic adjacent sidecars.
New sidecars are created exclusively as mode `0600`; existing candidates are
opened without following a leaf symlink and must be regular with link count
one. Numeric ownership is deliberately not treated as provenance because NFS
root squashing and FUSE/CIFS mappings can change it. The user-facing
[command reference](reference.md#resume-and-checkpoints) states that the
containing directory is a trust boundary and must not be writable by untrusted
users, especially for a privileged invocation.

**Evidence status.** Documented limitation, not an undocumented claim of safe
operation in an attacker-writable sidecar directory. Because SYQ enables
persistent partials by default while rsync does not, identical ordinary CLI
flags do not imply an identical partial-storage attack surface.

### 7. Temporary-file permissions during construction

**Attack.** Another identity reads or modifies a named temporary file before
publication, or executes a file while its bytes or metadata are incomplete.

**Possible effect.** Disclosure of abandoned/incomplete data or corruption of
the object SYQ believes it published.

**Rsync 3.5.0.** Temporary creation masks access to owner-only bits and removes
set-ID/group/other access. Final metadata is applied after transfer.

**SYQ snapshot.** New sidecars are `0600`. At finalization SYQ applies the
computed mode and mtime before the atomic rename. Thus the sidecar contents are
complete when final access is enabled, but there is a short interval in which
the complete file has final permissions under its sidecar name.

**Evidence status.** `0600` supplies a real construction-time restriction but
does not solve item 6 and cannot protect a final file from an identity that is
authorized to modify its final mode.

### 8. Hard-linked destination aliases

**Attack.** A destination path is a hard link to an inode also named outside
the selected tree. SYQ changes that inode rather than publishing a new one.

**Possible effect.** Content or metadata changes become visible through the
outside name despite pathname confinement.

**Rsync 3.5.0.** Normal staged content replacement creates a new inode and
breaks extra destination hard links. `--inplace` deliberately retains the inode
and changes every alias. Metadata-only changes to an existing inode are also
visible through all aliases.

**SYQ snapshot.** Ordinary staged content replacement has the same broad
property: aliases retain the old inode. `--inplace` changes the existing inode.
Content-identical metadata repair uses an opened handle to the existing inode,
so all hard-link aliases observe the metadata change. Sidecars themselves are
required to have link count one.

**Evidence status.** Mostly ordinary Unix/rsync semantics rather than a path
escape. It becomes security-sensitive when SYQ has more authority than whoever
can arrange the hard link and the OS permits that link to be created.

### 9. Recursive deletion under concurrent changes

**Attack.** An attacker changes a selected leaf into a directory, inserts new
children, replaces an ancestor with a symlink, or swaps the selected name to a
different inode while deletion is running.

**Possible effect.** Deleting more than was selected, deleting outside the
tree, or leaving a partial result.

**Rsync 3.5.0.** Recursive deletion uses held parent descriptors and fd-relative
operations. A concurrently non-empty directory can still make deletion fail.

**SYQ snapshot.** `syq rsync --delete` and native `cp-prune` plan leaves as
non-recursive `Unlink` and directories as deepest-first `Rmdir`, so a leaf type
change does not broaden into a recursive delete. They still share the ordinary
descendant-parent pathname limitation in item 3.

Native `rm` resolves all selectors before its first mutation, retains selected
objects and parent directories, enumerates opened directories, checks
device/inode/type before removal, and calls `unlinkat`. Concurrent additions
can produce `ENOTEMPTY`, retries, and a partial failure; a name swapped to a
different inode is refused rather than deleted.

**Evidence status.** Native `rm` has the strongest current mechanism. Copy
pruning has safe leaf-type behavior but incomplete ordinary parent confinement.

### 10. Privileged modes, ownership, devices, ACLs, and xattrs

**Attack.** Untrusted source metadata asks a privileged receiver to create a
set-ID executable, change ownership, install a device node, or copy an ACL,
security label, or capability xattr. A raced metadata path could also redirect
the privilege change.

**Possible effect.** Privilege grant, access-policy change, device access, or
metadata modification outside the destination.

**Rsync 3.5.0.** These behaviors require preservation options. Rsync applies
security-sensitive metadata to held objects and documents platform residuals
where no race-safe API exists.

**SYQ snapshot.** Native `cp`/`cp-prune` currently select `-rlt`: they do not
enable full permission, owner, group, or device/special preservation. New files
without `-p` omit special bits; an updated existing file retains its destination
mode, including pre-existing setuid/setgid bits, matching rsync's no-`-p`
behavior. `syq rsync -p`, `-o`, `-g`, and `-D` expose the corresponding
supported behavior explicitly. ACLs and xattrs are not implemented, so file
capabilities stored as xattrs are not copied.

The signed restricted receiver distinguishes receiver-derived non-`-p` modes
from source-proposed preserved modes and limits which flags a grant authorizes.
Ordinary compatibility operations do not use all of those restrictions.

**Evidence status.** Native defaults reduce exposure by omitting these classes;
explicit compatibility flags and future metadata features remain separate
attack surfaces.

### 11. Source mutation during a transfer

**Attack.** A source changes after scanning or while different ranges are read,
possibly preserving metadata used by a quick check.

**Possible effect.** A destination assembled from different source states,
truncation, or a misleading success result.

**Rsync 3.5.0.** Rsync detects several size/read changes and reports vanished or
changed files, but it does not provide a filesystem snapshot.

**SYQ snapshot.** SYQ hashes transmitted blocks, checks expected sizes, re-stats
the source after completion, and retries ordinary files whose size or mtime
changed. It preserves an old destination on ordinary staged-copy failure and
continues unrelated transfers. These checks do not create an immutable source
snapshot; a malicious writer able to change bytes while preserving the checked
metadata can exceed the guarantee.

**Evidence status.** Good accidental-change handling; no snapshot or
adversarial same-metadata guarantee.

### 12. Shell and SSH argument injection

**Attack.** A host, path, option, newline, or shell metacharacter is interpreted
as a second remote-shell command rather than as data.

**Possible effect.** Arbitrary command execution under the SSH login account.

**Rsync 3.5.0.** Remote-shell argument quoting and validation are treated as a
security boundary and have dedicated regressions.

**SYQ snapshot.** The compatibility corpus includes a passing adapted
remote-shell newline injection test. Native endpoint grammar separates endpoint
identity from paths and rejects path-like endpoint spellings. This inventory
does not claim that every option eventually forwarded through every topology
has been audited.

**Evidence status.** Important covered case plus remaining surface audit.

### 13. Protocol memory, CPU, and request amplification

**Attack.** A peer sends oversized frames, large collections, pathological hash
requests, recursive structures, repeated failures, or many individually valid
messages intended to exhaust memory, CPU, file descriptors, or work queues.

**Possible effect.** Process or host denial of service rather than filesystem
escape.

**Rsync 3.5.0.** The project describes protocol input as untrusted and uses
continuous fuzzing, bounds checks, and regression tests.

**SYQ snapshot.** [`src/proto.rs`](../src/proto.rs) limits an encoded frame to
256 MiB, constrains hash block sizes and response estimates, and several
restricted requests have additional signed entry/byte/connection limits. The
ordinary authenticated helper protocol still accepts repeated frames and large
valid jobs. No rsync-equivalent fuzzing claim or resource envelope is recorded
here.

**Evidence status.** Some explicit bounds; broader malicious-peer/resource
audit unknown.

## NFS and other ownership-remapping filesystems

NFS changes the interpretation or cost of several mechanisms above without
creating a new attacker model:

- Root squashing and other ID mappings mean `st_uid == geteuid()` is not a
  portable proof that the current process created a sidecar.
- Attribute and name caches mean `stat` observations are not a multi-object
  snapshot. An opened file or directory descriptor remains a stronger identity
  reference than a path observation.
- A cold descriptor component walk may cause additional directory lookup/open
  RPCs. A warm cache may satisfy some of them locally. No NFS measurement of
  SYQ's current rooted implementations is recorded here.
- Current staged publication commonly performs exclusive sidecar creation,
  final `chmod`, final `utimens`, and `rename`. On NFS, the mode and time changes
  can become separate metadata operations. Directory mtimes add analogous work.
- Keeping `-t` costs a metadata update when content changes, but also enables
  the size-and-mtime quick check that can avoid later data transfer.
- Reusing a partial requires reading and hashing it. This can be much more
  expensive than a local cached read, but may save retransmission of a much
  larger file.
- Owner/group, ACL, xattr, and special-file fidelity introduce additional
  metadata operations and platform-dependent failure behavior.
- Atomic rename, crash durability, and server acknowledgement are separate.
  Current normal publication is old-or-new visible but does not `fsync` every
  file and directory before reporting success.

These facts do not establish whether a proposed security check is expensive on
a particular NFS deployment. Relevant measurements would need to distinguish
client-cache hits from RPCs and record operations such as LOOKUP/GETATTR,
SETATTR, CREATE, and RENAME. No performance or safety profile is selected by
this note.

## Facts still needing verification

The following are uncertainties in this snapshot, not scheduled work:

- The exact ordinary-source confinement guarantee under every enumeration and
  content-open race, beyond the existing passing regression cases.
- A complete operation-by-operation comparison between ordinary SYQ and rsync
  3.5.0's held-parent path resolution.
- Whether every ordinary protocol path is validated at the narrowest authority
  boundary rather than only when scan results enter the planner.
- The consequences of deterministic automatic sidecar reuse under each NFS,
  FUSE, CIFS, root-squash, and shared-directory identity model.
- Non-Linux behavior where `O_PATH`, `/proc/self/fd`, or particular `*at()`
  metadata primitives differ or are absent.
- RPC and wall-clock costs of `0600` sidecars, final mode/time updates,
  descriptor walking, directory-fd reuse, and partial hashing on actual NFS
  systems.
- Protocol parser and scheduler behavior under sustained hostile but
  frame-valid traffic.

## Primary rsync references

- [Rsync 3.5.0 security policy and path-resolution design](https://github.com/RsyncProject/rsync/blob/v3.5.0/SECURITY.md)
- [Rsync manual: permissions, partial files, and partial-directory warning](https://download.samba.org/pub/rsync/rsync.1)
- [Rsync receiver temporary-file construction](https://github.com/RsyncProject/rsync/blob/v3.5.0/receiver.c)

