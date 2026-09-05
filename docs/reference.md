# Command reference

This is the detailed behavioral reference for syq's commands: the native
commands (`syq cp`, `syq rm`, and `syq map`), persistent SSH connections,
rsync mode (`syq rsync`), path semantics, how a copy works, resume,
verification, filtering, deletion, and exit codes. [Speed](speed.md), [Remote-to-remote
transfers](remote-to-remote.md), [Security](security.md), and
[Composability](composability.md) cover those topics in depth. The code is
authoritative where this document and the binary disagree; please report the
disagreement.

## Native commands

A native command starts with an operation and keeps endpoints, selectors,
and destination placement in separate arguments:

```sh
syq cp project --to server --into /backup       # named object → /backup/project
syq cp --srcs-in project --to server --into /app # project contents → /app
syq cp --from server --cwd /data --src a --src b --into ./data
syq cp --from server:2222 data --to backup:2200 --into /archive
# Pull using credentials already on backup for server:
syq cp --from server data --to backup --coordinate-at dst --peer-auth own-credentials --into /archive
syq cp --src-file report --src-dir assets --into /backup
syq cp --src-files a.txt b.txt --src-dirs images fonts --into /archive
syq cp report --to server --as-new /reports/final
syq cp --hash report --to server --as-existing /reports/final
syq cp --ignore '*.tmp' --srcs-in project --to server --into /app
syq cp --follow-src --srcs-in current-project --to server --into /app
syq cp --preserve=permissions,ownership project --to server --into /backup
syq cp --inplace disk.img --to server --as-existing /images/disk.img
syq cp --prune --srcs-in build --to server --into-existing /srv/app
syq rm cache old-output
syq rm --from server --cwd /srv --src old-output
syq rm --from server --syq-path /opt/syq-dev --src old-output
syq rm --root /srv --src-dir cache
syq rm --cwd /srv --follow-src --src-dir current-release
```

Native path and pattern option values that begin with `-` use the attached
`--option=value` spelling, for example `--src=--archive`, `--src-dir=-`, or
`--into=-archive`. This keeps a following option recognizable. `--mapping -`
is the intentional exception: there, `-` means to read the mapping from
standard input.

`--from [USER@]HOST[:PORT]` selects one source endpoint and `--to
[USER@]HOST[:PORT]` selects one destination endpoint; omission means local. Enclose
an IPv6 address in brackets, for example `alice@[2001:db8::1]:2222`. The port
override is used consistently for the SSH connection, `ssh -G` policy
resolution, known-host lookup, automatic enrollment, and later enrollment
reuse. A local path containing `:` stays local because native mode never
guesses endpoints from path text.

In `cp`, finish the source specification before starting the destination. The
source endpoint, `--cwd` or `--root`, every positional or `--src*` selector,
and `--mapping` must all appear before the first `--to` or placement option.
Other options remain order-independent, so flags such as `--dry-run` may still
follow the placement. This rule makes every bare path's role clear and applies
equally to local and remote copies.

`--cwd DIR`/`-C DIR` changes where relative source selectors are resolved at
the source endpoint. For `cp` and `rm`, selectors may be absolute, or use
`.` and `..` to resolve outside that base. `--cwd` changes where resolution
starts; it does not confine a selection. `syq map` needs named selectors to be
relative and resolve inside the base so it can emit relative source paths.
A contents selector (`--srcs-in DIR`) may point outside the base instead.
With `--root DIR` in place of `--cwd`, all three commands require relative
selectors that stay beneath `DIR`; absolute paths, `~` paths, and `..` that
would leave it are refused before anything changes.

Bare paths and repeatable `--src PATH` select named objects (an object is a
file, directory, symlink, or special file). A named directory keeps its
basename at the destination; by default a named symlink is copied as a
symlink. A trailing slash is just part of how a path is spelled and changes
nothing.
`--src-file PATH` adds the precondition that the named object is not a
directory, while `--src-dir DIR` requires a directory. Without `--follow`, a
symlink satisfies `--src-file` and is copied as a symlink, while it fails the
`--src-dir` precondition. With `--follow-src` (or `--follow`), the precondition
and copy both apply to the referent. These typed selectors are available to
`cp` and `rm`.
`--srcs-in DIR` selects a directory's contents and merges them directly into
the destination directory. `--srcs PATH...`, `--src-files PATH...`, and
`--src-dirs DIR...` are bulk conveniences for the corresponding singular
selectors. Symlinks found while traversing a selected directory are copied as
symlinks and are never followed. A singular selector option takes the next
argument as its value; the attached spelling above works for singular and bulk
selectors and preserves every Unix filename and its raw path bytes.

All native commands use one link-resolution rule for the filesystem paths you
name on the command line. By default, syq refuses a symlink in any component
that must be traversed. The last path component of a named `--src` is the
selected object rather than something to traverse, so a symlink there is
copied as the link itself, not followed. A directory-required selector such as
`--srcs-in` or `--src-dir` cannot use a symlink as its selected directory by
default. `--follow-src` permits this traversal only in source paths you name,
including `--cwd`, `--root`, and source selectors. `cp --follow-dst`
permits it only in the destination placement path. `--follow` is the umbrella:
it enables both directions and also permits traversal in the control paths
read by the coordinator (the process that runs the copy; for a
remote-to-remote copy that is one of the two remote hosts unless you pass
`--coordinate-at local`), such as `--ignore-from`, `--mapping`, and
`--results`. The directional options deliberately do not authorize those
control paths. None of these options makes syq follow symlinks discovered
beneath a selected directory, nor paths that come from a mapping manifest, a
directory scan, or the other endpoint.

A follow option resolves the selected filesystem identity; it is not a textual
substitution of every operand with the output of `realpath`. Logical source
mapping remains separate. If `current` points to `releases/v3`, then
`syq cp --follow-src current --into backup` copies the referent as
`backup/current`, not `backup/v3`. A contents selector still omits that name:
`--follow-src --srcs-in current --into backup` merges the referent's children
directly into `backup`.

For exact placement, the last path component is the requested directory entry,
not something to traverse. Both `--as link` and `--follow-dst --as link`
address and may replace the symlink itself; `--follow-dst` controls only
symlinks in the parent path. The `new` and `existing` preconditions test the
named entry, so a dangling symlink exists for `--as-new` and `--as-existing`.

An `--into` destination, by contrast, must be traversed as a container. A symlink
there is refused by default and accepted with `--follow-dst` (or the
`--follow` umbrella). If the container link is dangling, a placement form that
permits creation may create its referent directory. Thus, if `live` points to
`../releases/v3`, `--follow-dst --into live` uses `v3` as the container,
while `--follow-dst --as live` replaces the directory entry named `live` and
leaves `v3` untouched. To update the referent itself, pass its explicit path,
for example from `realpath`.

When link traversal is intentional, resolving it before invoking syq often
makes the choice clearer than using a follow option:

```sh
readlink -- current-project                 # inspect the link's stored target
realpath -- current-project                 # print the fully resolved path
syq cp --srcs-in "$(realpath -- current-project)" --into /backup
```

A relative value printed by `readlink` is relative to the directory containing
the link, not necessarily the shell's current directory. `realpath` is usually
the safer way to turn a link chain into an explicit operand.

These rules are how native copy and removal stay inside the directories you
selected, even when someone else is renaming paths around them. syq opens each
selected directory once (for a selected file or symlink, its parent directory
and the object itself) and keeps that handle open for the whole run, so later
work is relative to the handle and renaming the path cannot redirect it.
Native `rm` keeps those handles open until its last change is made. Copy
resolves and opens every selected source before it changes anything at the
destination, and every source worker acquires those same open handles when it
starts, before it reports that it is ready. Finding source files and checking
their metadata, including retry checks, source content hashes, and file reads,
all work relative to the open handle plus a strict relative path. They never
reopen the path you typed and never follow symlinks found inside a selected
directory; a selected file authorizes only that one file as it was when it was
opened, not its siblings in the same parent directory. The endpoint and every
started worker keep the selected object open, so the handle stays valid even
if the control connection exits first, and every open for content verifies
that it reached the same file. The target of a selected symlink is read once
through the opened symlink itself and never reread through its directory name,
which could change. Replacing a selected file or symlink itself during the run
is an error, while a file that changes beneath a selected directory is retried.
On macOS this handle-based symlink read requires macOS 13 or newer; older
releases fail when syq opens the sources rather than fall back to reading the
link by name.

Copy gives every destination worker the same open handle for the selected
destination directory. Inspecting the destination, scanning it, planning what
`--prune` will delete, creating directories and special files, changing
metadata, and the planned deletions are all relative to that handle. Checking,
preparing, hashing, and seeding regular files, writing file data, finishing a
file, cleaning up its partial file, and renaming it into place also stay
beneath that open handle and never follow symlinks found there. (The partial
file is the temporary file, named `.name.syq-part.<copy-id>`, that syq writes
beside a destination file and renames into place once it is complete; see
[How it works](#how-it-works).) Using the handle does not change the worker
process's current directory; destination operations do not depend on it.
If a write request reaches an endpoint before that handle exists and carries
no signed grant, syq refuses it instead of resolving the path by name.

Control files on the machine running syq get the same treatment:
`--ignore-from`, `--syq-ignore-from`, `--files-from`, and a named `--mapping`
are read from the file syq reached by walking the path one component at a
time, so renaming that path afterward cannot redirect the read. Their filenames
keep their raw Unix path bytes even though ignore-pattern contents must be
UTF-8. The mapping is read in full before anything at the destination changes.
On Linux, a named FIFO used as one of these inputs is reopened through the
handle syq already holds (via `/proc/self/fd`, after checking that it is the
same object); it therefore waits for a writer like a normal blocking open and
still reads the FIFO that was originally selected even after a rename. A
`/proc` file-descriptor link as the final component, which is what shell
process substitution produces, is opened relative to the open handle for its
`/proc` parent, so process substitution keeps working without falling back to
a plain path lookup. A Linux system without `/proc`, and macOS, refuse a named
FIFO for these inputs before anything at the destination changes, because they
cannot reopen it safely. Use `--files-from -` or `--mapping -`, which read
standard input, or put ignore rules in a regular file. A named `--results`
file is likewise created fresh relative to the open handle for its parent
directory; if an entry already exists there, syq refuses rather than truncating
it. With `--follow`, the selected object is the resolved link target, and a
missing target is created beneath the open handle for its parent. Replacing
the link afterward does not redirect the output. Use `--results-fd` when the
caller needs a pipe, process substitution, device, or other sink that is not a
regular file.

On Linux, a copy whose source and destination are on the same machine can
use the kernel copy (`copy_file_range`): its destination worker receives the
open handles for both sides when it starts, then opens source and destination
files relative to those handles. Rsync mode's `--insecure-links` skips the
kernel copy because it deliberately follows symlinks in source paths, which a
request expressed only in open handles cannot represent. The check that a
directory is not being copied into itself uses the same handles on a
same-machine copy: the destination side takes the opened source directory and
walks up the parents of its open destination handle. Renaming either path on
the command line cannot change that decision.

Rsync mode's `--insecure-links` is the explicit opt-out for rsync
compatibility: that run follows symlinks regardless of who owns them in the
source, destination, and control paths you name, and finds and reads source
files by path name rather than relative to an open handle. As in rsync, the flag is local only. It applies to the source or
destination on the machine where you run syq and to the control files syq
reads there; it is never passed to a remote endpoint, which keeps the default
trusted-owner policy and reads its source files relative to open handles.
Rsync lets the remote side opt out through `--rsync-path`; syq's
`--rsync-path` is an executable path only, so a remote endpoint cannot opt
out. Names that come from a native mapping or from scanning never inherit
native `--follow`; they must stay strictly beneath the opened source directory.
In rsync mode, control paths keep rsync's implicit policy of following a
symlink owned by root or by the endpoint's effective user. The link's owner
and its target are read from the same opened symlink on Linux and macOS 13 or
newer. On platforms that cannot read a link through an open handle (including
older macOS releases), this implicit trusted-owner traversal fails rather than
re-reading the link by name. Native `--follow` remains the explicit way to
follow links regardless of ownership.

Before it starts, syq counts the open file handles the run will need against
the process's open-file limit: the handles already open in the environment
that starts syq, one open parent directory per selected source, one open
handle per selected file or symlink itself, for the endpoint, the control
connection, and every worker that may share its process, plus a conservative
allowance per worker for its file cache, its transport, and handing open
handles between workers that run at the same time. On a same-machine Linux
copy the destination workers' handoffs are counted too. If the endpoint's
open-file limit cannot hold that set, the copy fails before anything at the
destination changes, with guidance to reduce selectors or `--connections`.
syq promises no particular minimum limit; the transports and the files
already open in the invoking environment count against the same limit.

Placement is always explicit:

| Placement | Mapping | Destination precondition |
|---|---|---|
| `--into DIR` | Put selected names inside `DIR` | Use or create the directory |
| `--into-new DIR` | Put selected names inside `DIR` | Must not exist |
| `--into-existing DIR` | Put selected names inside `DIR` | Must already be a directory |
| `--as PATH` | Map one named source exactly to `PATH` | Create or update the path |
| `--as-new PATH` | Map one named source exactly to `PATH` | Must not exist |
| `--as-existing PATH` | Map one named source exactly to `PATH` | Must exist |

The `new` and `existing` forms are checked during the initial look at the
destination, before anything is written. A mismatch fails before the copy
changes anything, and the selected destination directory stays held open while
workers operate on strict relative names beneath it. Conditional updates of
regular files, and the rename that puts a finished partial file in place, then
verify that the destination entry is the one that was inspected instead of
following a replaced name. This is not a snapshot of the whole directory: an
unconditional placement may still replace whatever non-directory entry is
present when it renames the finished file into place. Changed regular files
are always written to the partial file and then renamed into place.
Mapping a non-directory source exactly onto an existing directory is rejected
during the source's first scan batch, in both dry-run and execution. On the
restricted path (a remote-to-remote copy through the command-restricted
receiver, a forced command on hostB that syq installs when you enroll a
destination) the precondition is also signed into the grant, the signed,
single-use request that describes exactly what this one copy may do: the
receiver checks it against the enrolled directory when it redeems the grant,
and a `new` directory can only be created without replacing anything.

`cp` copies or updates the selected source objects and keeps unrelated
destination objects by default. With `--prune`, it then deletes
destination-only paths beneath the directories it mapped, using the same
rules as rsync mode's `--delete` (see Deleting extras below). Pruning never
removes a source and requires explicit placement; `--max-delete N` applies the
same all-or-nothing limit.

Native `rm` resolves every selector at the endpoint and opens the result,
keeping it open, before it makes its first change. A selector that names
nothing succeeds, and duplicate or overlapping selectors may perform redundant
work; they are not normalized or deduplicated. Removal then runs in a pool of
workers on the endpoint, relative to those open directory handles. An entry
already removed by another selector counts as success. Symlinks encountered
while walking inside a selected directory are removed as entries and are never
followed.

By default, native `rm` follows no symlinks while resolving `--cwd`, `--root`,
or a selector. A symlink selected by name is removed as a symlink without
touching its referent. A symlink in `--cwd`, or in a selector before the
selected name, would have to be traversed; encountering one therefore aborts
the entire command before it changes anything. `--follow-src` or the `--follow` umbrella
explicitly enables that traversal. The resolved non-symlink file or directory
is then removed while the symlinks used to reach it remain in place, usually
dangling.

`--root DIR` is mutually exclusive with `--cwd`. Without a source follow
option, the root path must contain no symlink. With `--follow-src` or
`--follow`, syq resolves the root's link target and holds it open before
resolving selectors; selectors still cannot leave it. Selector resolution
stays inside the open root and fails as soon as a relative or absolute symlink
target would leave it, even if later components would re-enter. `--cwd` is
not such a boundary when source links are followed.

For removal, `--src PATH` and bare paths accept either a selected file or
directory and remove that object, recursively for a directory. As with copy,
`--src-file PATH` requires a selected non-directory object, while
`--src-dir DIR` requires a directory and removes its entire tree.
`--srcs-in DIR` requires a directory, removes its contents, and leaves the
directory itself in place. All type checks and selector resolution finish
before deletion begins. `-vv` prints the base identity, symlink hops, and final
device/inode resolution used for the operation's audit trail.

Remote native `rm` is attached to its control connection. While work remains,
the endpoint sends a result or liveness frame at least once per second. A
detected write failure cancels queued work and stops directory scans from
scheduling more removals; operations already completed or inside a filesystem
call are not rolled back. Native `rm` has no detached mode.

Native copy fidelity defaults to `-rlt`: recurse through directories, copy
symlinks as symlinks, and keep modification times. `--preserve=permissions` additionally
copies modes, `--preserve=ownership` requests numeric owner and group, and
`--preserve=specials` copies device, FIFO, and socket nodes. The option is
repeatable and accepts comma-separated values. On macOS, socket nodes are
reported and skipped, even under `--quiet`, because macOS cannot create them
through the open destination directory handle; regular files and other
special files in the same copy continue normally. Ownership follows the same
destination-side rules as rsync mode's `-a`: owner is set only when the
process writing the destination runs as root, while group changes that fail
with `EPERM` are skipped. Hard links,
ACLs, and xattrs are not preserved.

Native `cp` and `rm` accept `--follow-src`, the `--follow` umbrella,
`-n`/`--dry-run`, `-v`/`--verbose`,
`-q`/`--quiet`, `-j`/`--connections`, `--progress`/`--no-progress`, and
`--progress-json` in addition to their endpoint and selector options. `cp`
also accepts `--follow-dst`, `--hash`, `--no-compress`, `--bwlimit RATE`,
`--stats`, repeatable `--ignore PATTERN`/`--ignore-from FILE`, `--preserve`,
and `--inplace`. Native `cp` and `rm` also accept an ephemeral SSH persistence
scope through `--pscope PATH`. Filters
use the gitignore semantics described below and apply at every source root;
`--prune` protects excluded destination paths from pruning. `--hash`
compares existing regular-file contents with full BLAKE3 digests instead of
trusting equal size and modification time; it does not add a second
post-transfer verification pass. The bandwidth limit applies only to file
data, not scanning, hashing, metadata, or pruning. A
native copy may also use `--max-size SIZE` or `--min-size SIZE` to skip regular
source files outside that inclusive range. Those files remain part of the
source population, so `--prune` protects any corresponding destination paths.
A remote-to-remote copy on the restricted path refuses `--min-size` and
refuses `--max-size` with `--prune`. The restricted receiver independently enforces the signed total-size ceiling, the signed
filters, and the signed choice between writing through partial files and
writing in place. On a direct remote-to-remote copy through that receiver,
`cp` also accepts the receiver ceilings `--receiver-max-entries N` and
`--receiver-max-bytes SIZE`, and `--receiver-receipt digests`, which asks the
receiver to record a BLAKE3 digest, taken when the transfer closes, of every
regular file whose path the transfer could have changed. They are signed into
the grant and enforced or honored by hostB, and are refused anywhere else
because nothing would act on them.
`cp` additionally accepts `--mapping` (see [Mappings](mappings.md)). Native
`cp` and `rm` can write the results stream, a machine-readable NDJSON record
of what happened: `--results FILE` creates the file fresh (an existing file is
refused: one file, one run), and `--results-fd N` writes to a file descriptor
the caller opened, e.g. `--results-fd 3 3>run.ndjson` (see
[Automation results](automation.md)). The stream is always written on the machine
where you run syq. For a remote-to-remote copy the coordinator is normally one
of the remote hosts, so the copy is refused unless you pass
`--coordinate-at local` explicitly (routing through this machine is never
chosen implicitly for the stream's sake) or the restricted receiver's verified
receipt supplies a receiver-attested stream (built from hostB's signed receipt
rather than from what hostA reported) while data flows directly between the
remotes. Both forms are rejected with `--detach`. Choose a results path
outside the copy or removal trees; one inside them can make the run's own
accounting unpredictable. A remote `rm` over a normal SSH login returns
structured outcomes from the endpoint, but the restricted receiver rejects
native removal because its signed grants authorize copy changes only.

Copy and removal continue if writing human summaries, file listings, or
diagnostics fails; the exit status still describes the filesystem operation.
If stdout fails, syq attempts one warning on stderr. A failed stderr cannot
carry that warning. A slow output consumer can still block the worker writing
to it. Progress can continue on a separate, writable stderr or results stream
while stdout is blocked.

`--mapping` cannot be combined with `--prune` because mapping manifests define
no region to prune; `--results` covers `--prune` runs, including their
removals. `--max-delete` requires `--prune`. `cp`, `rm`, and `map` all accept
`--root DIR` in place of `--cwd` to confine selectors beneath `DIR`. For `rm`,
that directory also bounds the removal itself.

Native `cp` exposes the remote runtime and transport controls
directly: `--rsh COMMAND`, `--syq-path PATH`, `--no-bootstrap`, `--no-tcp`,
`--tcp-plain`, `--tcp-ports LO-HI`, and Linux `--tcp-congestion ALGO`. An
explicit `--rsh` is the complete SSH and agent policy and bypasses the
automatic setup of the agent broker (syq's temporary local SSH agent that only
signs for the intended destination) and the restricted receiver. A port in
native endpoint syntax can be combined with the default SSH command or an
explicit command whose executable is `ssh`; an arbitrary remote-shell wrapper
must carry its own port option.
Remote `rm` accepts the same `--syq-path PATH` and `--no-bootstrap` helper
selection; those options are mutually exclusive and are rejected for a local
removal.

For two remote endpoints, `--coordinate-at auto` (the default) places the coordinator
at the source. Path operands travel base64-encoded inside the command line
sent to that host, so placing the coordinator on a remote host works for every
filename, and data is never routed through this machine implicitly.
`--coordinate-at src` explicitly selects a direct push, `--coordinate-at dst`
selects a direct pull, in which the destination host opens the SSH connection
to the source host, and `--coordinate-at local` explicitly selects a relay
through this machine. The explicit values `src`, `dst`, and `local` are
rejected for copies without two remote endpoints; `auto` is accepted
everywhere.

The default push (`--peer-auth restricted`) authenticates to the destination
through the agent broker, which signs only for that destination, and writes
through the restricted receiver. A default pull fails, because there is no
read-restricted receiver and syq never silently downgrades to a mode whose
only protection is authentication. Pull is available with an explicit
`--rsh`, `--peer-auth own-credentials` when the destination host already
holds its own credentials for the source, `--peer-auth broker`, or
`--peer-auth full-agent`. `--peer-auth` and `--detach` apply only to a direct
copy between distinct remote endpoints. The agent broker (the default and
`--peer-auth broker`) needs OpenSSH 8.9 or newer for the client on the local
machine, the client on the coordinator host, and the peer's server (the peer
is the other remote host, the one the coordinator connects to); syq checks
both clients before connecting and names the older one together with these
alternatives. A detached launch requires the coordinator to hold its own
credentials (`--peer-auth own-credentials`) or an explicit remote-shell
policy, and the coordinator host needs `/bin/kill` plus either `setsid` or
`perl` to start the new session (macOS has no `setsid`); the launcher reports
its coordinator and log only after the detached coordinator has established
the transfer route and finished checking the destination, before anything is
written. If that readiness deadline expires, the launcher
terminates and verifies the complete detached process group before reporting
failure.

If the job starts but the launcher cannot write its coordinator and log to
stdout, the launcher exits with an error and attempts to report that location
on stderr. The background job continues running.

The restricted receiver, which serves one copy and then exits, requires
encrypted TCP data connections. Consequently `--no-tcp`, falling back from TCP
to SSH, `--tcp-plain`, and `--tcp-congestion` work for a copy that does not
use the restricted receiver but are refused on it. Verification-only mode,
destination-state filters such as `--update`, and block sizing remain
available only in rsync mode.

## Persistent SSH connections

For interactive use, enable SSH connection persistence once:

```sh
syq persist on
syq persist status
syq persist off
```

While it is on, transfer and removal commands that use syq's implicit SSH
transport keep one control connection per `user@host:port` alive for five
minutes after its last session (OpenSSH `ControlMaster` with
`ControlPersist`). Later commands reuse that authenticated connection and
avoid another hardware-token interaction.

Reusing the connection alone still costs each command a new SSH session, a
helper launch, and a handshake before its first request: three network round
trips, which on a distant host is most of a second. So while persistence is
on, the first command to reach an endpoint also starts a small background
process, the session pool, that keeps one helper session ready for that
endpoint. The next command takes the ready session instead of opening its
own, so a remote completion or a small copy costs one round trip. The pool
opens its session through the existing control connection only: it checks
that the master is alive, attaches to it with every authentication method
disabled, no agent, display, or port forwarding, and no proxy of its own, and
never reads from the session it holds. If the master has gone away the pool
simply stays empty, and the next command logs in normally and shows whatever
OpenSSH has to say. The pool exits after five minutes without
handing over a session, and the control connection's own five-minute window
begins after that, so the reuse window after your last command can reach ten
minutes in total. It also exits when its scope is removed or when a newer
syq binary starts using the endpoint.

The pool keeps the environment variables it inherited from the command that
started it; later commands do not update them. If your SSH configuration uses
`SendEnv`, sessions opened by the pool send values from that original
environment, subject to the server's `AcceptEnv` settings. For example, changing
`LANG` before a later syq command does not change the value sent by the pool.
A session opened directly by that later command uses its current environment.
To start again with a changed environment, run `syq persist off`, then
`syq persist on`, and run your next command with the desired values.

`status` shows the global scope and its recorded endpoints, marking an
endpoint whose session pool is running; `off` disables the policy, stops
every session pool, asks every live syq-owned master to exit, and removes the
global runtime scope. The durable preference lives in
`$XDG_CONFIG_HOME/syq/persistence.json` (normally under `~/.config`), while
control sockets and pool sockets live in a per-user runtime directory that
only that user can read.

Scripts can avoid changing that shared preference by creating an ephemeral
persistence scope:

```sh
pscope=$(syq persist on --ephemeral) || exit
trap 'syq persist off --pscope "$pscope"' EXIT

syq cp --pscope "$pscope" first --to server --into /backup
syq cp --pscope "$pscope" second --to server --into /backup
syq persist status --pscope "$pscope"
```

`on --ephemeral` prints exactly the new ephemeral scope path. Passing that path
with `--pscope` lets separately launched or parallel commands share only that
scope, independently of the global setting. `off --pscope` closes its live
masters and removes it. If a script is killed before its cleanup trap runs,
the masters still leave after their five-minute idle limit; the inert scope
can be inspected or removed later with the printed path. Scope paths beginning
with a literal `~` or containing `${...}` are refused because OpenSSH expands
those forms before opening a control socket.

`--pscope` is deliberately not treated like the other control files. It
names a directory that syq creates with restrictive permissions and checks
before use; OpenSSH derives socket names beneath that directory. Its
protection therefore comes from that directory's ownership and permissions,
not from the open file handles syq uses for filters, mappings, file lists, and
results.

During either persistence window, anything able to act as the same local user
can open sessions through the socket without touching the key or agent, and
can take the ready helper session the pool holds. This is comparable to
sudo's credential cache; do not enable it where that window is unacceptable.
On the remote side the pool keeps one idle SSH session and one idle helper
process per endpoint for as long as the window lasts, and nothing else. Data
connections are unaffected: they remain separate TCP
streams (or independent SSH processes under `--no-tcp`), so bulk throughput
does not change. Persistence is not applied to an explicit `--rsh`, a
coordinator running on a remote host, or authentication to the restricted
receiver. A global preference is simply ignored on those paths; an explicit
`--pscope` is refused when the requested arrangement of hosts cannot honor
it. Use `--coordinate-at local` to keep a
native remote-to-remote copy's reusable connections on the invoking machine;
`syq rsync` does not accept remote-to-remote copies.

## Shell completion

`syq completion bash`, `syq completion zsh`, and `syq completion fish` print a
small adapter for the named shell. See [Installing](install.md#shell-completion)
for the startup-file lines. The adapter asks syq for each set of candidates, so
the command parser, endpoint rules, and path handling do not have to be
reimplemented in shell code.

Completion covers command and option names, fixed values such as
`--coordinate-at`, native `--from` and `--to` endpoints, local filenames, and
remote filenames. In native commands, source path options are listed at the
`--from` endpoint and placement paths at the `--to` endpoint. In `syq rsync`,
an operand such as `host:dir/fi` is listed on `host`. Files named with spaces,
newlines, or non-UTF-8 bytes remain single candidates in shells that support
those names.

Remote completion uses a normal SSH login in batch mode: it never opens a
password prompt, starts TCP data listeners, or uses the enrollment key (the
key that authenticates to a restricted receiver). This means a destination
used by a restricted remote-to-remote transfer can still be browsed when your
normal SSH key can log in to the same endpoint. An explicit `--rsh` gets no remote path completion,
because syq cannot safely infer how an arbitrary wrapper should be invoked.
Connection and listing failures simply produce no candidates; set
`SYQ_COMPLETION_DEBUG=1` to show their diagnostics.

The helper syq installs on a remote host serves one bounded, read-only
directory listing. If the matching helper is absent, the first completion may
install it through the same signed, verified bootstrap used by a transfer.
With persistence enabled, completion uses the same per-endpoint SSH control
connection as later transfers, which removes the repeated login latency. It
also takes the session pool's ready helper when one is waiting, which makes a
Tab one network round trip. Without persistence, the completion process opens
its own connection, which ends with that request.

After a successful SSH connection, syq remembers the endpoint as a future
suggestion. It also suggests literal aliases from SSH configuration,
unhashed names from `known_hosts`, and endpoints in the applicable persistence
scope. Port-specific entries are offered in native endpoint syntax only;
`host:2222` is a remote path, not a port, in rsync syntax.

The learned suggestions are a disposable local cache at
`$XDG_CACHE_HOME/syq/completion-endpoints.json`, normally
`~/.cache/syq/completion-endpoints.json`. It contains at most 100 recently
successful endpoint names, users, ports, and timestamps. It contains no paths,
credentials, keys, or transfer history. Manage it with:

```sh
syq completion cache list
syq completion cache forget user@host:2222
syq completion cache clear
```

Clearing the file does not affect remote data, credentials, helpers, or
persistent SSH sessions. An endpoint can still be suggested afterward when it
comes from SSH configuration, `known_hosts`, or a current persistence scope.

## Mappings

Placement can also be data instead of flags: `syq map` prints a local source
selection and optional root rename as NDJSON, and `syq cp --mapping`
executes such a manifest — a generalized `--as` covering many entries, each
with its own destination. Between the two, any tool that edits JSON can reshape
a transfer:

```bash
set -o pipefail
syq map --srcs-in photos \
  | jq -c '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C photos --to nas --into /pub
```

`syq map` is local and destination-independent. Its options are `-C` or `--root`,
`--follow-src`/`--follow`, the source-selector family, and `--as PATH` for
placing the single selected top-level object at `PATH`. Copy destinations,
filtering, transfer policy, execution
controls, results, receiver ceilings, and receipts belong to the downstream `cp`
invocation or the manifest transform.

Conflicting destinations are refused before any byte moves. See
[Mappings](mappings.md) for the format, more one-line transforms, and
limits.

## Rsync compatibility

Rsync mode, `syq rsync`, accepts a deliberately narrow set of rsync's options
for local, push, and pull copies:

```
syq rsync [OPTIONS] SRC... DEST
syq rsync [OPTIONS] [USER@]HOST:SRC... DEST
syq rsync [OPTIONS] SRC... [USER@]HOST:DEST
```

```sh
syq rsync -av project/ server:backup/project/       # push
syq rsync -av server:data/ ./data/                  # pull
syq rsync -a /mnt/nfs/tree /local/tree              # local → local
syq rsync -av --syq-connections 16 bigdir server:dest # fixed parallelism
syq rsync -a --dry-run -v src host:dst              # preview
syq rsync -a --syq-verify-only src host:dst          # compare only
```

As with rsync itself, the source and destination cannot both be remote. Use
native `syq cp` or `syq cp --prune` for remote-to-remote work. Options that are
specific to syq and remain useful in rsync mode begin with `--syq-`; their
names make clear that an rsync installation will not accept them.

### Compatibility options

| Option | Meaning |
|---|---|
| `-a`, `--archive` | Same as `-rlptgoD` |
| `-r`/`--recursive`, `-l`/`--links`, `-p`/`--perms`, `-t`/`--times`, `-g`/`--group`, `-o`/`--owner`, `-D` | Recursive; symlinks as symlinks; perms; mtimes; group; owner; devices and specials |
| `-v`/`--verbose`, `-vv` | `-v` lists files as they complete; for copies, `-vv` also explains remote helpers, candidate TCP addresses, the planned transport, and initial concurrency |
| `-q`, `--quiet` | Errors only |
| `-z`, `--compress` / `--no-compress` | Enable (the default) or disable zstd compression in syq's protocol; this is not `ssh -C` |
| `-n`, `--dry-run` | Resolve mappings and transport, estimate transfers/exclusions/deletions; change nothing |
| `--syq-connections N` | Syq extension: parallel data connections (default: auto-tuned, see [Speed](speed.md#how-many-connections)) |
| `--bwlimit RATE` | Limit aggregate file-data throughput (bare rate is KiB/s; `0` disables) |
| `-B SIZE`, `--block-size SIZE` | Transfer and hash block size (default 4M) |
| `--progress` / `--no-progress` | Progress meter (default on when stderr is a terminal) |
| `-P` | Turns on `--progress` (the `--partial` half is always on; see below) |
| `--partial` | No-op for rsync compatibility (syq always keeps partial files) |
| `--numeric-ids` | No-op for rsync compatibility (syq always uses numeric uid/gid) |
| `--syq-progress-json` | Syq extension: one JSON line per second on stderr |
| `--stats` | Summary counts at the end |
| `-c`, `--checksum` | Compare every file with BLAKE3 instead of size+mtime; repair mismatches (native spelling: `--hash`) |
| `--syq-verify-only` | Syq extension: hash every file in the run's scope on both sides and report differences; write nothing |
| `--inplace` | Write directly into destination files (no partial + rename) |
| `-e CMD`, `--rsh CMD` | Remote shell command; bypasses syq's automatic agent broker, restricted receiver, and enrollment setup and controls agent forwarding itself (default `ssh`) |
| `--rsync-path PATH` | Use this exact remote `syq` instead of the helper syq installs; despite rsync's standard spelling, PATH must name syq because the wire protocols differ |
| `--syq-no-bootstrap` | Syq extension: require `syq` on the remote `PATH`; do not install syq's helper |
| `--syq-no-tcp` | Syq extension: send data over the ssh connection instead of separate TCP sockets |
| `--syq-tcp-plain` | Syq extension: TCP data connections without encryption (trusted networks only) |
| `--syq-tcp-ports LO-HI` | Syq extension: port range the remote listens on for TCP data (default 47600-47699) |
| `--syq-tcp-congestion ALGO` | Syq extension, Linux: use `ALGO` on both ends of TCP data sockets; the host default is unchanged |
| `--syq-pscope PATH` | Syq extension: use an ephemeral SSH persistence scope created by `syq persist on --ephemeral` |
| `--syq-ignore PATTERN` | Syq extension: skip paths matching a gitignore-style pattern (repeatable; see below) |
| `--syq-ignore-from FILE` | Syq extension: read ignore patterns from a file (repeatable, stacks with `--syq-ignore`) |
| `--delete` | Remove destination paths the source doesn't have (see below); `--delete-after`/`--delete-delay` are synonyms |
| `--delete-excluded` | With `--delete`, also remove destination paths the `--syq-ignore` patterns exclude |
| `--max-delete N` | With `--delete`, delete nothing if more than N deletions are planned (exit 25); unlike rsync for positive N, the limit is atomic |
| `-u`, `--update` | Skip files that are newer on the destination |
| `--existing` | Only update files that already exist on the destination; create nothing |
| `--ignore-existing` | Only create files missing on the destination; update nothing |
| `--max-size SIZE`, `--min-size SIZE` | Don't transfer regular files larger / smaller than SIZE |
| `--files-from FILE` | Copy only the listed paths (relative to the one source directory; see below) |
| `--from0` | `--files-from` entries are NUL-separated |
| `--insecure-links` | Follow symlinks in the paths you name on this machine regardless of ownership, and walk source directories by path name, through symlinked parents; never applied to a remote endpoint, as in rsync |
| `-h`, `--human-readable` | No-op for rsync compatibility; sizes are always human-readable. Use `--help` for help |
| `-V`, `--version` | Print the version |

Like rsync, `-q` suppresses all non-error output: progress, summaries,
notices, and `-v` file listings are hidden. Copy failures are still written to
stderr and reflected in the exit status.

`--bwlimit` is one approximate limit shared by every `--syq-connections` worker, not a
per-connection limit. As in rsync, a bare rate is KiB/s, suffixes such as `K`,
`M`, `G`, and `MiB` use powers of 1024, a final `+1` or `-1` adjusts the scaled
value by one byte, and `0` means unlimited. Syq counts uncompressed file bytes;
protocol overhead is not counted, and transport compression may make the actual
network rate lower. Scanning, hashing, and metadata operations are not limited.

Remote transfers use fast zstd level-1 compression by default. Each protocol
frame is sent compressed only when that representation is smaller, so archives,
media, and encrypted data do not expand on the wire. They still cost a fast
compression attempt; use `--no-compress` when CPU is scarcer than network
bandwidth, particularly on a very fast LAN. Compression is transport-only and
does not change file contents, hashes, resume offsets, or `--bwlimit` accounting.

### Native remote-to-remote

`syq cp --from hostA ... --to hostB ...` copies directly from one remote host
to another (`syq rsync` refuses two remote operands, as rsync does). The
arrangement of hosts, the default restricted path, what is signed into the
grant and which options are refused under it, enrolling and revoking
destinations, and the alternatives are documented in
[Remote-to-remote transfers](remote-to-remote.md).

## Path semantics

Identical to rsync:

- `syq rsync -a src dest` copies the directory itself → `dest/src`. `dest` is
  created if missing.
- An existing non-directory `dest` cannot be the parent of that `dest/src`
  mapping; dry-run rejects it instead of presenting an impossible summary.
  With `--existing`, both dry-run and the real command skip the whole mapping
  as a no-op because creating `dest/src` is outside the selected scope.
- `syq rsync -a src/ dest` copies the *contents* of `src` into `dest`. `src/.` and
  `.` behave the same way.
- A single file source goes to `dest/file` if `dest` is an existing directory,
  otherwise `dest` is the new filename.
- Several sources require (or create) a directory destination. With several
  sources syq scans them all before writing anything, so two sources mapping
  onto one destination path is refused before the destination is touched —
  not even a missing destination directory is created (the transfer starts
  once the scans finish). Naming the destination file itself as one of the
  sources doesn't change that: it would be overwritten, so it's a conflict.
  The price is memory: every scanned entry is held until the scans are
  validated, roughly a few hundred bytes per entry across all sources.
- An exactly repeated source operand is scanned once. It still counts toward
  the original source count for placement, so `syq file file new-dest` creates
  the directory `new-dest` and writes `new-dest/file`.
- An explicitly supplied destination root that is a symlink to a directory is
  that directory when the link is owned by root or by the effective user of
  the process writing the destination (the link is kept, with or without a
  trailing slash). A component owned by anyone else is refused. The control
  connection opens the selected directory and keeps it open, and every worker
  receives that same open handle rather than resolving the path again.
  Renaming the destination path afterward therefore cannot redirect its
  writes. A symlink found below the destination root is treated as an entry
  at that path: it is replaced rather than followed, even when it points to a
  directory.
- Source paths that look like partial files (`.name.syq-part.<copy-id>`) are
  copied as ordinary data and produce one warning summary. Before transfer
  starts, syq rejects the unusual case where a source path maps exactly onto
  the partial file this copy would use for another file.
- `host:path` is relative to the remote home; `host:/abs` and `host:~/x` work.
  A colon before the first slash means remote; `./x:y` is local. All sources
  must be on the same host. `host::module` (daemon syntax) is not supported.

### Previewing a copy

`-n` / `--dry-run` connects to the endpoints and scans both sides, but creates,
updates, and deletes nothing. Its concise summary, printed before anything
would be written, makes path placement, intended changes, logical work, and
the selected data route explicit before a real copy:

```text
syq: dry-run summary
  mapping: ./dataset/ -> gpu01:/scratch/run42 (directory contents)
  changes: 82,411 regular files; 96 directories; 14 symlinks; 3 metadata-only entries; 2 type replacements among them
  deletions: 7 entries planned after a successful copy
  logical data: 1.70 TiB in 82,411 files needing content work (upper bound); 340 GiB in 18,204 files with unchanged content
  capacity: 1.70 TiB logical data required; 2.30 TiB available; 82,522 destination objects; 14,200,000 inodes available (appears sufficient)
  exclusions: 3 paths/subtrees skipped by ignore rules; 12 other entries
  route: encrypted TCP to gpu01; 16 initial connections (auto-tuned)
```

Each source gets its own `mapping` line. The annotation distinguishes directory
contents, a directory copied as a child, a file placed inside a directory, and
an exact destination path. `--files-from` is identified as a selected-path
mapping. A destination-root symlink is shown as the effective directory it
resolves to. By default, syq follows a symlink in this path you named only
when the link is owned by root or by the effective user of the process writing
the destination, matching rsync. The rule is the same whoever runs that
process; running it as root makes links owned by an unprivileged user fail it. The `changes` line separately
accounts for regular files, directories, symlinks, special files, and metadata-only updates; type
replacements are called out as an overlapping subset. This is an assessment
made at preview time, not a frozen list of changes that can later be executed
unchanged. When a destination entry will be replaced by a directory, its
descendants are assessed against that new directory rather than through the
old entry (including an old symlink).

The logical-data upper bound is the full size of regular files that fail the
planning-time metadata check. Resume state, block reuse, reflinks, compression,
server-side copying, or a content comparison can make the real I/O or wire-byte
count smaller.

When the effective destination is missing or is an existing empty directory,
Syq also has a useful simple capacity check: no replaced destination file can
free space, and newly created descendants cannot already cross filesystem
boundaries. After scanning the selected source entries, syq rechecks the same
destination filesystem and refuses a real copy if their logical file sizes
exceed the space available to the user writing the destination, or if their
object count exceeds an available inode count reported by the filesystem. The
dry-run `capacity` line shows the same assessment. The line is omitted for a
nonempty destination, a destination or filesystem that cannot report the
figures, or a changed filesystem; those cases still fail when an allocation
runs out of space, because updates, mounts, and replacement order make a
simple whole-copy estimate misleading. An
insufficient dry run exits unsuccessfully while still printing its plan and
capacity line. This is a sanity check rather than a reservation, and it imposes
no separate free-space reserve: another process can still consume or release
space after it runs.

An ignored directory is skipped without scanning its descendants,
so the exclusions line counts that directory as one `path/subtree`; it does not
invent a descendant count. Other exclusions cover state and size options and
unsupported entry types. With `--delete`, the destination is walked and the
exact deletion count is shown; scan errors and `--max-delete` guards are shown
as skipped or blocked rather than as a misleading zero.

Add `-v` for a typed explanation of each intended change, for example `create
file PATH (destination missing)`, `replace with symlink PATH -> TARGET
(destination is regular file)`, `update metadata PATH (requested file metadata
differs)`, or `delete PATH (destination only)`. The default stays compact for
large trees.

### What `-a` does here

`-rlptgoD`: recurse, symlinks as symlinks (targets copied verbatim,
dangling links included), permissions, mtimes, group, owner, and device /
fifo / socket nodes via `mknod`. Owner is only set when the *destination* side
runs as root; group is attempted for everyone and silently skipped on
`EPERM`, as rsync does. Without `-p`, new files get the source mode masked
by the local umask and existing files keep their mode. Without `-t`, every
file is transferred every time (the quick check needs mtimes).

Directory mtimes are set last, deepest first, so writing children doesn't
disturb them. A directory syq must write into but can't (no owner write bit)
is opened up for the duration and gets its own mode back at the end — or the
source's mode with `-p`.

## How it works

One control connection per endpoint does the scan (a parallel walk on each
side, streamed in batches), the diff, directory creation and metadata.
Workers receive no file work until syq has checked that no file's
destination path collides with another file's partial file. For a fresh remote
destination with a selected TCP route, they begin connecting as soon as a
source batch proves that file work exists, overlapping authentication with
those partial-file checks and directory creation; an empty tree opens no
worker connection.
The data connections — by default separate TCP sockets carrying AES-256-GCM
records — carry only "read range" / "write range" requests. When data uses SSH
(through `--syq-no-tcp` or TCP fallback), a transfer consisting entirely of fresh
small files opens worker sessions over the already-authenticated OpenSSH control
connection; larger or mixed workloads keep separate `ssh` processes, TCP
flows, and cipher processes. A custom `-e` command keeps its own SSH
multiplexing policy. Files go onto a largest-first queue; when a worker runs dry
it steals the back half of the remaining range of whichever file has the most
left, so the tail of a transfer stays parallel without pre-deciding chunk
counts.

On the destination side a file that needs content changes is written beside
its final path as the partial file `.name.syq-part.<copy-id>`, written with
`pwrite` from several workers, given its metadata, and `rename`d over the
final path. Eligible local filesystems preallocate fresh partial files with
`fallocate`; on NFS, partial files grow from the data writes themselves so
allocation and initial-size requests do not add metadata-server round trips.
Newly created partial files are mode `0600`; final metadata is applied just
before the rename into place. On Linux, local filesystems fall back to setting
the file's length only when `fallocate` is unsupported; actual space and quota
failures remain errors and abort the whole transfer instead of letting later
files keep filling the filesystem. When an existing final file is the basis
for comparison, the destination side keeps that file open while its blocks are
hashed. If every block matches, metadata is applied through that open file
without creating or renaming a partial file; otherwise that same open file
seeds the partial file.
The copy ID, the identity of one logical copy, is a 128-bit digest of the
normalized source/destination mapping and content-affecting options, and is
stable when the same logical command is rerun. It includes trailing-slash mapping, order-sensitive filters, metadata
semantics and block size, but not operational controls such as checksum
checking, connection count, verbosity, progress or bandwidth limiting.
Filesystem component limits are queried once per observed filesystem and reused
by missing descendants; long basenames are deterministically truncated and
disambiguated to fit. An exceptionally long full path still fails that one file
with a clear error (even when it is already up to date) while the rest of the
transfer continues. The same is true when a destination entry (say, a
directory some other tool left) already occupies the exact path this copy's
partial file for that file needs. Syq does not `fsync` transfer data; renaming
a complete partial file into place means a reader sees either the old file or
the new one, and interrupted work can be resumed, but it is not durability
across power loss.
Small files still use a pipelined whole-file request, but the destination side
writes each request through its partial file and renames it before
acknowledging success. Thus every non-`--inplace` content change appears
atomically complete, while an existing file that syq compares block by block
and finds content-identical keeps its inode and any destination hardlinks. The
kernel copy used when source and destination are on the same host may replace
a byte-identical destination that failed the quick check, because it
deliberately avoids that comparison.
`--inplace` writes every file directly (for example, to update a large file
without room for a second copy); eligible new small files keep the same
pipelined batching without creating partial files. Readers can observe partially
updated contents and an interruption leaves the final file unfinished.

Local → local runs the same machinery in-process with N threads, which helps
on NFS and NVMe.

### Resume

With the default of writing to a partial file and renaming it into place,
Ctrl-C is safe: kill it and rerun the same command. `--inplace` deliberately gives up that guarantee. Resume works at two
levels.

**Within a file.** There is no per-file state file; the partial file *is* the
state:

- Files whose size and mtime already match are skipped (the rsync quick check).
- If this copy's partial file `.name.syq-part.<copy-id>` exists, both sides
  hash it and the source with full BLAKE3 digests in `--block-size` blocks and
  only the mismatching blocks are sent. A leftover is reused only when it can
  be safely opened as a singly-linked regular file without following a symlink; numeric ownership is
  deliberately not required because NFS root squashing and some FUSE/CIFS
  mounts remap it. A safe leftover that cannot be made mode `0600` is discarded
  and recreated instead of permanently blocking that file. Anything else is
  safely replaced or reported as an error.
  On NFS, reuse requires the destination side to reread the partial file; syq
  deliberately keeps no separate record of which blocks are complete.
  Pipelined small files are rewritten wholesale on retry instead of paying an
  extra partial-file probe.
- If the destination file exists but differs, its blocks are hashed against
  the source too; if all match only metadata is fixed, otherwise the matching
  blocks are copied locally into a new partial and the rest transferred.

This block-level skip catches appends and in-place modifications (VM images,
databases, logs). It does **not** catch a byte inserted near the start of a
file, which rsync's rolling checksum would — for syq's intended use (fresh
uploads and downloads) that trade was made deliberately.

The copy ID includes `--block-size` and the ordered ignore rules, so changing
either starts a separate set of partial files. Old partial files are not
cleaned up automatically and may be deleted manually when the earlier command
will not be resumed. Options that do not change the copy itself, such as
`-c`, `--bwlimit`, and `--syq-connections`, do not change the copy ID.

The directory containing a partial file is a trust boundary, as with rsync's
partial directories. It must not be writable by untrusted users, especially
when syq runs with elevated privileges. A reused partial file may have a
numeric owner remapped by the filesystem; checking its mode and link count
cannot prove who originally created a predictable pathname in a shared
writable directory.

**Across the whole copy.** Copies keep no transfer history. Their source and
destination scans skip files already complete, and deleting or changing a
destination file affects the next run just as it does with rsync.

Like rsync, separate syq runs do not coordinate with each other. Different
logical commands use different partial-file names, so concurrent copies into
one tree produce the union of their files and one whole-file rename wins for
any path both write. But do not combine concurrent copies with `--delete`,
which mirrors *its* source and removes the other command's not-yet-shared
files and partial files as extras. A content-identical comparison applies
metadata only through the inode it verified, so it cannot mix its metadata
with another copy's newly renamed contents. Quick-check metadata repair likewise verifies the inode;
if a concurrent rename put a new file in its place, the repair reports an
error instead of mixing metadata with the new contents.
Starting the same logical command twice at once is
unsupported: both invocations intentionally address the same partial files.
After a crash, abandoned partial files may be deleted manually if that command
will not be resumed.

These guarantees cover other syq copies, which put complete files in place by
rename.
They do not cover another process modifying an existing destination inode in
place while syq is hashing or reusing it. As with rsync, such an external
writer can invalidate a comparison after it was made; do not independently
modify destination files during a transfer.

### Verification and consistency

Always:

- Every transferred block carries a full BLAKE3 digest computed by the reader
  and checked by the destination side; a mismatch aborts that file with an
  error (exit 23) rather than silently continuing. It indicates transport
  corruption, which is rare.
- After a file completes, the source is re-stat'ed. If its size or mtime
  changed during the transfer the file is redone (up to three attempts), then
  reported as an error.
- Unless `--inplace` was explicit, destination content changes appear
  atomically via rename, including new small files.
- Non-zero exit if anything failed.

On request:

- `--syq-verify-only` hashes every file on both sides with BLAKE3 in parallel and
  reports `DIFFERS` / `MISSING`.
- `-c`/`--checksum` (`--hash` in the native commands) does the BLAKE3 block
  comparison for every file, not just ones that fail the quick check, and
  repairs what differs.

Content decisions use full BLAKE3 digests so that a digest match is
collision-resistant rather than merely a fast corruption check. In one
release-mode, single-thread CPU microbenchmark with 4 MiB inputs
on an AMD EPYC 9454P, BLAKE3 processed 6.69 GB/s, compared with 31.25 GB/s for
XXH3 and 1.86 GB/s for SHA-256. This is design-rationale data, not an end-to-end
copy-speed claim; filesystem and transport work usually dominate, and syq
hashes concurrently across workers.

Not verified: directory and symlink metadata are set but not read back; a
source that changes *between* the final re-stat and the next block of another
file isn't noticed (same as rsync). Two chunks of one file are read at
different moments, so a file being written while copied may come out mixed —
the re-stat catches the common case, `--syq-verify-only` afterwards catches the
rest.

Compared with rsync: content-changing writes use the same temporary-file
plus atomic rename model; `--inplace` explicitly gives that up.
Rsync chooses a random temporary suffix, while syq uses a deterministic copy ID
so an interrupted command can find its partial again without a local state
file. The change-during-transfer check is the same idea; `--delete` runs
strictly after the transfer (see below); hardlinks aren't implemented.

## Ignoring paths

syq has one filter mechanism instead of rsync's include/exclude/filter rules:
native copy calls it `--ignore`/`--ignore-from`, while rsync mode uses the
explicitly extended `--syq-ignore`/`--syq-ignore-from` spellings. Each pattern
is a line of a virtual `.gitignore` placed at every source root, and each
pattern file is spliced into that sequence. Rules are applied in command-line
order with gitignore semantics (last match wins, `!` re-includes):

```sh
syq rsync -a --syq-ignore node_modules --syq-ignore .git src/ host:dst/
syq rsync -a --syq-ignore '*.o' --syq-ignore /build src/ host:dst/
syq rsync -a --syq-ignore 'logs/*' --syq-ignore '!logs/keep/' src/ dst/
syq rsync -a --syq-ignore-from .gitignore --syq-ignore '!dist/' repo/ host:repo/
syq rsync -a --syq-ignore '*' --syq-ignore '!*/' --syq-ignore '!*.jpg' photos/ bak/
syq cp --ignore-from .gitignore --srcs-in repo --to host --into repo
syq cp --prune --ignore cache/ --srcs-in build --into-existing deploy
```

Rules of thumb (they're git's): `foo` matches a file or directory named `foo`
at any depth; `/foo` only at the source root; `foo/` only a directory; `*`
doesn't cross `/`, `**` does. An ignored directory is skipped, so nothing
inside it is transferred or even scanned, which is why "only `*.jpg`" needs
the `!*/` line to keep descending. Empty directories are copied like any other
(this is a filter on the walk, not git's notion of what's tracked). The source
root itself is never ignored; with several sources each is filtered from its
own root. `-n` previews the selected scope and intended changes. The same rules
are available on native `cp`, with or without `--prune`. Neither native `rm`
takes filters: removal always selects the whole explicit tree.

As in git, a `!` rule cannot re-include something whose parent directory is
ignored: `logs/**` ignores `logs/keep` itself, so `!logs/keep/**` after it has
nothing to act on. Ignore the siblings instead (`logs/*`, which does not cross
`/`) and re-include the directory (`!logs/keep/`), as above.

## Deleting extras (`--delete`)

`syq rsync -a --delete src/ host:dst/` makes `dst` look like `src`: after the
transfer, anything under a destination directory that the source doesn't
have is removed. The rules are simpler than rsync's, deliberately:

- **Scope.** Only inside directories the sources map onto: `syq rsync --delete a b
  dst/` cleans `dst/a` and `dst/b`, never `dst/c`. A single-file source deletes
  nothing.
- **Ignored means out of scope, on both sides.** The `--syq-ignore` patterns are applied
  to the destination walk from the same roots, so an ignored entry is neither
  copied nor deleted, and a directory that holds one is kept (`not deleting
  keep/: it holds ignored paths`, on stderr, not an error). Patterns are
  matched against each side's actual entry, with gitignore's one type
  distinction: `cache/` matches only directories, so it protects a destination
  directory named `cache` but not a destination *file* of that name, which is
  an ordinary extra (rsync behaves the same). Write `cache` without the slash
  to cover both. `--delete-excluded` drops that protection: ignored paths on
  the destination are extras too.
- **Anything the source has is safe.** A file skipped by `-u`, `--existing`,
  `--ignore-existing`, `--max-size` or `--min-size` — or a symlink or special
  file skipped for lack of `-l`/`-D` — still exists in the source, so its
  destination copy is left alone, as in rsync. Such files are reported under
  `files excluded` in `--stats`.
- With `--delete` the partial-file path of every mapped regular file stays in
  memory until deletions run (that set is what tells a live partial file from
  an orphan); on multi-million-file trees this is the option's main memory
  cost.
- **After, not before.** Deletions run once every file has been transferred
  and only if the whole source scan succeeded: an unreadable source directory
  would otherwise look like one whose contents vanished (`source scan reported
  errors; skipping deletions`). The destination walk is held to the same rule:
  an unreadable directory *there* looks empty and would be removed over its
  unknown contents, so its errors also skip all deletions. A run interrupted
  during scanning or transfer therefore never starts deletion. Once deletion
  has begun, interruption can leave some planned extras removed; rerunning
  finishes the mirror. Directory mtimes are set after the deletes.
- **Files named like partial files are extras unless they are this copy's
  live resume state.** A `.name.syq-part.<copy-id>` of *this* command whose
  `name` is still in the source stays, whatever happened to that file this run
  (failed, filtered, already up to date): the next transfer of that file
  consumes it. Everything else matching the pattern (an orphan of this
  command, or any other copy ID) is an ordinary extra: syq copies such names
  as ordinary data, so the name alone proves nothing, and mirroring the source
  is what --delete is for. Note that the copy ID includes the command's
  semantic options: change those (or the source/destination spelling they
  normalize to) and the previous copy ID's partial files become orphans,
  removed by `--delete` and inert otherwise.
- `--max-delete N` is an intentional positive-limit divergence. Syq plans the
  complete deletion set and, if it contains more than N entries, deletes
  nothing, reports the refusal, and exits 25. Rsync instead deletes the first N
  and then stops. `--max-delete=0` therefore has rsync's useful no-deletion
  reporting behavior; `--max-delete=-1` is accepted as its historical synonym.
  Without `--delete`, the option is accepted and has no effect, as in rsync.
- `-n --delete -v` lists every intended removal as `delete path (destination
  only)`. The dry-run summary reports the number planned; a real run reports
  the number deleted. `--delete`
  conflicts with `--syq-verify-only` (deleting is the opposite of writing
  nothing) and with `--files-from` (deletion scope under a file list is
  ambiguous).

Deletion goes through the control connection in batches of 1000 (the
destination side unlinks each batch in parallel); it is not spread over the
copy's data connections.

## Skipping by state and size

- `-u` / `--update`: a file whose destination copy has a newer mtime is left
  alone (regular files only). Neither `-u` nor `--ignore-existing` can be
  combined with `--inplace`: an interrupted in-place write leaves a
  partially-written final file that looks newer, which those filters would
  then skip on every retry.
- `--existing`: never create anything — files, symlinks, specials,
  directories, *or the destination itself* — that isn't already there;
  existing files are still updated. `--ignore-existing` is the mirror image: create what's
  missing, never touch what exists — including an existing file or symlink
  where the source maps a *directory*: it stays, and that directory with its
  whole subtree is skipped with a notice (rsync would delete the file to
  make room). Both apply to every non-directory entry.
- `--max-size` / `--min-size`: regular files outside the range are not
  transferred (`4K`, `100M`, `2G`; the same suffixes as `--block-size`).
  Directories and symlinks are unaffected.

All of these define the scope of the run, so `--syq-verify-only` checks the files
the same command would transfer and nothing else.

## Copying a list (`--files-from`)

`syq rsync -a --files-from list.txt host:src/ dst/` copies only the paths named in
`list.txt`, one per line (`--from0`: NUL-separated; `-` reads stdin), each
relative to the single source directory, to the same relative path under the
destination. The source is not walked, which is the point on a slow
filesystem when the list is known. Parent directories of listed paths are
created (with their metadata). By default, a parent that is a symlink on the
source is not traversed and that listed path fails. This is deliberately
stricter than hardened rsync 3.5.0: rsync may first emit the implied destination
directory and then fail the content open, while syq refuses the path before
emitting that implied parent. Both report a partial-transfer error (exit 23).
`--insecure-links` opts a local source into walking by path name instead of
by open handle: such a parent is followed and becomes a real directory on the
destination. A remote source keeps the default behavior, because the flag is
never sent to the remote side. A parent that resolves to a file or dangles is an error. A
listed directory is copied *without*
its contents unless `-r` is given on the command line itself — `-a` alone
does not count, as in rsync — so `-a -r --files-from` walks the directories
the list names (never the implied parents).
Blank entries and entries starting with `#` or `;` are ignored in both modes;
spell a literal comment-looking name as `./#name` or `./;name`. Leading `/` or
`./` and trailing `/` are stripped, and `..` components or an entry that names
the root itself are rejected. A listed path that doesn't exist is an error
(exit 23) and the rest is still copied. The destination must be a directory (an
existing file there is an error, never replaced). `--files-from` cannot be
combined with `--syq-ignore`/`--syq-ignore-from` or `--delete`. To also choose
each entry's destination path, use a native mapping instead (see
[Mappings](mappings.md)).

## Not implemented (on purpose, for now)

[rsync-compat.md](rsync-compat.md) tracks rsync compatibility in full: what matches, what
differs and why, and what's missing. The short version:

- rsync filter rules (`--exclude`/`--include`/`--filter`); use the
  `--syq-ignore` extension (gitignore syntax) instead.
- `--link-dest`, `--backup`.
- `--delete-before`/`--delete-during` and `--force`. syq deletes only after
  the transfer (`--delete-after`/`--delete-delay` are accepted as synonyms).
- Hardlinks (`-H`), ACLs and xattrs (`-A`/`-X`).
- rsync daemon mode / `rsync://`. syq speaks its own protocol; it cannot talk
  to an rsync server.
- Rolling-checksum delta transfer (see Resume above).
- UDP or forward-error-correcting data transport. TCP retransmission/RTT
  counters are collected for diagnosis, but a loss-tolerant transport would be
  a separate protocol and security design.
- Preserving existing partial files from `rsync --partial`; only syq's own
  `.name.syq-part.<copy-id>` partial files for the same logical command are
  recognised.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Everything copied and verified |
| 1 | Fatal: couldn't connect, remote `syq` missing, connection lost |
| 2 | Bad arguments or usage |
| 23 | Finished, but some files failed (unreadable source, `DIFFERS`, changed during transfer …) — errors are on stderr |
| 25 | Finished, but `--max-delete` stopped the deletions |
