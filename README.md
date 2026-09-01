# syq

`syq` is a parallel file copier with an explicit native command line and a
retained rsync-compatibility subcommand. It scans source and destination, works
out what differs, and moves the data over
**N independent connections at once** — encrypted TCP by default, authenticated
over ssh, falling back to ssh's own channels when a direct port can't be
reached — splitting large files into ranges
that idle workers steal from each other, so a single huge file at the end of
a transfer still uses every connection. Throughput is typically several times
that of a single ssh stream. It also has a progress meter that separates
transferred bytes from unchanged ones and automatically resumes interrupted
transfers from partial files without retransmitting their finished blocks. An
optional checkpoint can avoid repeated destination lookups for exceptionally
large or failure-prone jobs; it is not required for normal resumption. SYQ can
also verify that a copy is complete.

## Install

The standalone installer needs no `sudo` and installs the matching Linux or
macOS binary in `~/.local/bin`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

That initial shell installer necessarily needs `curl` or `wget` to obtain syq
before syq exists. The installed application and its managed remote bootstrap
do not depend on either command.

To inspect it first, download the same URL without piping it to `sh`. Every
release also has an immutable versioned installer, for example
`https://github.com/greaber/syq/releases/download/v0.1.0/install.sh`. To choose
another directory, download the script and run `sh install.sh --bin-dir DIR`
(or pipe it to `sh -s -- --bin-dir DIR`). The script detects the target,
verifies the archive's embedded SHA-256 and size, runs the temporary binary to
check its version and release identity, and then replaces `syq` atomically.
Even with `--bin-dir`, either `HOME` or `XDG_CONFIG_HOME` must be set so every
successful standalone installation can record its managed-install receipt.

Homebrew is also supported through the project-owned tap:

```sh
brew install greaber/tap/syq
```

Rust users can instead compile and install the published source package:

```sh
cargo install --locked syq
```

Or build a checkout with the pinned Rust toolchain:

```sh
cargo build --release          # binary at target/release/syq
cargo install --locked --path . # or: put it on your PATH
```

Checkout builds carry a source-revision identity. The crates.io 0.1.5 package
predates stable identities for packaged source: two independent
`cargo install --locked syq` builds receive different identities and cannot
connect as remote peers. To use a 0.1.5 Cargo installation remotely, copy the
exact installed executable to the remote and pass `--syq-path /path/to/syq`
(or put it on the remote `PATH` and use `--no-bootstrap`).

A later crate release containing packaged-source identity support will carry
the package's source revision, allowing independent locked installations of
that same version to connect. Source builds deliberately do not claim to be an
immutable release, so managed remote bootstrap remains available only in
official release binaries.

Standalone installs download and verify one signed release manifest at most
once a day after a successful interactive command. When a newer release is
available they print a reminder; updates are never installed as a side effect
of a copy. Run `syq --self-update` to install the update, or set
`SYQ_NO_UPDATE_CHECK=1` to disable automatic checks and reminders. Explicit
`syq --self-update` checks still work when that variable is set. The install
receipt lives at
`$XDG_CONFIG_HOME/syq/install.json` (normally `~/.config/syq/install.json`) and
must name the running executable, so a Homebrew or source build never replaces
itself. Self-update is deliberately limited to standalone installs because a
package manager must remain the owner of its files. Update Homebrew installs
with `brew upgrade syq`.

Release binaries are published for Linux x86-64/ARM64 and macOS Apple
Silicon/Intel. Terminal downloads and Homebrew normally do not attach macOS's
quarantine attribute, which is why command-line tools installed this way do not
usually produce Gatekeeper prompts. A binary downloaded through a browser may;
browser-oriented distribution would need Apple Developer ID signing and
notarization in addition to this terminal-first path.

The remote side runs `syq --server`, but it does not need to be installed or
configured first. An official syq uses its exact release helper under
`~/.cache/syq/helpers/`. On first use of a version it detects the remote
platform and checks for a downloader, SHA-256 implementation, and `gzip`. When
that complete toolchain is available, the remote downloads the matching
compressed binary and signed manifest from that version's GitHub release. It
relays the manifest and computed digest over SSH, then waits while the local
client verifies the manifest signature and compares its expected digest. Only
an explicit approval from the client lets the remote install the helper
atomically. This path therefore works even when the local machine cannot reach
the release host. Later runs execute that exact path without an extra probe
connection.

If the remote toolchain is unavailable, a tool fails, or the download times
out or otherwise fails, the local client downloads the target-specific archive
with its built-in rustls HTTP client instead. It verifies both the archive and
decompressed binary, caches the verified binary under
`$XDG_CACHE_HOME/syq/helpers/` (normally `~/.cache/syq/helpers/`), and uploads it
through the configured SSH command.
This fallback does not require a remote downloader, hasher, or decompressor.
Remote filesystem and installation errors fail immediately because uploading
the same helper cannot fix them. A completed download with the wrong digest is
discarded and produces an integrity warning even if the verified upload then
succeeds.

The managed cache accepts only a verified release binary. Helpers cached under
an older identity or cache layout are never executed; they may be removed with
the rest of the disposable helper cache. To opt out of managed bootstrap,
install a compatible binary yourself and pass `--syq-path /path/to/syq`, or put
it on the non-interactive remote `PATH` and use `--no-bootstrap`.

The local client verifies the manifest's embedded Ed25519 signature over its
RFC 8785 canonical JSON. Direct remote download uses `curl` or `wget`, `gzip`,
and one of `sha256sum`, `shasum`, or `openssl`; those programs are optional
because missing or unusable tools select verified SSH upload instead. Version
directories coexist and either helper cache can be removed at any time; syq
recreates the helper it needs on the next connection. After launch, both peers
require the same build identity: the release tag for official binaries, or the
Git-derived identity when an explicit source-built helper is used.

- **macOS (Apple Silicon / Intel):** build natively on the Mac with
  `cargo build --release` (needs the Xcode command-line tools, `xcode-select
  --install`, for the bundled zstd C library). The tool is otherwise pure Rust
  and uses only POSIX calls; Linux-only optimizations (`fallocate`,
  glibc `mallopt`) are compiled out automatically. copy_file_range's local
  fast path is Linux-only; on macOS same-machine copies use the normal path.
- For a manually installed binary that is portable across distributions (for
  example, a host with an older glibc), build a static binary:
  `RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-gnu`
  (the musl target also works if `musl-gcc` is installed, which `zstd-sys` needs).

## Native commands

Native syntax starts with an operation and keeps endpoints, selectors, and
target placement in separate arguments:

```sh
syq cp project --to server --into /backup       # named object → /backup/project
syq cp --src-src project --to server --into /app # project contents → /app
syq cp --from server --cwd /data --src a --src b --into ./data
syq cp report --to server --as-new /reports/final
syq cp-prune --src-src build --to server --into-existing /srv/app
syq rm cache old-output
syq rm --from server --cwd /srv --src old-output
syq rm --root /srv --src-dir cache
syq rm --cwd /srv --follow --src-dir current-release
```

`--from [USER@]HOST` selects one source endpoint and `--to [USER@]HOST`
selects one target endpoint; omission means local. A local path containing `:`
stays local because native mode never guesses endpoints from path text.
`--cwd DIR`/`-C DIR` changes where relative source selectors are resolved at
the source endpoint. Copy selectors may be absolute and then ignore `--cwd`.
Removal selectors are always relative; native `rm` rejects a leading slash and
any `.` or `..` component.

Bare paths and repeatable `--src PATH` select named objects. A named directory
keeps its basename at the target; a named symlink is copied as a symlink. A
trailing slash is ordinary path spelling and has no semantic effect.
`--src-src DIR` selects a directory's contents and merges them directly into
the target container. `--srcs PATH...` and `--src-srcs DIR...` are bulk
conveniences for those two canonical selectors. Symlinks found while traversing
a directory are copied as symlinks and are never followed. Singular selector
options consume their next argument even when it begins with `-`, so every Unix
filename is expressible without losing raw path bytes.

Placement is always explicit in this initial native surface:

| Placement | Mapping | Target precondition |
|---|---|---|
| `--into DIR` | Put selected names inside `DIR` | Use or create the directory |
| `--into-new DIR` | Put selected names inside `DIR` | Must not exist |
| `--into-existing DIR` | Put selected names inside `DIR` | Must already be a directory |
| `--as PATH` | Map one named source exactly to `PATH` | Create or update the path |
| `--as-new PATH` | Map one named source exactly to `PATH` | Must not exist |
| `--as-existing PATH` | Map one named source exactly to `PATH` | Must exist |

The `new` and `existing` forms are lightweight placement-root pathname checks
during the ordinary initial destination inspection. A mismatch fails before
transfer mutation begins. After a successful check, the current engine's
ordinary pathname and publication behavior applies: these forms do not pin an
inode or provide compare-and-swap behavior against a concurrent namespace
writer. Changed regular files continue to use staged atomic publication.
Mapping a non-directory source exactly onto an existing directory is rejected
during the source's first scan batch, in both dry-run and execution.

`cp` copies or updates mapped source objects and keeps unrelated target
objects. `cp-prune` uses the same mapping and transfer engine, then applies the
existing safe deletion planner to remove target-only descendants in mapped
directory scopes. It never removes a source and requires explicit placement;
`--max-delete N` keeps its all-or-nothing deletion budget.

Native `rm` resolves every explicit selector at the endpoint and pins the
result before it makes its first change. Missing selectors are successful and
duplicate or overlapping selectors may perform redundant work; they are not
canonicalized or deduplicated. Removal then runs in an endpoint-local worker
pool relative to the pinned directory handles. A namespace entry already
removed by another selector is successful. Symlinks encountered while walking
inside a selected directory are removed as entries and are never followed.

By default, native `rm` follows no symlinks while resolving `--cwd` or a
selector. A symlink selected by name is removed as a symlink without touching
its referent. A symlink in `--cwd`, or in a selector before the selected name,
would have to be traversed; encountering one therefore aborts the entire
command before mutation. `--follow` explicitly enables that traversal. The
resolved non-symlink file or directory is then removed while the symlinks used
to reach it remain in place, usually dangling.

`--root DIR` is mutually exclusive with `--cwd`. The root path itself must
contain no symlink, even with `--follow`. Selector resolution is confined to
the pinned root and fails as soon as a relative or absolute symlink target
would leave it, even if later components would re-enter. `--cwd` is not a
containment boundary when `--follow` is used.

For removal, `--src PATH` and bare paths accept either a terminal file or
directory and remove that object, recursively for a directory.
`--src-file PATH` requires a non-directory terminal object, while
`--src-dir DIR` requires a directory and removes its entire tree.
`--src-src DIR` requires a directory, removes its contents, and retains the
resolved directory itself. All type checks and selector resolution finish
before deletion begins. `-vv` prints the base identity, symlink hops, and final
device/inode resolution used for the operation's audit trail.

Remote native `rm` is attached to its control connection. While work remains,
the endpoint sends a result or liveness frame at least once per second. A
detected write failure cancels queued work and stops directory scans from
scheduling more removals; operations already completed or inside a filesystem
call are not rolled back. Native `rm` has no detached mode.

The first native fidelity default is exactly `-rlt`: it recurses through
directories, copies symlinks as symlinks, and retains mtimes. Owner, group,
modes, special files,
hard links, ACLs, xattrs, filtering, comparison policy, and the automation API
are intentionally not frozen by this first grammar. Use `syq rsync` when the
current compatibility options for those capabilities are needed.

The native commands accept only `-n`/`--dry-run`, `-v`/`--verbose`,
`-q`/`--quiet`, and `-j`/`--connections` in addition to the endpoint,
selector, cwd, and placement options above. `cp-prune` additionally accepts
`--max-delete`; `rm` additionally accepts `--root` and `--follow` plus its
typed selectors. Preservation policies, filters, comparison controls, progress
interfaces, and SSH/transport configuration remain available only through
`syq rsync`; sharing the transfer engine does not expose those options in
native mode. Remote-to-remote copies still use the ordinary automatic
transport. Native raw path bytes are relayed through syq's protocol when they
cannot be represented in a direct remote shell command.

## Mappings

Placement can also be data instead of flags: `syq map` prints the resolved
selection and placement of a command as JSON lines, and `syq cp --mapping`
executes such a manifest — a generalized `--as` covering many entries, each
with its own destination. Between the two, any tool that edits JSON can
reshape a transfer:

```sh
syq map --src-src photos \
  | jq '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C photos --to nas --into /pub
```

Conflicting destinations are refused before any byte moves. See
[MAPPINGS.md](MAPPINGS.md) for the format, more one-line transforms, and
limits.

## Rsync compatibility

The complete previous command surface remains available under `syq rsync`:

```
syq rsync [OPTIONS] SRC... DEST
syq rsync [OPTIONS] [USER@]HOST:SRC... DEST
syq rsync [OPTIONS] SRC... [USER@]HOST:DEST
```

```sh
syq rsync -av project/ server:backup/project/       # push
syq rsync -av server:data/ ./data/                  # pull
syq rsync -a /mnt/nfs/tree /local/tree              # local → local
syq rsync -a hostA:big/ hostB:big/                  # direct remote → remote
syq rsync -a --relay hostA:big/ hostB:big/          # relay when A cannot reach B
syq rsync -av -j 16 bigdir server:dest              # fixed parallelism
syq rsync -a --dry-run -v src host:dst              # preview
syq rsync -a --verify-only src host:dst             # compare only
```

The sections below document this retained compatibility surface unless they
explicitly say otherwise.

### Compatibility options

| Option | Meaning |
|---|---|
| `-a`, `--archive` | Same as `-rlptgoD` |
| `-r` `-l` `-p` `-t` `-g` `-o` `-D` | Recursive; symlinks as symlinks; perms; mtimes; group; owner; devices and specials |
| `-v`, `-vv` | `-v` lists files as they complete; for copies, `-vv` also explains remote helpers, candidate TCP addresses, the planned transport, and initial concurrency |
| `-q` | Errors only |
| `-z`, `--compress` / `--no-compress` | Enable (the default) or disable zstd compression in syq's protocol; this is not `ssh -C` |
| `-n`, `--dry-run` | Resolve mappings and transport, estimate transfers/exclusions/deletions; change nothing |
| `-j N`, `--connections N` | Parallel data connections (default: auto-tuned, see below) |
| `--bwlimit RATE` | Limit aggregate file-data throughput (bare rate is KiB/s; `0` disables) |
| `--block-size SIZE` | Transfer and hash block size (default 4M) |
| `--min-split SIZE` | Don't split an in-flight file with less than this left (default 32M) |
| `--progress` / `--no-progress` | Progress meter (default on when stderr is a terminal) |
| `-P` | Turns on `--progress` (the `--partial` half is always on; see below) |
| `--partial` | No-op for rsync compatibility (syq always keeps partial files) |
| `--numeric-ids` | No-op for rsync compatibility (syq always uses numeric uid/gid) |
| `--insecure-links` | Allow a receiving process to follow destination-path symlinks owned by other users (unsafe legacy opt-out) |
| `--progress-json` | One JSON line per second on stderr |
| `--stats` | Summary counts at the end |
| `-c`, `--checksum` | Compare every file block by block instead of size+mtime; repair mismatches |
| `--verify-only` | Hash every file in the run's scope on both sides and report differences; write nothing |
| `--inplace` | Write directly into destination files (no partial + rename) |
| `--checkpoint FILE` | Avoid completed-file destination lookups on later runs; normal resume does not need it |
| `-e CMD`, `--rsh CMD` | Remote shell command; bypasses automatic broker, receiver, and enrollment setup and controls agent forwarding itself (default `ssh`) |
| `--syq-path PATH` | Use this exact remote `syq` instead of the managed helper |
| `--no-bootstrap` | Require `syq` on the remote `PATH`; do not install a managed helper |
| `--no-tcp` | Send data over the ssh connection instead of separate TCP sockets |
| `--tcp-plain` | TCP data connections without encryption (trusted networks only) |
| `--tcp-ports LO-HI` | Port range the remote listens on for TCP data (default 47600-47699) |
| `--tcp-congestion ALGO` | Linux: use `ALGO` on both ends of direct TCP data sockets; the host default is unchanged |
| `--ignore PATTERN` | Skip paths matching a gitignore-style pattern (repeatable; see below) |
| `--ignore-from FILE` | Read ignore patterns from a file (repeatable, stacks with `--ignore`) |
| `--delete` | Remove destination paths the source doesn't have (see below); `--delete-after`/`--delete-delay` are synonyms |
| `--delete-excluded` | With `--delete`, also remove destination paths the `--ignore` patterns exclude |
| `--max-delete N` | With `--delete`, delete nothing if more than N deletions are planned (exit 25) |
| `-u`, `--update` | Skip files that are newer on the destination |
| `--existing` | Only update files that already exist on the destination; create nothing |
| `--ignore-existing` | Only create files missing on the destination; update nothing |
| `--max-size SIZE`, `--min-size SIZE` | Don't transfer regular files larger / smaller than SIZE |
| `--files-from FILE` | Copy only the listed paths (relative to the one source directory; see below) |
| `--from0` | `--files-from` entries are NUL-separated |
| `--rm` | Remove the given paths recursively and in parallel (see below) |
| `--relay` | Remote-to-remote: route data through this machine instead of running on the source host |
| `--no-forward-agent` | Remote-to-remote with default `ssh`: give hostA no agent; it must have credentials for hostB (conflicts with `-e`) |
| `--agent-broker-only` | Remote-to-remote: use destination-bound authentication without installing or using the command-restricted receiver |
| `--unrestricted-agent-forwarding` | Remote-to-remote compatibility escape hatch: expose the complete local agent to hostA instead of the constrained broker |
| `--detach` | Remote-to-remote: run the transfer detached on the source host so it survives losing this ssh session; prints the follow target even with `-q` |
| `--follow HOST:LOG` | Attach to a detached transfer's log and stream its progress |
| `-h` | No-op for rsync compatibility; sizes are always human-readable. Use `--help` for help |

Like rsync, `-q` suppresses ordinary non-error output: progress, summaries,
notices, and `-v` file listings are hidden. The warning that
`--unrestricted-agent-forwarding` exposes the complete ambient agent is never
hidden by `-q`. Copy failures are still written to stderr and reflected in the
exit status.

`--bwlimit` is one approximate limit shared by every `-j` worker, not a
per-connection limit. As in rsync, a bare rate is KiB/s, suffixes such as `K`,
`M`, `G`, and `MiB` use powers of 1024, a final `+1` or `-1` adjusts the scaled
value by one byte, and `0` means unlimited. SYQ counts uncompressed file bytes;
protocol overhead is not counted, and transport compression may make the actual
network rate lower. Scanning, hashing, and metadata operations are not limited.

Remote transfers use fast zstd level-1 compression by default. Each protocol
frame is sent compressed only when that representation is smaller, so archives,
media, and encrypted data do not expand on the wire. They still cost a fast
compression attempt; use `--no-compress` when CPU is scarcer than network
bandwidth, particularly on a very fast LAN. Compression is transport-only and
does not change file contents, hashes, resume offsets, or `--bwlimit` accounting.

### Remote-to-remote

`syq rsync hostA:src hostB:dst` starts the orchestrator *on hostA*, which then pushes
to hostB with N connections, so data flows A → B directly. Matching helpers
are installed automatically on both hosts. Progress and `-v` output are
streamed back. If hostA can't reach hostB, `--relay` keeps the orchestrator
here and routes every byte A → you → B — always works, at half the bandwidth.
`syq rsync hostA:src hostA:dst` (same host and user on both ends) simply runs a
local copy on hostA and disables agent forwarding.

With implicit OpenSSH, the default combines a pre-enrolled forced receiver on
hostB with a temporary local agent broker. The first transfer to a destination
parent generates an Ed25519 enrollment key locally, uploads the exact running
syq as `~/.local/libexec/syq-receiver` on hostB, and appends one managed
`restrict,command=...` line to hostB's `authorized_keys`. The private enrollment
key stays under `~/.local/state/syq/restricted/` on the local machine and is
never copied to hostA. HostB keeps only its forced public key, SSHSIG verifier
policy, and replay state under `~/.local/share/syq/restricted/`. Before
publishing the forced key, syq verifies that the installed receiver is a
regular executable and that it and every path ancestor are trusted-owner- or
root-owned, non-writable by other users, and free of non-owner ACL grants.

Enrollment first tries local→hostB directly. If that network path is
unavailable, it retries through hostA with OpenSSH `ProxyJump`; hostA gets only
`ssh -W` byte forwarding and cannot see the encrypted hostB session, an agent
socket, or the enrollment key. The destination parent must already exist.
Enrollment is durable, is reused for later destination leaves sharing that
parent, and is reported as an intentional remote state change. The local
OpenSSH client has ordinary command authority on hostB during this initial
installation, whether the connection is direct or tunneled through hostA. That
one setup session is the bootstrap trust boundary; later transfers use only the
forced key. Syq generates the special key automatically, and its
`syq-enrollment:ID` marker makes the managed `authorized_keys` line
recognizable to users, administrators, and monitoring tools.

For each transfer, the local machine signs a typed request naming the exact
destination, login, copy semantics, hash block size, TCP port range, limits,
validity interval, and a fresh one-time nonce. The temporary broker advertises
only that enrollment key to hostA and releases its signature only after
validating this path:

```text
trusted hostA session -> configured-user@trusted-hostB session
```

The broker verifies OpenSSH session-bind signatures for both hosts and strictly checks
the final host-bound authentication request's session ID, destination login
user, host key, selected credential, and signature algorithm. Key addition,
removal, raw or legacy signing, unknown extensions, and extra forwarding hops
are refused. The A → B client is forced to use host-bound public-key
authentication. The forced receiver verifies and durably claims the signed
request before starting syq's protocol. Every destination scan, stat, hash,
sidecar operation, metadata change, write, and deletion is rewritten onto the
enrolled root descriptor. Descendant symlinks are payload, never traversal.
HostA cannot replace that guard, widen the destination, add an unsigned
preservation option, exceed signed entry/byte/deletion/connection limits, or
replay the request. Source-permission preservation and ordinary non-`-p`
creation/restoration use distinct protocol flags and signed policy. For
non-`-p` requests, existing objects retain the mode observed on hostB; new
objects accept only ordinary permission bits masked by hostB's umask. HostA
cannot supply special bits or turn this path into chmod authority over existing
objects. A new directory does retain a setgid bit inherited from its destination
parent by hostB's kernel; that bit is read from the newly created inode and is
not accepted from HostA's mode proposal. Preserved modes are bound to the
receiver-observed inode fingerprint; atomic publication fails if that object
changes instead of carrying its mode onto a replacement. Hash requests must use
the signed block size, and the receiver rejects any request whose hash vector
could exceed the protocol frame
limit.
Encrypted token-authenticated TCP workers inherit the same authority. The
receiver permits one encrypted listener in the signed port range and closes it
when the forced control session ends or the grant expires; after redemption
there is no second SSH authentication or silent SSH fallback.

This preferred path gives hostA neither a credential nor an ambient-agent
capability. The local ambient agent—including a YubiKey—is used for the
local→hostA login and ordinary enrollment SSH sessions, but hostA never gets
access to it.

The restriction protects hostB; it does not make hostA a trustworthy source.
A compromised hostA can omit source files, alter their contents, lie about
source metadata, or stop the transfer. It still cannot escape the signed
destination scopes or independently authenticate to hostB with the enrollment
key.

The command-restricted path requires atomic staged publication and encrypted
TCP data connections. `--inplace`, `--no-tcp`, `--tcp-plain`,
`--tcp-congestion`, `--update`, `--existing`, `--ignore-existing`, native
`--*-new`/`--*-existing`,
`--ignore`/`--ignore-from`, `--files-from`, `--min-size`, a nonzero
`--bwlimit`, `--syq-path`, and `--no-bootstrap` currently fail closed because
the receiver cannot enforce those semantics independently of hostA.
`--max-size` is enforced as a signed per-file limit, but is refused together
with deletion because filtered source files could otherwise make hostA's
deletion plan ambiguous. Explicit `-j` values above 64 are also refused; auto
tuning may use up to that signed ceiling.

`--dry-run` and `--verify-only` are cryptographically read-only: the signed
grant marks them as such and the receiver rejects every mutation even if hostA
sends one. They use an existing enrollment but do not install one; run
`syq enroll` first when previewing or verifying a new destination.
Destination-root symlinks are also refused in this mode; enroll the explicit
referent so the signed pathname and opened root identify the same object.

One conservative rsync-shaped edge fails safely: for a named recursive source
such as `hostA:dir` and a destination path whose existence changes rsync's
placement meaning, the grant authorizes the existing-directory interpretation.
If that destination does not exist, creation of children at the alternate
exact-path interpretation is denied. Use a trailing slash (`hostA:dir/`), the
native `--as`/`--into` placement spelling, or create the destination directory
first when that distinction matters.

Use `syq enroll [USER@]HOST:DEST [--via [USER@]HOST]` to pre-enroll,
`syq enrollments` to list local enrollments, and `syq revoke ID [--via ...]` to
remove the forced key and both sides' per-enrollment state. Before changing
hostB, syq durably records a pending enrollment and its private key locally. If
the installation response is lost, the next enrollment of the same endpoint
and destination retries the same ID safely; `syq enrollments` labels that state
`pending`, and `syq revoke` can remove either pending or active state. Running
`syq enroll` again for an active destination also refreshes the installed
receiver to the exact local syq binary. Revocation leaves that shared binary
because other enrollments may use it. It prevents new receiver sessions. A
session that already claimed its signed request can finish an operation already
in progress; later protocol requests are rejected once the signed execution
deadline expires rather than forcibly interrupting a filesystem syscall.

`--agent-broker-only` explicitly selects the authentication-only compromise.
It installs no receiver. HostA may list a sanitized snapshot of the ambient
agent's supported public identities with comments removed, but the broker signs
only for the exact hostA→user@hostB path above. Key changes, raw or legacy
signing, unknown extensions, and extra hops are refused; successful ambient
signatures are verified before release.

In broker-only mode, use OpenSSH 10.5 or newer for the ambient agent if relying
on its existing per-key destination constraints as an additional layer.
OpenSSH 10.5 fixed an
interaction in which a locked agent refused session-bind requests, allowing
operations intended to be local—including use of destination-restricted
keys—to occur remotely ([OpenSSH 10.5 release notes](https://www.openssh.com/txt/release-10.5);
CVE-2026-73281). Syq cannot query an agent's version and does not count that
extra layer as part of its own mandatory path restriction.

In broker-only mode, private keys remain in the original agent, so
hardware-backed, PIV/OpenPGP-agent, and desktop-agent identities continue to handle their own
touch/PIN/approval behavior. For a user certificate selected by hostB's local
`CertificateFile`, syq exposes only that exact certificate in place of its
matching raw agent identity, validates the exact certificate-bearing host-bound
request, and translates only the agent request's outer credential back to the
matching raw key. This supports the common arrangement where a YubiKey or other
agent lists the private key while a centrally managed certificate is a local
file. When no `CertificateFile` is explicitly configured, syq also follows
OpenSSH's implicit `<IdentityFile>-cert.pub` convention. An OpenSSH agent may
itself reject certificate translation when the raw key has
`ssh-add -h` destination constraints but the certificate was not associated
with the agent; that combination fails closed. Loading the certificate into the
agent avoids translation. The broker socket and every open channel are closed
when the attached transfer ends; SIGINT and SIGTERM also remove its private
socket directory. Stalled broker and ambient-agent operations
time out after two minutes, long enough for ordinary hardware-token approval
while preventing idle clients from holding worker slots indefinitely.

Broker-only mode restricts *where and as whom* hostA may authenticate; stock
OpenSSH does not bind the subsequent command. A compromised hostA still receives the
authority of that destination account for the transfer's lifetime. Command or
filesystem restrictions require destination-side policy such as a forced syq
receiver. This is not a signed grant: it adds no timestamp, expiry, or replay
cache beyond the live SSH sessions and the broker socket's lifetime.

The constrained path requires OpenSSH 8.9 or newer session-bind and host-bound
authentication support on the local machine, hostA, and hostB; a local
`SSH_AUTH_SOCK`; and exact plain host keys for both hosts in the effective local
`known_hosts` files. Host-certificate/CA-only trust is refused until syq can
validate certificate principals and validity as strictly as OpenSSH. Static
`HostKeyAlgorithms` and `RequiredRSASize` policy is enforced. A configured
`KnownHostsCommand` or `RevokedHostKeys` KRL is refused because the broker does
not yet reproduce those dynamic or external revocation checks. Local
`CertificateFile` and implicit `IdentityFile` certificate expansion supports the
ordinary OpenSSH percent tokens except `%C`; named-user tildes are also refused
rather than guessed. Credential and host-key algorithms that syq's SSH library
cannot cryptographically verify are removed or refused rather than failing only
after a signing request. OpenSSH's `ssh -G` output does not preserve quoting for
custom known-hosts filenames. Syq uses OpenSSH's debug provenance to inspect the
configuration files OpenSSH actually read for the host. It accepts the compiled
default list only when none of those files contains the corresponding
known-hosts directive; an explicitly configured value that renders exactly like
the defaults is still treated as configured. Otherwise syq accepts one absolute
whitespace-free configured file per
`UserKnownHostsFile`/`GlobalKnownHostsFile` directive. Ambiguous custom
multi-file or whitespace-containing values fail closed.

The local configuration resolves hostB's login user, network hostname, port,
and host-key algorithms, and syq passes those values explicitly to hostA. The
inner client reads no hostA SSH configuration, disables all identity and
certificate files and PKCS#11 providers, and permits only public-key
authentication through its forwarded `SSH_AUTH_SOCK`. Its ordinary
`known_hosts` lookup is disabled because the broker independently validates
the session-bound host key against the stricter local policy before releasing
a signature. Thus hostA's `IdentityFile`, `CertificateFile`, `IdentityAgent`,
`IdentitiesOnly`, proxy, and multiplexing configuration cannot accidentally
bypass the broker. This does not revoke unrelated credentials that an already
privileged hostA possessed before syq; the preferred threat model is precisely
that hostA has no independent hostB credential. Connection
multiplexing is disabled for the outer session
so a pre-existing master cannot substitute another forwarded agent. Configured
port forwards, X11 and GSS credential delegation, PTY allocation, and
`LocalCommand` are also disabled on that session.

Session binding identifies a host by its host key, not by a DNS name or network
address. The configured name chooses the locally trusted key set, but an
endpoint that shares hostB's private host key is intentionally equivalent to
hostB for this broker. Deployments requiring distinct host identities must not
reuse host private keys between them.

Pass `--no-forward-agent` to give hostA no agent at all; hostA must then have
its own credentials for hostB, and its own `IdentityAgent` configuration is
left intact. `--unrestricted-agent-forwarding` is a
conspicuous compatibility escape hatch that exposes the complete ambient agent
to hostA for the attached transfer without imposing the constrained path's
host-bound authentication requirement. With an explicit `-e/--rsh`, syq
creates no broker and adds neither `-A` nor `-a`, so that command is the
complete agent policy; `--no-forward-agent`, `--agent-broker-only`, and the
unrestricted escape hatch therefore conflict with `-e`. `--relay` also avoids exposing authentication to
hostA, at the cost of routing file data through this machine.

SYQ uses the user's SSH configuration to resolve the login user, host-key name,
port, static known-hosts files, host-key algorithms, RSA size, and configured or
implicit user certificates. The default constrained broker requires already
recorded exact keys for hostA and hostB before connecting; it never learns a key
through hostA or silently accepts one. Dynamic `KnownHostsCommand`, external
`RevokedHostKeys`, and host-certificate trust are currently refused as described
above. If first-contact trust is appropriate, establish it with ordinary SSH
(directly or through the configured jump path) before starting the transfer.
An explicit `-e 'ssh -o StrictHostKeyChecking=accept-new'` bypasses the broker
and leaves that policy to the supplied command.

Add `--detach --no-forward-agent` to let a remote-to-remote transfer outlive
the ssh session that launched it: syq starts it on hostA, returns, and writes
progress to a log on hostA. HostA needs its own hostB credential because a
temporary local broker cannot survive detachment. An explicit `--rsh` may
provide another persistent authentication policy. Reattach with
`syq --follow hostA:LOG` to stream that progress.
An explicit `--checkpoint` path belongs to the machine running the
orchestrator: normally the invoking machine, but hostA for a direct or detached
remote-to-remote copy (`--relay` keeps it local).

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
  that directory when the link is owned by root or by the receiver's effective
  uid (the link is kept, with or without a trailing slash). A foreign-owned
  component is refused unless `--insecure-links` is given. Each receiving
  connection retains and verifies the selected directory, so replacing the
  external destination spelling afterward cannot redirect its writes. A
  symlink encountered below the destination root is payload at that path: it is
  replaced rather than followed, even when it points to a directory.
- Recognizable `.syq-part.<job-id>` paths in a source are copied as ordinary
  payload and produce one warning summary. Before transfer starts, SYQ rejects
  the exceptional case where a mapped payload path exactly equals a sidecar
  this job would use for another mapped file.
- `host:path` is relative to the remote home; `host:/abs` and `host:~/x` work.
  A colon before the first slash means remote; `./x:y` is local. All sources
  must be on the same host. `host::module` (daemon syntax) is not supported.

### Previewing a copy

`-n` / `--dry-run` connects to the endpoints and scans both sides, but creates,
updates, and deletes nothing. Its concise preflight summary makes path
placement, intended changes, logical work, and the selected data route explicit
before a real copy:

```text
syq: dry-run summary
  mapping: ./dataset/ -> gpu01:/scratch/run42 (directory contents)
  changes: 82,411 regular files; 96 directories; 14 symlinks; 3 metadata-only entries; 2 type replacements among them
  deletions: 7 entries planned after a successful copy
  logical data: 1.70 TiB in 82,411 files needing content work (upper bound); 340 GiB in 18,204 files with unchanged content
  exclusions: 3 paths/subtrees pruned by ignore rules; 12 other entries
  route: encrypted TCP to gpu01; 16 initial connections (auto-tuned)
```

Each source gets its own `mapping` line. The annotation distinguishes directory
contents, a directory copied as a child, a file placed inside a directory, and
an exact destination path. `--files-from` is identified as a selected-path
mapping. A destination-root symlink is shown as the effective directory it
resolves to. By default, syq follows a symlink in this operator-named path only
when the link is owned by root or by the receiving process's effective user,
matching rsync. This rule is the same for every receiver; running as root makes
links owned by an unprivileged user fail it. `--insecure-links` restores the
legacy follow-any-link behavior. The `changes` line separately accounts for regular files,
directories, symlinks, special files, and metadata-only updates; type
replacements are called out as an overlapping subset. This is a current
preflight assessment, not a frozen mutation ledger that can later be executed
unchanged. When a destination leaf will be replaced by a directory, descendants
are assessed against that post-replacement directory rather than through the
old leaf (including an old symlink).

The logical-data upper bound is the full size of regular files that fail the
planning-time metadata check. Resume state, block reuse, reflinks, compression,
server-side copying, or a content comparison can make the real I/O or wire-byte
count smaller. An ignored directory is pruned without scanning its descendants,
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
fifo / socket nodes via `mknod`. Owner is only set when the *receiving* side
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
Workers connect while the source is scanned but begin file data only after
the mapped payload/sidecar namespace preflight completes.
The data connections — by default separate TCP sockets carrying AES-256-GCM
records (under `--no-tcp`, separate `ssh` processes instead), each its own flow
and cipher — carry only "read range" / "write range" requests. Files go
onto a largest-first queue; when a worker runs dry it steals the back half of
the remaining range of whichever file has the most left, so the tail of a
transfer stays parallel without pre-deciding chunk counts.

On the receiving side a file that needs content changes is written beside its
destination as `.name.syq-part.<job-id>` (preallocated with `fallocate`,
written with `pwrite` from several workers), given its metadata, and `rename`d
over the target. Newly created sidecars are mode `0600`; final metadata is
applied just before publication. When an existing final file is the comparison
basis, the receiver retains that open descriptor while its blocks are hashed.
If every block matches, metadata is applied through the descriptor without
allocating or publishing a sidecar; otherwise that exact descriptor seeds the
sidecar.
The job ID is a 128-bit digest of the normalized source/destination mapping and
content-affecting options, and is stable when the same logical command is
rerun. It includes trailing-slash mapping, order-sensitive filters, metadata
semantics and block size, but not operational controls such as checksum
checking, `-j`, verbosity, progress or bandwidth limiting. Filesystem
component limits are queried and cached per directory; long basenames are
deterministically truncated and disambiguated to fit. An exceptionally long
full path still fails that one file with a clear error (even when it is
already up to date) while the rest of the transfer continues, and so does a
destination entry — say, a directory some other tool left — already occupying
the exact path this job's sidecar for that file needs. SYQ does not `fsync` transfer data;
atomic sidecar publication provides old-or-new visibility and resumable
interrupted work, not crash-durability across power loss.
Small files still use a pipelined whole-file request, but the receiver writes
each request through its sidecar and renames it before acknowledging success.
Thus every non-`--inplace` content change appears atomically complete, while
an existing file that SYQ compares block by block and finds content-identical
keeps its inode and any destination hardlinks. The same-host kernel-copy fast
path may replace a byte-identical destination that failed the quick check,
because it deliberately avoids that comparison.
`--inplace` writes every file directly (for example, to update a large file
without room for a second copy), so readers can observe partially updated
contents and an interruption leaves the final file unfinished.

Local → local runs the same machinery in-process with N threads, which helps
on NFS and NVMe.

### Resume and checkpoints

With the default staged write path, Ctrl-C is safe: kill it and rerun the same
command. `--inplace` deliberately gives up that guarantee. No checkpoint is
needed for this normal resumption. Resume works at two levels.

**Within a file.** There is no per-file state file — the partial *is* the state:

- Files whose size and mtime already match are skipped (the rsync quick check).
- If this job's range-transfer `.name.syq-part.<job-id>` exists, both sides
  hash it and the source in `--block-size` blocks and only the mismatching
  blocks are sent. A leftover is reused only when it can be safely opened as a
  singly-linked regular file without following a symlink; numeric ownership is
  deliberately not required because NFS root squashing and some FUSE/CIFS
  mounts remap it. A safe leftover that cannot be made mode `0600` is discarded
  and recreated instead of permanently blocking that file. Anything else is
  safely replaced or reported as an error.
  On NFS, reuse requires the receiver to reread the partial; syq deliberately
  keeps no separate block-completion map.
  Pipelined small files are rewritten wholesale on retry instead of paying an
  extra partial-file probe.
- If the destination file exists but differs, its blocks are hashed against
  the source too; if all match only metadata is fixed, otherwise the matching
  blocks are copied locally into a new partial and the rest transferred.

This block-level skip catches appends and in-place modifications (VM images,
databases, logs). It does **not** catch a byte inserted near the start of a
file, which rsync's rolling checksum would — for syq's intended use (fresh
uploads and downloads) that trade was made deliberately.

The partial job ID includes `--block-size` and the ordered ignore rules, so
changing either starts a separate resumable namespace. Old sidecars are not
garbage-collected automatically and may be deleted manually when the earlier
command will not be resumed. Options that do not change the copy itself, such
as `-c`, `--bwlimit`, and `-j`, do not change the partial ID.

The directory containing a destination sidecar is a trust boundary, as with
rsync's partial directories. It must not be writable by untrusted users,
especially when SYQ runs with elevated privileges. A reused sidecar may have a
filesystem-remapped numeric owner; mode and link-count validation cannot prove
who originally created a deterministic pathname in a shared writable
directory.

Versions 0.1.1 and 0.1.2 used `.name.syq-partial`. This version deliberately
does not recognize or resume that legacy form: remove any such destination
sidecars manually after an interrupted old-version transfer. A legacy-named
file in a source tree is copied as ordinary payload without a special warning.

**Across the whole job.** Ordinary copies keep no transfer history, but their
source and destination scans still skip files already complete. Deleting or
changing a destination file affects the next run just as it does with rsync.

Only when repeated destination metadata lookups are themselves too expensive
should you opt in to a checkpoint:

```sh
syq rsync -a --checkpoint ./copy.state huge-tree/ host:huge-tree/
# after an interruption, run the identical command again
```

The mode-0600 JSONL checkpoint identifies the canonical source, destination,
and copy semantics. It records regular files only after SYQ established that
the destination was complete and, for transferred files, rechecked the source.
On retry, a record whose source fingerprint still matches (size, nanosecond
mtime, and requested mode/owner/group metadata) skips that destination lookup.
Everything else follows the normal quick check, partial hashing, and transfer
path. Unfinished individual files are never checkpoint-complete; their actual
`.syq-part.<job-id>` contents remain the resume state.

The checkpoint is flushed about once a second and persists after both failed
and successful runs until you remove or stop passing it. Losing its last
buffered records only causes repeated work; if recording stops mid-run the
copy continues and a warning names the I/O error — printed even under `-q`,
while the exit code keeps describing the copy itself. Invalidation records are
flushed before a checkpoint-covered destination is removed or changes type,
but the checkpoint is not `fsync`ed and does not promise recovery across power
loss. If an existing checkpoint has completed records but an expected
destination root is missing, SYQ fails and asks you to remove the checkpoint to
restart. The checkpoint must be a regular file with exactly one hard link and
must be outside local source and destination trees; a hardlinked checkpoint is
refused because appending or changing its permissions would also affect its
other names. `-n` reads and validates existing state but never creates or
changes it. `-c`, `--verify-only`, and `--rm` conflict with `--checkpoint`. One
checkpoint file may be used by only one running copy at a time. Its filesystem
must support advisory file locking; SYQ fails rather than write checkpoint
state without single-writer exclusion.

A checkpoint is an explicit trust decision: SYQ does not inspect a destination
file covered by a matching record. If another process deleted, replaced, or
modified that destination after it was recorded, a checkpointed retry will not
notice. Do not use a checkpoint when the destination may be independently
modified; omit the option and SYQ remains history-independent. `--delete`
records what it removes in an active checkpoint, so a file the source drops
and later brings back is transferred again rather than assumed complete.

Like rsync, ordinary SYQ runs do not coordinate with each other. Different
logical commands use different partial names, so concurrent copies into one
tree produce the union of their files and one whole-file rename wins for any
path both write — but do not combine concurrent copies with `--delete`,
which mirrors *its* source and removes the other command's not-yet-shared
files and sidecars as extras. A content-identical comparison applies metadata only through
the inode it verified, so it cannot mix its metadata with another job's newly
renamed contents. Quick-check metadata repair likewise verifies the inode;
if a concurrent publication replaced it, the repair reports an error instead
of mixing metadata with the new contents.
Starting the same logical command twice at once is
unsupported: both invocations intentionally address the same resumable
sidecars. After a crash, abandoned sidecars may be deleted manually if that
command will not be resumed.

These guarantees cover other SYQ jobs, which publish complete files by rename.
They do not cover another process modifying an existing destination inode in
place while SYQ is hashing or reusing it. As with rsync, such an external
writer can invalidate a comparison after it was made; do not independently
modify destination files during a transfer.

### Verification and consistency

Always:

- Every block carries an xxh3 hash checked on receipt (read side and write
  side); a mismatch aborts that file with an error (exit 23) rather than
  silently continuing — it indicates transport corruption, which is rare.
- After a file completes, the source is re-stat'ed. If its size or mtime
  changed during the transfer the file is redone (up to three attempts), then
  reported as an error.
- Unless `--inplace` was explicit, destination content changes appear
  atomically via rename, including new small files.
- Non-zero exit if anything failed.

On request:

- `--verify-only` hashes every file on both sides in parallel and reports
  `DIFFERS` / `MISSING`.
- `-c` does the block comparison for every file, not just ones that fail the
  quick check, and repairs what differs.

Not verified: directory and symlink metadata are set but not read back; a
source that changes *between* the final re-stat and the next block of another
file isn't noticed (same as rsync). Two chunks of one file are read at
different moments, so a file being written while copied may come out mixed —
the re-stat catches the common case, `--verify-only` afterwards catches the
rest.

Compared with rsync: ordinary content-changing writes use the same
temporary-file plus atomic rename model; `--inplace` explicitly gives that up.
Rsync chooses a random temporary suffix, while SYQ uses a deterministic job ID
so an interrupted command can find its partial again without a local state
file. The change-during-transfer check is the same idea; `--delete` runs
strictly after the transfer (see below); hardlinks aren't implemented.

## Not implemented (on purpose, for now)

`RSYNC-COMPAT.md` tracks rsync compatibility in full: what matches, what
differs and why, what's missing, and the open issues. The short version:

- rsync filter rules (`--exclude`/`--include`/`--filter`); use `--ignore` (gitignore
  syntax) instead.
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
- Preserving existing partial files from `rsync --partial`; only SYQ's own
  `.name.syq-part.<job-id>` sidecars for the same logical command are
  recognised.

## When parallelism helps

- **ssh CPU**: one ssh process tops out at a few hundred MB/s of cipher/MAC
  work. N processes scale roughly linearly. Multiplexed channels over one
  connection wouldn't help — same TCP stream, same single encrypting process —
  so syq passes `-o ControlMaster=no -o ControlPath=none` for its connections
  on purpose.
- **WAN**: several TCP flows beat one against per-flow window and loss limits.
- **High-latency filesystems** (NFS, FUSE, object-backed): many small files
  are latency-bound; parallel stat and I/O hide it. The scan is parallel too.
- **NVMe / RAID** on either side.
- **Not** a single spinning disk: parallel reads of one file there mean seeks.
  Use `-j 1` or a large `--min-split`.

## How many connections (`-j`)

Without `-j`, syq tunes the number of workers while a copy runs instead of
guessing (`--rm` keeps a fixed 8, or 32 locally: removal is metadata-bound
and short). On a data path it has measured before, it starts at that path's last
settled count; otherwise it starts with 16 when every remote endpoint has a
reachable TCP data path, 8 over ssh, or 32 when both ends are local (threads
are free, connections are not). Remembered results are keyed only by the
directional endpoint path and transport (TCP and ssh learn separately), not by
RTT, workload, filesystem or other volatile telemetry. A stale hint only costs
the tuner a probe or two. The cache is
`$XDG_CACHE_HOME/syq/tuning-v1.json` (normally
`~/.cache/syq/tuning-v1.json`; set `SYQ_TUNING_CACHE` to override it or to an
empty value to disable it). Explicit `-j`, dry runs, verification, short runs
that compare no counts, failed/aborted copies, and runs whose TCP path falls
back to ssh after workers start do not update it; the last case may contain
mixed-transport measurements that are not representative of either pure path.

Useful progress (the high-water mark of logically completed bytes, plus a small
credit per completed file so small-file trees count) is sampled every 2.5 s.
Recovery can retract uncertain bytes, and retransmitting those same bytes does
not inflate the tuning rate. A count has been *measured* only once two
consecutive samples agree within 10 %, so a burst that gets throttled or a link
still ramping up is waited out (up to 20 s) rather than credited to the last
change. The first probe is a 1.3× step up — 8→10, not 8→16. A step up is kept
only when the smaller count is more than 5 % below the best recent measurement;
a step down is kept when it stays within 5 %. Thus acceptance directly follows
the objective: the smallest measured count within 5 % of the best observed
speed, from 1 through 64. A successful move keeps exploring in the same
direction. A failed move returns to the last good count and records a bound, so
later probes refine untested integers: if 10→13 helps and 13→17 is flat, syq
stays at 13 and can later try 11 rather than immediately falling back to 10.

In steady state, evidence in the upward and downward directions ages and backs
off independently. A direction is first eligible again after 6 stable
measurements (about 30 seconds at minimum); repeated failures double only that
direction's delay, up to 4 minutes at the minimum sampling rate. When both
directions are equally informative, syq deterministically probes up first:
most connection/throughput curves are concave or saturating, so an extra
connection usually loses less transfer speed than removing a useful one. This
is a prior, not a rule — measured collapse aborts a probe early, and independent
backoff lets downward evidence win.

Upward candidates connect in the background while the settled workers keep
copying; their stable rate refreshes the comparison baseline, while connection
setup time itself is not scored. A probe starts only when the activity remaining
at the observed rate is estimated to last through a complete measurement, so a
slow path is not rejected by a fixed byte threshold and a very fast tail is not
mistaken for evidence. After a decision, surplus connections and their reader
threads are closed instead of retaining the largest pool ever tried. At one
active connection syq keeps exactly one ready spare so the important 1→2 probe
remains cheap. A dropped data connection is reopened with bounded exponential
backoff; ranges with uncertain acknowledgements and final publication are
safely requeued. Transfers shorter than a measurement or two just run with the
starting count. The progress line shows the current count
(`16 conn`), and `--stats` reports the path it took
(`connections: auto: settled at 16 (path 16, peak 16)`).

Measured from a 1 Gbit box in Germany to a host in Japan (265 ms): over TCP
data connections it settles around 8–13 at line rate; over ssh data
connections (where each stream is capped by OpenSSH's 2 MB window) it
reaches line rate (~110 MB/s, where a fixed `-j 8` managed 44) about 30 s
after the connections are up.

`-j N` fixes the count and disables tuning. Use it when you know better (a
spinning disk that must not be read in parallel: `-j 1`), or to be polite on
a shared link.

## TCP data connections

ssh caps every stream at a few hundred MB/s of cipher CPU, and its 2 MB
per-channel flow-control window caps a stream at roughly `2 MB / RTT` on long
links (≈7 MB/s at 265 ms). So by default (unless `--no-tcp`) syq keeps ssh for
authentication and control only and moves the data over separate TCP
connections: the remote opens a listener on a port from `--tcp-ports` (default
47600-47699), and the data connections are plain TCP sockets carrying
AES-256-GCM records keyed by a secret exchanged over the ssh session
(`--tcp-plain` skips the encryption on trusted networks; `--no-tcp` sends data over the ssh connection instead). If the port can't be
reached — a firewall, typically — syq says so once and falls back to ssh data
connections, so the default is always safe.

On Linux, `--tcp-congestion ALGO` requests a congestion-control algorithm for
both ends of every direct TCP data connection. The connecting socket is
configured before `connect`, and the remote listener is configured before its
port is advertised, so accepted sockets inherit the same algorithm. This is a
per-socket override: syq does not change sysctls, load kernel modules, or alter
queueing disciplines. Without the option, every socket keeps its host's
default. An explicit override that either kernel rejects is a fatal error with
the affected host and kernel error; syq never silently substitutes another
algorithm. If the TCP route itself is unreachable, the normal warned SSH
fallback still applies and says that the requested algorithm is not used by
the SSH fallback.

The algorithm must be registered on both Linux hosts and available to the syq
process. Unprivileged processes may choose only entries in
`net.ipv4.tcp_allowed_congestion_control`; inspect host prerequisites and qdisc
state as described in [SERVER-TUNING.md](SERVER-TUNING.md). Congestion control
is sender-side, so setting it only on a download server does not also select it
for uploads from a client. syq can cover both directions because it owns the
data socket on each endpoint.

With `--stats`, direct TCP copies also report the kernel counters available on
both socket ends: the effective congestion-control algorithm, retransmitted
packets and bytes (a packet-loss signal), current/minimum RTT, congestion window
and delivery rate, receive-window and send-buffer limited time, and ECN CE
deliveries. These are diagnostic telemetry only and do not change the tuning
cache key. Unsupported fields are labeled unavailable rather than displayed as
zero. SSH does not expose per-data-connection TCP counters to syq, so the
statistics say they are unavailable when the data transport is SSH.

The remote advertises every address it has (the one your ssh session arrived
on first, then private LAN, then public, then CGNAT/Tailscale); the client
adds the name it reached ssh through — the only address that works for a
host behind NAT or port forwarding — ahead of the overlay ones, tries them
all, and prefers the best that answers. If none answers it says so and uses
ssh (silenced by `-q`). When several NICs of
comparable speed are reachable (e.g. an 8-rail RoCE fabric), syq spreads its
data connections across all of them (multipath) — it keeps only paths within
2x of the fastest, so it never drags a fast transfer down by mixing in a slow
link. Single-homed hosts and laptops use the one best path, unchanged. With ufw:

```sh
sudo ufw allow from 192.0.2.0/24  to any port 47600:47699 proto tcp   # example LAN
sudo ufw allow from 203.0.113.5   to any port 47600:47699 proto tcp   # a specific client
```

Use `-vv` to see the route planned for the real transfer. For each remote
endpoint seen by the active orchestrator it reports the authenticated helper
identity and platform, every TCP address syq considered, reachability and
advertised link speed, why a reachable address was or was not selected by the
preflight, the resulting planned TCP/ssh transport, and the initial connection
count. Workers authenticate their data connections after this report; if TCP
then fails, syq prints its normal data-over-ssh fallback notice. `-v` alone
keeps its existing file-listing behavior.

`-vv --dry-run` is observational: it reports the same control connection,
helper startup, TCP listener, address probes, and fallback decision that plain
`--dry-run` already performs. It does not open an authenticated data connection
or start transfer workers, and verbosity does not change dry-run's success or
failure. The reported route is therefore a plan for a real transfer, not a
claim that a worker data connection was completed.

Remote→remote (`syq rsync hostA:src hostB:dst`) works the same way: the orchestrator
on hostA connects to hostB's listener. Diagnostics are relative to that active
orchestrator: the existing status message identifies hostA, and the detailed
remote block describes hostB. If both paths are on hostA, `-vv` reports a local
filesystem route there. With `--relay`, this machine is the orchestrator and
both remote endpoints receive detailed blocks.

No special server setup is required. For a measurement-first checklist of
optional firewall, sshd, TCP, and host-network changes, including their
trade-offs and rollback considerations, see [Server performance
tuning](SERVER-TUNING.md).

## Defaults chosen for network filesystems

Small files are read and written in pipelined batches, but every non-`--inplace`
write still finishes with an atomic rename. When both ends are local, 32 workers
are used. This costs one rename per file on NFS, but avoids exposing incomplete
final-named files. `--inplace` is the explicit space/safety tradeoff.

## Ignoring paths (`--ignore`, `--ignore-from`)

syq has one filter mechanism instead of rsync's include/exclude/filter rules:
every `--ignore PATTERN` is a line of a virtual `.gitignore` anchored at each source
root, and `--ignore-from FILE` splices in the lines of a file. Patterns from
both are applied in command-line order with gitignore semantics (last match
wins, `!` re-includes), so anything you'd write in a `.gitignore` works here:

```sh
syq rsync -a --ignore node_modules --ignore .git src/ host:dst/ # a name matches at any depth
syq rsync -a --ignore '*.o' --ignore /build src/ host:dst/      # glob; leading / anchors to root
syq rsync -a --ignore 'logs/*' --ignore '!logs/keep/' src/ dst/ # everything in logs/ except keep/
syq rsync -a --ignore-from .gitignore --ignore '!dist/' repo/ host:repo/
syq rsync -a --ignore '*' --ignore '!*/' --ignore '!*.jpg' photos/ bak/ # copy only *.jpg
```

Rules of thumb (they're git's): `foo` matches a file or directory named `foo`
at any depth; `/foo` only at the source root; `foo/` only a directory; `*`
doesn't cross `/`, `**` does. An ignored directory is pruned, so nothing inside
it is transferred or even scanned — which is why "only `*.jpg`" needs the
`!*/` line to keep descending. Empty directories are copied like any other
(this is a filter on the walk, not git's notion of what's tracked). The source
root itself is never ignored; with several sources each is filtered from its
own root. `-n` previews the selected scope and intended changes. `--rm` does not
take filters (it always removes the whole tree), so `--ignore` conflicts with it.

As in git, a `!` rule cannot re-include something whose parent directory is
ignored: `logs/**` prunes `logs/keep` itself, so `!logs/keep/**` after it has
nothing to act on. Ignore the siblings instead (`logs/*`, which does not cross
`/`) and re-include the directory (`!logs/keep/`), as above.

## Deleting extras (`--delete`)

`syq rsync -a --delete src/ host:dst/` makes `dst` look like `src`: after the
transfer, anything under a destination directory that the source doesn't
have is removed. The rules are simpler than rsync's, deliberately:

- **Scope.** Only inside directories the sources map onto: `syq rsync --delete a b
  dst/` cleans `dst/a` and `dst/b`, never `dst/c`. A single-file source deletes
  nothing.
- **Ignored means out of scope, on both sides.** The `--ignore` patterns are applied
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
- With `--delete` the sidecar path of every mapped regular file stays in
  memory until deletions run (that set is what tells a live sidecar from an
  orphan); on multi-million-file trees this is the option's main memory cost.
- **After, not before.** Deletions run once every file has been transferred
  and only if the whole source scan succeeded: an unreadable source directory
  would otherwise look like one whose contents vanished (`source scan reported
  errors; skipping deletions`). The destination walk is held to the same rule:
  an unreadable directory *there* looks empty and would be removed over its
  unknown contents, so its errors also skip all deletions. A run interrupted
  during scanning or transfer therefore never starts deletion. Once deletion
  has begun, interruption can leave some planned extras removed; rerunning
  finishes the mirror. Directory mtimes are set after the deletes.
- **Sidecar-patterned files are extras unless they are this job's live
  resume state.** A `.name.syq-part.<job-id>` of *this* command whose `name`
  is still in the source stays, whatever happened to that file this run
  (failed, filtered, already up to date): the next transfer of that file
  consumes it. Everything else matching the pattern — an orphan of this
  command, or any other job id — is an ordinary extra: syq copies such names
  as payload, so the name alone proves nothing, and mirroring the source is
  what --delete is for. Note that the job identity includes the command's
  semantic options: change those (or the source/destination spelling they
  normalize to) and the previous identity's sidecars become orphans —
  removed by `--delete`, inert otherwise.
- `--max-delete N` refuses to delete anything — not the first N — when more
  than N deletions are planned, says so, and exits 25 (rsync's code for it).
- `-n --delete -v` lists every intended removal as `delete path (destination
  only)`. The preflight summary reports the number planned; a real run reports
  the number deleted. `--delete`
  conflicts with `--verify-only` (deleting is the opposite of writing
  nothing) and with `--files-from` (deletion scope under a file list is
  ambiguous).

Deletion goes through the control connection in batches of 1000 (the
destination side unlinks each batch in parallel); it isn't spread over the
`-j` data connections like `--rm` is.

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

All of these define the scope of the run, so `--verify-only` checks the files
the same command would transfer and nothing else.

## Copying a list (`--files-from`)

`syq rsync -a --files-from list.txt host:src/ dst/` copies only the paths named in
`list.txt`, one per line (`--from0`: NUL-separated; `-` reads stdin), each
relative to the single source directory, to the same relative path under the
destination. The source is not walked, which is the point on a slow
filesystem when the list is known. Parent directories of listed paths are
created (with their metadata). A parent that is a symlink on the source is
followed — you named a path through it — and becomes a real directory on the
destination, so nothing is ever written through a destination symlink; a
parent that resolves to a file or dangles is an error. A listed directory is copied *without*
its contents unless `-r` is given on the command line itself — `-a` alone
does not count, as in rsync — so `-a -r --files-from` walks the directories
the list names (never the implied parents).
Blank entries and entries starting with `#` or `;` are ignored in both modes;
spell a literal comment-looking name as `./#name` or `./;name`. Leading `/` or
`./` and trailing `/` are stripped, and `..` components or an entry that names
the root itself are rejected. A listed path that doesn't exist is an error
(exit 23) and the rest is still copied. The destination must be a directory (an
existing file there is an error, never replaced). `--files-from` can't be
combined with `--ignore`/`--ignore-from` or `--delete`; for a remote-to-remote copy
it needs `--relay` (the list is read on this machine). To also choose each
entry's destination path, use a native mapping instead (see
[MAPPINGS.md](MAPPINGS.md)).

## Parallel removal (`--rm`)

`syq rsync --rm [-j N] [-n] [-v] PATH...` removes trees the way syq copies them:
a parallel scan, files unlinked in batches across N workers, directories
removed deepest-first with each level in parallel. Symlinks are removed, not
followed. If a scanned non-directory is replaced by a directory before its
batch runs, SYQ reports the type change and never recurses into the new
directory. Remote paths (`host:path`) work. It refuses `/`, `.` and `~`. On
NFS, where every unlink is a round trip, `-j32` removed 20,000 files in 2.5 s
versus 9.7 s for `rm -rf`; on a local SSD `rm -rf` is already fast and syq is
no faster.

## Same-machine copies (copy_file_range)

When source and destination are on the same machine, syq copies each file with
`copy_file_range(2)` instead of streaming bytes through userspace: the kernel
does a reflink or a straight in-kernel copy, and on NFS 4.2 the *server* copies
the file internally (no client round trip). Measured: a single 8 GB file
/raid→/raid at 24.8 GB/s vs 2.5 GB/s for `cp`; NFS→NFS at 3.3 GB/s vs 0.4.
Hashing is skipped on this path (there's no wire to corrupt it); `-c`, any
existing partial, and `--bwlimit` disable this shortcut. Existing partials and
larger bwlimited files use the hash-resumable streaming path. Small new
bwlimited files that fit in one paced transfer block retain the `PutSmall`
exception described above.

## NFS

Local↔NFS copies are a local→local syq run (`syq rsync -a -j16 /raid/x /mnt/nfs/x`)
and benefit from the same parallelism: measured on a 20 Gbit NFSv4.2 mount,
reads of one 4 GB file 858 MiB/s with `-j8` vs ~400 MB/s for `cp`; 20,000
small files written in 28 s vs 72 s for `cp -r`. Writes of a *single* file
were capped at ~250 MB/s regardless of `-j`, while eight files written in
parallel reached ~650 MB/s: the per-file limit comes from the NFS client's one
TCP connection and per-inode write serialization. Mounting with
`nconnect=8` (NFS 4.1+; needs an unmount/mount, not a remount) is the usual
fix for that.

## Performance notes

- syq asks ssh for `aes128-gcm@openssh.com` first (falling back to the usual
  ciphers). On x86 with AES-NI that is noticeably faster per stream than
  OpenSSH's default chacha20-poly1305.
- Each connection costs one ssh handshake (~0.3 s on a LAN, several seconds
  across continents). The control connections always come up first
  (everything waits on them; only then do data connections start), up to 32
  at a time, and if the
  server sheds one — sshd's `MaxStartups` (default 10) randomly rejects
  sessions beyond 10 being set up at once — syq halves that number for the
  rest of the run and retries. Raising `MaxStartups` can reduce setup time for
  ssh data connections, but increases the resources available to
  unauthenticated clients; see [Server performance tuning](SERVER-TUNING.md).
  Auto-tuning starts at 16 for TCP data, or 8 for ssh data, and only opens more
  once they have been shown to pay.
- Preferred direct remote→remote uses one enrollment-key authentication for the
  hostB control connection, then encrypted token-authenticated TCP workers.
  `--agent-broker-only` instead authenticates every hostB SSH connection
  through your ambient agent; over a slow link or with a confirming hardware
  key, those round trips can dominate setup time.
- Measured on two 160-core hosts on a 20 Gbit LAN: a single ssh stream tops out
  around 450–550 MB/s; `syq rsync -j8` into tmpfs reached ~1.2–1.3 GiB/s (the raw
  multi-stream ssh ceiling), while writes to the destination's ext4 NVMe capped
  everything, rsync included, at ~600 MB/s. Check the disk before blaming the
  network.
- `SYQ_DEBUG=1` prints connect times and where each worker and each remote
  server spent its time (blocked on reads, pipe writes, acks; waiting, handling).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Everything copied and verified |
| 23 | Finished, but some files failed (unreadable source, `DIFFERS`, changed during transfer …) — errors are on stderr |
| 25 | Finished, but `--max-delete` stopped the deletions |
| 1 | Fatal: bad arguments, couldn't connect, remote `syq` missing, connection lost |
