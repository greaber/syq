# Changelog

User-facing changes are recorded here starting with the release after
[0.5.2](https://github.com/greaber/syq/releases/tag/v0.5.2).
Earlier releases have notes on [GitHub Releases](https://github.com/greaber/syq/releases).

## Unreleased

Changes since 0.7.1. Copies between servers now set up one enrollment per
server account, authorized by your own SSH key. Copies can preserve hard
links, ACLs, extended attributes and more, select files with expressions, and
choose how existing files are handled. Updates of existing files, small files
and network filesystems are much faster.

### Upgrade notes

- **Copies between servers enroll again.** Restricted copying now uses one
  enrollment per server account, and your own SSH login key signs each copy.
  Enrollments made by syq 0.7.1 and earlier are ignored and not listed; the
  first copy sets up a new one beside them, and an older syq can keep using
  the old ones. Revoke them with the older syq before upgrading, or remove
  them by hand as described in
  [enrollments from older versions](docs/remote-reference.md#enrollments-from-older-versions).
  `syq receiver enroll` now takes an account, `[USER@]HOST`, instead of
  `HOST:DESTINATION`.
- **Enrollment needs a key login and an ordinary account.** The login to the
  destination must use an SSH key syq can sign with: one in your SSH agent or
  a key file without a passphrase. Password, keyboard-interactive and other
  non-key logins no longer authorize these copies, RSA keys need at least
  2048 bits, and DSA keys are refused. The receiver refuses to run as root.
  These copies no longer require OpenSSH 8.9; the destination needs OpenSSH
  7.2 or newer.
- **Host keys for copies between servers follow ssh.** The coordinating server
  checks the destination's host key the way its own `ssh` would, including
  `Match` blocks, `KnownHostsCommand` and host certificates, and also accepts
  the keys your laptop knows. `StrictHostKeyChecking ask` is treated as
  `accept-new`; set `StrictHostKeyChecking yes` on that server to refuse hosts
  neither machine knows. See
  [how hostA checks hostB's key](docs/security.md#how-hosta-checks-hostbs-key).
- **Renamed and removed options.** Most old spellings now fail with a message
  that names the replacement. Python keywords changed the same way.
  - `--inplace` becomes `--in-place=new` (write only new files at their final
    names) or `--in-place=update` (also update existing files in place where
    syq can vouch for them, and replace the rest). `syq rsync --inplace` now
    means `update`.
  - `--preserve` becomes `--copy-metadata`, which also accepts `times` for
    `mtime`.
  - `--only-new` becomes `--if-exists=keep`, and the hidden `--skip-newer`
    becomes `--if-exists=update-if-older`.
  - `--tcp-plain` becomes `--no-tcp-encryption` (`--syq-no-tcp-encryption` in
    `syq rsync`). It now also checks payloads with XXH3-128 unless
    `--integrity-checking` sets `transfer`.
  - `--receiver-receipt` and the Python receipt types are removed. `--results`
    now works for every copy between servers, without `--coordinate-at local`.
  - `--performance-tuning s3-retries=N` becomes `--s3-retries N`.
  - `syq persist receive on --server` and `--all-servers` become `--connection`
    and `--all-connections`.
  - `--mapping` no longer combines with `--ignore` or `--ignore-from`; leave
    unwanted entries out of the mapping instead.
- **Unchanged files keep their metadata.** In `syq cp`, files whose contents
  already match, and existing directories, keep their modification time and
  other metadata unless `--copy-metadata` selects it, for example
  `--copy-metadata=mtime`. `--if-exists` chooses how existing files are
  handled; the default, `update`, updates files whose contents differ. See
  [choose which existing files to update](docs/reference.md#choose-which-existing-files-to-update).
- **`syq map` lists only `src` and `dst`** unless you add fields with
  `--include`, for example `--include kind,size,mtime`.
- **Automation output** now uses schema 4 for ordinary calls and schema 5 for
  stream mappings. Top-level `elapsed_ms` moves to `timings.total_ms`;
  `copying_elapsed_ms` moves to `timings.transfer_ms` for filesystem and S3
  copies. In activity objects, including per-endpoint entries, `elapsed_ms`
  is now `sample_duration_ms`. Receipt fields and records are gone, and a
  copy that fails outright now writes an `error` record. The Python SDK
  exposes the measurements through `Timings`; update the SDK and executable
  together, since older and newer versions reject each other's output.
- **Helpers live in `~/.local/lib/syq`.** Syq keeps the helpers it installs on
  servers, and releases chosen with `--use-version`, in `~/.local/lib/syq`
  instead of `~/.cache`, so servers need a writable `~/.local/lib`. Helpers
  are installed again on first use, and `~/.cache/syq/helpers` can be deleted.
- **HTTPS uses the system's root certificates** for release and helper
  downloads and S3. Minimal Linux systems may need the `ca-certificates`
  package; `SSL_CERT_FILE` and `SSL_CERT_DIR` replace the system roots. See
  [HTTPS certificates](docs/security.md#https-certificates).
- **Interrupted S3 multipart uploads** started by 0.7.1 start over after the
  upgrade, and older versions refuse to resume uploads this version started.
- **Receiving machines:** after upgrading both machines, run
  `syq persist connect SERVER` on the receiving machine. It replaces the
  receiving connection from the older version and keeps your settings;
  requests that were waiting for approval must be made again. See
  [updating connections](docs/persistence-reference.md#updating-connections).
- **Builds from source**, including `cargo install syq` and Python source
  builds, now report their development version, such as
  `0.7.1+dev.0123456789ab`, from `--version` and in results.

### Behavior changes

- `--auth-from auto`, the default, first tries the server's own SSH login. It
  asks a receiving machine for approval only when that login fails: the key is
  refused, the host key is not trusted, the name does not resolve, or the
  connection is refused. Use `--auth-from @NAME` to always ask.
- `syq cp` no longer changes the permissions of read-only directories you own
  to copy into them; `--widen-dirs rsync` or `all` allows it. `syq rsync`
  briefly widens the directories it copies, as rsync does (`--syq-widen-dirs`).
- Without `--copy-metadata=permissions` (`syq rsync -p`), new files and
  directories follow the destination's default ACL or umask on every route,
  and `syq rsync` keeps read-only source directory modes, as rsync does. When
  permissions are copied, an existing destination directory that is wider
  than its source is narrowed before files are copied into it.
- Ignore rules match paths relative to each selected source directory on every
  route, including S3, and skip named file sources whose names match.
- Bandwidth limits on SSH and TCP copies count bytes sent after compression,
  shared by all workers. A copy relayed through a server limits each direction
  separately.
- Copies on one machine, including onto mounted network filesystems, copy
  changed files whole instead of reading the old file to reuse its blocks;
  copies with a remote syq endpoint still reuse matching blocks. See
  `--transfer-strategy`.
- Copies no longer refuse to start for lack of free space; they start copying
  while still scanning. `--dry-run` shows the space estimate, and a copy that
  runs out of space keeps the files it finished.
- Tuning history uses a new format and a 10 MiB default size, so starting
  worker counts are learned again. Syq 0.7.1 on the same machine ignores the
  new history.
- Relative `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `XDG_RUNTIME_DIR` values are
  ignored.
- `--version`, `--help`, `completion` and `persist status --json` exit 0
  quietly when their output is closed early, and 1 when writing fails.

### Copies between servers and receiving machines

- When your laptop approves an upload that a server starts with
  `--auth-from @NAME`, the first approval sets up an enrollment on the
  destination. The server then connects to it directly, and the copy keeps
  going if your laptop disconnects.
- Restricted receivers use the ordinary copy path. They are faster and use
  much less memory, no longer stop near four million files, and support hard
  links, ACLs, extended attributes, access and birth times, sparse files,
  ownership and special files. Approval prompts are shorter, show the
  server's actual syq command, and add a warning line for each such option.
- Pruning on a copy a receiving machine approves uses that machine's
  `--max-delete` as its limit; the server no longer needs its own.
- A server can open SSH sessions to another account by asking your laptop or
  an SSH provider host for approval instead of forwarding your SSH agent: see
  `syq ssh`, `syq persist auth-from` and `syq persist ssh-config`. This needs
  OpenSSH 8.9 or newer. `--pscope` selects an isolated set of connections and
  settings on every `persist` command.
- `--rsh` commands that run `ssh` share and keep connections like the default
  ssh.
- One copy accepts up to 1,024 named sources, including on approved copies.
- Ending the syq command that started a copy between servers stops the copy,
  unless it used `--detach`.
- Receiving no longer redials forever a server that refuses forwarding; it
  names the sshd setting to change. After a rejected login it backs off, and
  `syq persist status` shows why. `persist receive on` no longer fails
  intermittently while the receiving service starts.
- `SYQ_AUTH_FROM` sets the SSH authorization choice for every command run in
  a shell or script. It overrides saved choices, and `--auth-from` still wins
  over it.
- Inside tmux, commands that can use SSH replace an `SSH_AUTH_SOCK` that no
  longer exists with the tmux session's current agent: `syq ssh`, `persist`
  and `receiver`, copies, removals and listings with an SSH endpoint
  (including descriptor and pipe copies), and remote path completion.
- When `auto` asks a receiving machine because this machine's own SSH keys or
  agent did not work, syq first prints one line saying what went wrong and how
  to fix it. Every wait for approval says so at once on stderr, even without a
  terminal. A command queued behind another one says it is waiting for that
  command to finish setting up SSH access.
- A command that starts background connections or receiving says so once and
  names `syq persist off`.

### Copying

- `--copy-metadata=hardlinks,acls,xattrs,atimes,crtimes`
  (`syq rsync -H -A -X -U -N`) preserves hard links, ACLs and extended
  attributes on Linux and macOS, access times, and macOS birth times, and
  `syq rsync -aHAX` now works. `--open-noatime` reads sources without
  updating their access times, and `--sparse` (`syq rsync -S`) writes zero
  ranges as holes.
- `--where` selects files with typed expressions and `--copy-if` decides which
  ones may be created or updated; `syq map` accepts `--where` too. See
  [expressions](docs/expressions.md).
- `syq map --from HOST` and `--from s3://BUCKET` list remote sources.
- `--if-exists` chooses between `update`, `error-if-different`, `error`,
  `keep` and `update-if-older`.
- `--in-place=update` writes only the changed parts of existing files, and
  updates small files in groups.
- `--transfer-strategy` chooses whether to reuse blocks of the existing
  destination file; `syq rsync` accepts `-W` and `--no-W`. `--hash-or-copy`
  compares only the files the strategy would compare, and `syq rsync` accepts
  `-I`.
- `--prune-before` removes extra destination entries before copying, to free
  space.
- `syq --use-version VERSION` runs an exact official release, and
  `--version-is` stops a script unless the invoked release matches.
- Copies report setup, planning, transfer, finalization and total time
  separately, and show a compact timing line. Transfer time and speed leave out
  setup and helper installation.
- An interrupted copy removes its temporary files, except partial files a
  later copy can resume from. A rerun that finds leftover partial files from
  earlier attempts names the `syq clean-partials` command that removes them,
  and `clean-partials` now also removes S3 download partials.
- The TCP check waits a few SSH round trips for an answer instead of a full
  second, and says when file data falls back to SSH. The summary shows data
  reused inside transferred files separately from unchanged files.

### S3

- `--s3-write-header` adds headers only to requests that create objects, and
  `--s3-retries` sets the retry count. S3-to-S3 copies can update content
  headers, user metadata, tags and storage class with `--copy-metadata`.
- Uploads store a BLAKE3 hash of each file, so later `--hash` runs compare
  without downloading, and a file with matching contents but a different time
  is not uploaded again.
- Uploads over HTTPS no longer send request checksums or the signed payload
  hash that 0.7.1 added, and rely on TLS in transit; this cuts CPU use
  sharply. Buckets that require a checksum get Content-MD5, and uploads over
  plain HTTP always send it.
- Bucket-to-bucket copies decide whether a destination matches from syq's
  hashes, full-object SHA-256 or CRC64NVME, and otherwise ETags or stored size
  and time; 32-bit CRCs and SHA-1 no longer count.
- Each request keeps its own retries under throttling and honors
  `Retry-After`. Copies and removals stop after the service stops answering,
  uploads the service received corrupted are sent again, and a missing
  recovery cache no longer stops a copy.
- Permanent version deletions work on Tigris.
- Storage approvals (`--auth-from @NAME`) never sign requests that create or
  delete a bucket, and sign only the headers syq sends or you named.
- Downloads make fewer requests, and planning large S3 mappings is much
  faster.

### Performance

- Fresh local copies scan in parallel and start copying before the scan
  finishes, short copies start faster, and replacing many small files uses
  far less CPU.
- Updating existing files over a remote connection compares files in groups,
  with 64 KiB blocks. In one test, 1,024 changed 16 KiB files at 100 ms round
  trip took 2.7 s instead of 31.9 s. `--hash` keeps the fast paths and, on one
  machine, hashes both sides in parallel.
- Remote copies spend fewer round trips setting up and closing. On slow links,
  workers size their requests from measured completion times and share unread
  work.
- Copies onto NFS, SMB, SSHFS and other network filesystems make far fewer
  requests per file, write in parallel, and start more workers for small
  files.
- Removal and pruning tune their own concurrency and use much less CPU on many
  small files.
- `syq map` uses up to about 40% less memory on large trees, and published
  binaries for Linux and Apple Silicon macOS are 16-20% smaller.
- Files on compressed btrfs are no longer preallocated, so they stay
  compressed.
- Copies use more workers under low open-file limits, and recover when they
  run short of file descriptors or threads.

### Fixes

- A same-machine in-place copy could leave an existing file empty when its
  fallback write failed, for example on an rclone mount or a full disk.
- Delayed write errors, such as a full NFS export, are reported before the file
  is put in place. In filesystem copies, a source that changes during the copy
  is usually detected before the destination is replaced.
- On Linux ext4, XFS, Btrfs, ZFS and tmpfs, destination blocks syq reuses are
  checked with a read lease, so another program writing them during the copy
  is noticed.
- New files and directories stay private until their permissions are set,
  and metadata changes never briefly widen permissions. In ordinary copies, a
  file another program swaps in during the copy never receives the copy's
  data or metadata; `--in-place=update` and `--as-fd` write into existing
  files. The receiver of a local copy listens only on the loopback interface.
- SSHFS, FAT, exFAT and macOS FAT32 destinations are handled safely: hard
  links and symlink copies work on SSHFS, FAT files with odd-second times are
  no longer copied again on every run, and a replacement on macOS FAT32 no
  longer destroys the target.
- `syq rm` no longer reports failures after removing directories on NFS,
  SSHFS and other FUSE mounts.
- Hangs fixed: several SSH helpers starting at once on macOS, undecodable
  replies from a helper, a crashing worker, and a closed stderr pipe. Remote
  command output on macOS is no longer lost.
- On Linux, long copies keep working when syq is upgraded during the copy.
- Copies keep working, with a warning, when persistent connections or SSH
  connection sharing cannot be used, and SSH control socket directories are
  always private. Installing a helper on a server no longer needs a writable
  cache on your machine.
- Python: `timeout=` holds when a child process keeps syq's output open, and
  mapping callbacks keep per-entry failures separate.
- Dependency updates for TLS advisories RUSTSEC-2026-0346 to 0349 (rustls),
  RUSTSEC-2026-0381 (webpki-roots), RUSTSEC-2026-0382 (rustls-webpki) and
  RUSTSEC-2026-0385 (ctutils).

## 0.7.1 — 2026-09-22

- Strengthen single-part S3 upload integrity by reusing the prepared SHA-256
  checksum for signed payload validation. This lets providers such as Tigris
  reject corrupted payloads even when they do not enforce the additional
  checksum header. It applies to direct and delegated uploads without another
  hashing pass; multipart and MD5-based uploads keep their existing behavior.
- Reduce release preparation time with reusable validation evidence and Cargo
  caches, native builds alongside validation, and Python packaging alongside
  SDK checks. Python wheels reuse the verified native release executables.

## 0.7.0 — 2026-09-22

Changes since 0.6.0. This release adds S3-compatible storage, byte streams and
callback mappings, and new controls for receiving and automatic tuning.

### Upgrade notes

- Native `--connections` / `-j` and `--tuning-options` are replaced by
  `--performance-tuning`, for example `workers=4`. Native `--bwlimit` becomes
  `--resource-limits bandwidth=RATE`. Resource limits can also cap automatic
  concurrency. S3 uses separate `s3-requests`, `s3-objects`, and
  `s3-parts-per-object` counts; `workers` is filesystem-only.
  The corresponding Python keywords changed too. In `syq rsync`, standard
  `--bwlimit` remains, while `--syq-connections` becomes
  `--performance-tuning workers=N`.
- `--verify-only` and `--syq-verify-only` are removed. Use `--dry-run --hash`
  (rsync: `--dry-run --checksum`) to compare contents without copying.
  Differences are planned changes, not a failing exit status; scripts that
  need to detect differences must inspect the results.
- `--progress-json` and `--syq-progress-json` are removed. Native `--results`
  includes progress and final outcomes, with optional rate and ETA estimates.
  Automation uses schema 2, or schema 3 for stream mappings; schema-1 consumers
  must be updated. Use the matching Python SDK with the new executable.
- Native `cp --min-size`, `--max-size`, and the `--via` authorization alias
  are removed. Filter mapping entries to select sizes, and use
  `--auth-from @NAME` for authorization. Native `--only-existing` and
  `--skip-newer` are hidden experimental options that warn when used;
  rsync's standard `--existing` and `--update` remain available.
- Extra payload integrity checks are now opt-in with
  `--integrity-checking transfer=blake3`, independently of encryption.
  Transport authentication, content comparison, resume checks, and required
  storage-provider checks remain active when needed. Mapping entries can
  supply an `expected_hash` to require complete known contents before a staged
  replacement is published; `--inplace` may leave changes on failure.
- Before upgrading receiving machines, stop background services with
  `syq persist off`, including any script scopes. Upgrade both machines, then
  reconnect with `syq persist connect SERVER`. Saved names and directories
  carry over, but former `--approve always` settings now require approval.
  Choose `--auto-approve-root DIR` explicitly for unattended downloads within
  a directory. Older binaries reject the updated preferences; manage them
  with the new binary. See [updating connections](docs/persistence-reference.md#updating-connections).
- The Python SDK now requires Python 3.13.4+. Platform wheels include the
  matching executable and expose the `syq` command. Source installations
  require Rust and a C compiler. JavaScript and Go SDK releases are separate.

### S3 storage and programmable copies

- Copy to, from, and between S3-compatible buckets with `syq cp`; remove
  objects with `syq rm`, including explicitly selected historical versions.
  Support includes pruning, metadata preservation, AWS region discovery,
  custom providers and request headers, and resumable multipart transfers.
  Bucket-to-bucket copies stay within one storage service.
- Use `--auth-from @NAME` to approve S3 work with credentials on a connected
  receiving machine. After storage authorization is ready, that machine can
  disconnect while the server transfers directly to storage. Authorization
  is bounded by its approved lifetime and the provider's credential policies.
- `--src-fd` and `--as-fd` connect local, SSH, and S3 copies to open files and
  shell pipelines. Python `open_reader` / `open_writer` provide managed byte
  streams; `StreamSource` / `StreamDestination` callbacks support generated
  or consumed data across mapping entries with shared transfer capacity.
- Mapping entries can specify destination metadata and expected hashes.
  Failed-entry results preserve those values for retries. Dry-run hash
  comparison reports content differences without changing destination data.
- `SYQ_CP_OPTIONS`, `SYQ_RSYNC_OPTIONS`, and `SYQ_RM_OPTIONS` supply options
  for commands inside scripts without passing those settings to child helpers.

### Receiving, performance, and installation

- Receiving profiles support a hard directory root, a separate automatic
  approval root, and allowed-server selection. Commands and credential
  authorization always require approval. Copies to a named receiving machine
  can use encrypted TCP initiated by that machine, with SSH fallback.
- Filesystem transfers save local tuning histories and reuse starting worker
  counts matched to their context. `syq tuning-cache` inspects and clears this
  history. Remote hints also distinguish known local networks. History stays
  on the coordinator, defaults to a 128 MiB retention target, and can be
  disabled with `SYQ_TUNING_HISTORY=`.
- Automatic tuning prepares and reuses connections, explores startup counts,
  and evaluates changes against current throughput. Compression adapts to
  channel speed. TCP discovery includes IPoIB and uses available macOS link
  speed information.
- Local macOS copies can use APFS cloning. Small-file batching, metadata
  lookup reuse, sparse updates, and transfer-buffer reuse reduce repeated
  work. Removal no longer waits unnecessarily after its last task finishes.
- Release downloads, helper installation, managed Python downloads, and update
  checks use `dl.syq.christmas`, a maintainer-run cache for GitHub release files.
  It records request and location data described in the
  [install guide](docs/install.md#update-check-data). Homebrew installations
  receive update reminders too; `SYQ_NO_UPDATE_CHECK=1` or `DO_NOT_TRACK=1`
  disables reminders.
- Release binaries and Python distributions have pinned reproducible build
  recipes. The documentation site provides separate stable, archived-release,
  and development versions, with command and Python reference pages.

## 0.6.0 — 2026-09-13

Changes since 0.5.2.

Highlights include safer concurrent copies, lower CPU use for large Linux
transfers, and receiving names that remain assigned while a machine is offline.

### Upgrade notes

- Receiving machines now require `@NAME`: use `--to @laptop`,
  `--auth-from @laptop`, `--via @laptop`, and `syq exec --on @laptop`.
  **`--to laptop` now always selects an SSH host**, even when a receiving
  machine has that name.
- Receiving names stay assigned to the same machine while it is offline.
  Before upgrading, stop receiving services with `syq persist off`, including
  any script scopes. Upgrade the commands on both machines, then reconnect
  with `syq persist connect SERVER`. Older commands do not enforce the new
  assignments. To replace a receiving machine, stop its connection and run
  `syq persist destinations forget NAME` on the server. See
  [updating connections](docs/persistence-reference.md#updating-connections).
- Interrupted copies now leave private `.FILENAME.syq-tmp.RANDOM` files.
  Partials from 0.5.2 (`.syq-part.`) are not reused or selected by the new
  cleanup command. Finish interrupted transfers before upgrading if you need
  to preserve their resume progress; otherwise, retry the copy and inspect
  old partials before removing them manually.
- Both `syq cp` and `syq rsync` refuse replacement between a directory and
  any non-directory, even an empty directory. Move or remove the obstruction
  before retrying. Replacements between non-directory types remain supported.
- When an official release bootstraps an SSH helper, it also tries to install
  an independent command at `~/.local/bin/syq`. This can happen during dry runs,
  completion, and background connection setup. Existing commands are kept;
  installation failure does not fail the copy. See
  [automatic installation](docs/install.md#automatic-installation-on-ssh-servers).
- New standalone installations keep their self-update receipt beside the
  executable, normally `.syq-install.json`. Existing receipts in the syq
  configuration directory remain supported.

### Copying and cleanup

- Concurrent copies use separate partial files and check reused blocks against
  the source. A successful retry can leave earlier partials behind.
  `syq clean-partials --dry-run TREE` previews their removal; stop copies before
  running `syq clean-partials TREE`. Remote cleanup uses `--on SERVER`.
- Resume discovery is bounded: directories with more than 256 partials may
  not reuse all of them. Shortened or omitted filename prefixes may also
  prevent reuse. These cases resend data rather than compromising the result.
- Scan or copy errors now prevent pruning. Pruning also protects recognized
  partials, replacement recovery entries, and their parent directories, and
  refuses source overlap it can identify. See
  [pruning rules and coverage](docs/reference.md#mirror-a-directory).
- Failed non-directory replacements preserve the previous destination when
  staging fails. Truncated local copies and failed or cancelled range writes
  cannot be published as complete files.
- Native copies now compare fractional modification times at the precision
  suggested by the destination timestamp. This catches more same-size edits
  within a second. `syq rsync` keeps its whole-second file comparison;
  `--hash` (`-c` in rsync mode) checks content regardless of timestamps.
- macOS copies handle directory permission repair more consistently and no
  longer mistake exFAT's unavailable inode count for a full filesystem.

### Performance and tools

- Large transfers on Linux can use substantially less CPU when several workers
  write one file. This benefits TCP and local range copies while keeping
  reception and hashing parallel. [PR #336](https://github.com/greaber/syq/pull/336)
  records the measured CPU savings and copy times, which vary by workload.
  Independent SSH helpers do not share this optimization.
- Local destinations use directory descriptors directly without a loopback
  data connection. Metadata workers are reused between batches, large prune
  plans use less temporary storage, and remote alias checks are pipelined.
- The benchmark script defaults to small SSH uploads, adds an untimed tuning
  warm-up, supports individual tools and explicit syq tuning options, and
  separates total time from copying time. Use `--mode local` for local tests
  and `--warmup off` to skip warm-up.
- Documentation separates task guides from persistence and tuning references.
  Existing documentation heading links are preserved.
