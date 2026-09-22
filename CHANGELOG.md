# Changelog

User-facing changes are recorded here starting with the release after
[0.5.2](https://github.com/greaber/syq/releases/tag/v0.5.2).
Earlier releases have notes on [GitHub Releases](https://github.com/greaber/syq/releases).

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
