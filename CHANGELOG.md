# Changelog

User-facing changes are recorded here starting with the release after
[0.5.2](https://github.com/greaber/syq/releases/tag/v0.5.2).
Earlier releases have notes on [GitHub Releases](https://github.com/greaber/syq/releases).

## Unreleased

Changes since 0.5.2.

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

- Local destinations use directory descriptors directly without a loopback
  data connection. Metadata workers are reused between batches, large prune
  plans use less temporary storage, and remote alias checks are pipelined.
- Linux range writes to the same file are serialized within each helper
  process, while reception and hashing remain parallel.
- The benchmark script defaults to small SSH uploads, adds an untimed tuning
  warm-up, supports individual tools and explicit syq tuning options, and
  separates total time from copying time. Use `--mode local` for local tests
  and `--warmup off` to skip warm-up.
- Documentation separates task guides from persistence and tuning references.
  Existing documentation heading links are preserved.
