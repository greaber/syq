# Rsync compatibility

For examples, start with [Use rsync-style commands](rsync.md).
See [`syq rsync`](commands/rsync.md) for all accepted options.

## Differences to check before switching

| Area | Syq behavior |
|---|---|
| Filters | Gitignore syntax via `--syq-ignore` / `--syq-ignore-from`; rsync filters are unsupported |
| Deletion timing | Extras are deleted after copying; no delete-before or delete-during mode |
| Positive `--max-delete N` | Deletes nothing if the plan exceeds N; rsync deletes up to N |
| Destination collisions | Distinct sources claiming the same destination fail before copying |
| `--ignore-existing` | Keeps an existing non-directory even where the source would create a directory |
| Type changes | Refuses replacement between a directory and any non-directory, even when the directory is empty |
| `--update` | Checks mtimes only for regular files; replacements between non-directory types still occur |
| Read-only destination directories | Briefly adds owner access, as rsync does, but then restores each directory's exact mode; `--syq-widen-dirs` changes this ([details](reference.md#copy-metadata)) |
| Resume | Keeps syq partial files a later copy can resume from; cannot reuse rsync partials |
| Existing files | Often replaced where rsync changes them in place; see [below](#existing-files) |
| Delta transfer | Reuses matching blocks only at the same offsets in the destination file. Local copies default to whole-file and remote copies to block reuse; `-W` / `--whole-file` disables reuse and `--no-W` enables it |
| `--rsync-path PATH` | Exact syq executable path, not a shell fragment |
| Remote-to-remote | Refused; use native `syq cp` |

### Existing files

Rsync changes some files in place, through every name a file has. In these
cases syq gives the name a new file instead, and other hard links keep the old
one:

- With `--inplace`, a file with other hard links, another owner, or wider
  permissions than the copy gives it ([In-place writes](reference.md#in-place-writes)).
- When only metadata changed, a file with other hard links or an unexpected
  owner, and any file on filesystems whose link counts syq does not trust,
  such as SMB, SSHFS, and some NFS and macOS volumes.
- Symlinks, named pipes, and devices whose metadata changes.

See [Copy metadata](reference.md#copy-metadata) for the details.

Scan and copy errors prevent deletion. A destination that contains its source
on the same host cannot be pruned. Preview deletion scope with `--dry-run -v`;
see [deletion rules](reference.md#mirror-a-directory).

`syq rsync` uses rsync's default size-and-whole-second timestamp quick check;
see [timestamp matching](integrity-checking.md#comparison). Use `-c` to compare
contents when size and timestamp match. `-I` (`--ignore-times`) compares only
the files block reuse would compare, by default every file in a remote copy,
and copies the rest whole, so files that already match may be rewritten. `-c`
takes precedence when both are given.

Syq uses numeric IDs and keeps partial files a later copy can resume from (see
[Resume an interrupted copy](reference.md#resume-an-interrupted-copy)), so
`--numeric-ids` and `--partial` are accepted no-ops. `-P` enables progress. Compression is on by
default; `-z` does not enable anything extra. `-B` / `--block-size` changes
syq's comparison and reuse block size; see the [tuning table](tuning.md#transfer-controls)
for its default and allowed range. Values outside that range are rejected.

`-H` preserves hardlinks between selected regular files. On Linux and macOS,
`-A` preserves ACLs and `-X` extended attributes. `-S` turns written zero
ranges into sparse holes. See the
[preservation rules and limits](reference.md#copy-metadata).

## Unsupported features

| Feature | Options or syntax |
|---|---|
| Rsync filter rules | `--exclude`, `--include`, `--filter` |
| Backup and alternate destination trees | `--backup`, `--backup-dir`, `--suffix`, `--link-dest`, `--compare-dest`, `--copy-dest` |
| Following descendant links | `-L`, `--copy-links`, `--copy-unsafe-links`, `-k`, `--copy-dirlinks`, `-K`, `--keep-dirlinks` |
| Link filtering or rewriting | `--safe-links`, `--munge-links` |
| Other placement and filesystem controls | `-R` / `--relative`, `--partial-dir`, `-x` / `--one-file-system` |
| Early deletion | `--delete-before`, `--delete-during`, `--force` |
| Other comparison and output controls | `--size-only`, `--modify-window` (FAT destinations are compared at two seconds automatically), `--chmod`, `--log-file`, `-i` / `--itemize-changes` |
| Daemon connections | `rsync://`, `host::module` |

Unsupported common flags are rejected with an explanation. Selected symlink
targets are copied unchanged. `--insecure-links` only relaxes the ownership
check on symlinks in paths you type; it does not follow symlinks beneath a
selected source.

## File-list parsing and help

`--files-from` cannot combine with syq ignore rules or deletion. A listed
source whose parent is a symlink fails that entry with exit 23.

Other parsing differences:

- `..` components are rejected rather than clamped at the source root.
- `dir/` and `dir` select the same entry. Neither selects contents unless
  `-r` is explicitly supplied; `-a` alone does not enable recursion here.
- `.` and `/` are rejected as root entries.
- Use `--from0` for NUL separators; `-0` is unsupported.

Blank entries and names starting with `#` or `;` are ignored in both separator
modes; use `./#name` for a literal name.

`-h` alone does not show help; use `--help` or `--help-all`.

## Syq extensions

Most syq-specific options carry a `--syq-` prefix. Common ones are
`--syq-ignore` and `--syq-ignore-from`. `syq rsync` also accepts syq's
`--performance-tuning`, `--resource-limits`, and
[`--integrity-checking`](integrity-checking.md) for extra payload checks.
Rsync's `--bwlimit` and `-c` / `--checksum` (BLAKE3 content comparison) keep
their usual spellings.

Filters are last-match-wins with `!` re-inclusion, unlike rsync's first-match
rules. Check the [gitignore examples](reference.md#ignoring-paths) when
converting a filtered command.

## Compare without copying

```sh
syq rsync -ancv project/ backup/
```

Compares contents without copying and lists planned changes.
