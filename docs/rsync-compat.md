# Rsync compatibility

For examples, start with [Use rsync-style commands](rsync.md).
See [`syq rsync`](commands/rsync.md) for all accepted options.

## Differences to check before switching

| Area | Syq behavior |
|---|---|
| Filters | Gitignore syntax via `--syq-ignore` / `--syq-ignore-from`; rsync filters are unsupported |
| Deletion timing | Extras are deleted after copying, and not at all after scan or copy errors; no delete-before or delete-during mode ([rules](reference.md#mirror-a-directory)) |
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

Rsync changes some existing files in place, so every hard link to the file
sees the change. In these cases syq instead replaces the file at the name it
copies to, and other hard links keep the old file:

- With `--inplace`, a file with other hard links, another owner, or wider
  permissions than the copy gives it ([In-place writes](reference.md#in-place-writes)).
- When only metadata changed, a file with other hard links or an unexpected
  owner, and any file where syq can't tell it has no other names, such as on
  SMB, SSHFS, and some NFS and macOS volumes.
- Symlinks, named pipes, and devices whose metadata changes.

See [Copy metadata](reference.md#copy-metadata) for the details.

### Comparison

Like rsync, `syq rsync` skips files whose size and modification time match to
the whole second ([details](integrity-checking.md#comparison)), and `-c`
compares their contents too. `-I` (`--ignore-times`) also stops trusting size
and time, but compares only the files block reuse would compare (by default,
every file in a remote copy) and copies the rest whole, so files that already
match can be rewritten. `-c` wins when both are given.

### Other options

`--numeric-ids` and `--partial` are accepted and change nothing: syq always
uses numeric IDs and keeps [partial files to resume
from](reference.md#resume-an-interrupted-copy). `-P` shows progress.
Compression is on by default, so `-z` adds nothing. `-B` / `--block-size` sets
syq's comparison and reuse block size, within the range in the [tuning
table](tuning.md#transfer-controls).

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

Symlinks are copied with their targets unchanged. `--insecure-links` only
relaxes the ownership check on symlinks in paths you type; it does not follow
symlinks beneath a selected source.

## File-list parsing and help

With `--files-from`:

- `dir/` and `dir` select the same entry. Neither selects contents unless
  `-r` is explicitly supplied; `-a` alone does not enable recursion here.
- Blank entries and names starting with `#` or `;` are ignored, also with
  `--from0`; use `./#name` for a literal name.
- A listed source whose parent is a symlink fails that entry with exit 23.
- Use `--from0`, not `-0`, for NUL separators.

`-h` alone does not show help; use `--help` or `--help-all`.

## Syq extensions

Most syq-specific options carry a `--syq-` prefix. `syq rsync` also accepts
syq's `--performance-tuning`, `--resource-limits`, and
[`--integrity-checking`](integrity-checking.md) for extra payload checks.

Filters are last-match-wins with `!` re-inclusion, unlike rsync's first-match
rules. Check the [gitignore examples](reference.md#ignoring-paths) when
converting a filtered command.

## Compare without copying

```sh
syq rsync -ancv project/ backup/
```

Compares contents without copying and lists planned changes.
