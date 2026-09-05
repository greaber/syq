# Rsync compatibility

`syq rsync` accepts common rsync commands for local copies, pushes, and pulls.
It uses its own protocol: the remote program must be syq, not rsync.
For all accepted flags, see the [option table](reference.md#compatibility-options)
or `syq rsync --help-all`.

```sh
syq rsync -av project/ server:backup/project/
```

## Differences to check before switching

| Area | Syq behavior |
|---|---|
| Filters | Gitignore syntax via `--syq-ignore` / `--syq-ignore-from`; rsync filters are unsupported |
| Deletion timing | Extras are deleted after copying; no delete-before or delete-during mode |
| Positive `--max-delete N` | Deletes nothing if the plan exceeds N; rsync deletes up to N |
| Destination collisions | Distinct sources claiming the same destination fail before copying |
| `--ignore-existing` | Keeps an existing non-directory even where the source would create a directory |
| `--update` | Checks mtimes only for regular files; type replacements still occur |
| Resume | Always keeps syq partial files; cannot reuse rsync partials |
| Delta transfer | Reuses matching blocks at the same offsets; does not find shifted blocks |
| `--rsync-path PATH` | Exact syq executable path, not a shell fragment |
| Remote-to-remote | Refused; use native `syq cp` |

A failed source or destination scan prevents deletion. A per-file read failure
during transfer does not by itself prevent deletion: that source entry remains
present, so its destination counterpart is not an extra. Preview deletion
scope with `--dry-run -v`; see [deletion rules](reference.md#deleting-extras---delete).

Syq uses numeric IDs and always keeps partial files, so `--numeric-ids` and
`--partial` are accepted no-ops. `-P` enables progress. Compression is on by
default; `-z` does not enable anything extra. `-B` / `--block-size` changes
syq's fixed hash and resume block size.

## Unsupported features

| Feature | Options or syntax |
|---|---|
| Rsync filter rules | `--exclude`, `--include`, `--filter` |
| Hard links, ACLs, xattrs, sparse files | `-H`, `-A`, `-X`, `-S` |
| Backup and alternate destination trees | `--backup`, `--backup-dir`, `--suffix`, `--link-dest`, `--compare-dest`, `--copy-dest` |
| Following descendant links | `-L`, `--copy-links`, `--copy-unsafe-links`, `-k`, `--copy-dirlinks`, `-K`, `--keep-dirlinks` |
| Link filtering or rewriting | `--safe-links`, `--munge-links` |
| Other placement and filesystem controls | `-R` / `--relative`, `--partial-dir`, `-x` / `--one-file-system` |
| Early deletion | `--delete-before`, `--delete-during`, `--force` |
| Other comparison and output controls | `--size-only`, `-I` / `--ignore-times`, `--modify-window`, `--chmod`, `--log-file`, `-i` / `--itemize-changes` |
| Daemon connections | `rsync://`, `host::module` |

Unsupported common flags are rejected with an explanation. Selected symlink
targets are copied unchanged. `--insecure-links` does not enable any of the
unsupported descendant-link options.

## File-list parsing and help

`--files-from` cannot combine with syq ignore rules or deletion. A listed
source whose parent is a symlink fails that entry with exit 23, without
creating its implied destination parent. `--insecure-links` allows traversal
on a local source only; remote sources always refuse it.

Other parsing differences:

- `..` components are rejected rather than clamped at the source root.
- `dir/` and `dir` select the same entry. Neither selects contents unless
  `-r` is explicitly supplied; `-a` alone does not enable recursion here.
- `.` and `/` are rejected as root entries.
- Use `--from0` for NUL separators; `-0` is unsupported.

Blank entries and comment-looking names starting with `#` or `;` are ignored
in both separator modes. Use `./#name` for a literal name. See
[copying a list](reference.md#copying-a-list---files-from).

`-h` alone does not show help; use `--help` or `--help-all`.

## Syq extensions

Syq-specific options carry a `--syq-` prefix. Common ones are
`--syq-connections`, `--syq-ignore`, `--syq-ignore-from`, and
`--syq-verify-only`. The last compares selected contents without writing;
it does not produce rsync's itemized-change format.

Filters are last-match-wins with `!` re-inclusion, unlike rsync's first-match
rules. Check the [gitignore examples](reference.md#ignoring-paths) when
converting a filtered command.

The [compatibility tests](https://github.com/greaber/syq/tree/master/tests/rsync-compat)
record comparison evidence and version-specific details.
