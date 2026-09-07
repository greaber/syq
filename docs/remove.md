# Remove files

Remove a file or a directory tree:

```sh
syq rm old-output
```

Remove a directory's contents, leaving the directory itself:

```sh
syq rm --srcs-in cache
```

Add `--dry-run -v` to either command to see what would be removed first.
Missing paths succeed. Removal is permanent; completed deletions cannot be
rolled back.

## On another machine

```sh
syq rm --on server /scratch/old-output
```

This removes `/scratch/old-output` on `server`. Remote removal runs while your
connection stays open; there is no detached mode.

## Limit the selection

```sh
syq rm --root /srv cache old-output
```

This removes `/srv/cache` and `/srv/old-output`, with selection confined to
`/srv`. Use `--src-non-dir PATH` or `--src-dir DIR` when the path must be a
non-directory or directory respectively. All selections are checked before
deletion begins. Filters are not supported.

## Symlinks

A selected symlink is removed as a link, leaving its target alone. Symlinks
inside a selected directory are also only unlinked.

`--follow-src` permits traversal through symlinks in `--cwd`, `--root`, and
selector parent directories. `--follow` also permits symlinks in the
`--results` path.
The final selected symlink is always removed as a link, even with `--follow-src`
or `--follow`. For example, if `current` points to `releases/v1`,
`syq rm --follow-src current/log.txt` removes `releases/v1/log.txt`, while
`syq rm --follow-src current` removes only the link.

`--src-dir` and `--srcs-in` reject a final selected symlink, including when
following is enabled. Select the actual directory to remove it or its contents.
With `--root`, traversal must still stay inside that root.

## Results

The command continues with independent entries after per-entry failures and
exits 23. Fatal setup or connection failures exit 1. Use
[`--results`](automation.md) for per-path outcomes in scripts.

For the full option list, run `syq rm --help-all`.
