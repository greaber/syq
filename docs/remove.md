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
syq rm --from server /scratch/old-output
```

This removes `/scratch/old-output` on `server`. Remote removal runs while your
connection stays open; there is no detached mode.

## Limit the selection

```sh
syq rm --root /srv cache old-output
```

This removes `/srv/cache` and `/srv/old-output`, with selection confined to
`/srv`. Use `--src-file PATH` or `--src-dir DIR` when the path must be a
non-directory or directory respectively. All selections are checked before
deletion begins. Filters are not supported.

## Symlinks

A selected symlink is removed as a link, leaving its target alone. Symlinks
inside a selected directory are also only unlinked.

`--follow-src` follows links in paths you supply and removes the referent;
the link remains. With `--root`, the selection must still stay inside that root.

## Results

The command continues with independent entries after per-entry failures and
exits 23. Fatal setup or connection failures exit 1. Use
[`--results`](automation.md) for per-path outcomes in scripts.

For the full option list, run `syq rm --help-all`.
