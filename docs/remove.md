# Remove files

See [`syq rm`](commands/rm.md) for the option list.

Remove a file or symlink:

```sh
syq rm old-file
```

Named paths, `--src`, and `--srcs` refuse directories. Select a tree explicitly
to remove it recursively:

```sh
syq rm --src-dir old-output
```

Remove a directory's contents recursively, leaving the directory itself:

```sh
syq rm --srcs-in cache
```

Add `--dry-run -v` to either command to see what would be removed first.
Missing paths succeed. Filesystem removal is permanent; completed deletions cannot be
rolled back.

## On another machine

```sh
syq rm --on server --src-dir /scratch/old-output
```

Keep the connection open until removal finishes. A dry run may still
[install syq](install.md#automatic-installation-on-ssh-servers) on the server.

For object storage, use `--on s3://BUCKET`:

```sh
syq rm --on s3://backups --src-dir old-backup --dry-run -v
```

Ordinary removal respects bucket
versioning; explicit version deletion is available with `--s3-all-versions` or
`--s3-version-id`. See [S3 removal](object-storage.md#versions-and-deletion).

## Limit the selection

```sh
syq rm --root /srv --src-dir cache --src-dir old-output
```

This removes `/srv/cache` and `/srv/old-output`, with selection confined to
`/srv`. Use `--src-non-dir PATH` or `--src-dir DIR` when the path must be a
non-directory or directory respectively. All selections are checked before
deletion begins. Filters are not supported.

## Symlinks

Removing a symlink leaves its target alone. This applies to selected links and
links found inside a directory being removed.

Use `--follow-src` to reach a file through a symlink in its parent path:

```sh
# If current points to releases/v1, remove releases/v1/log.txt.
syq rm --follow-src current/log.txt
```

`syq rm --follow-src current` still removes only the link. To remove a linked
directory or its contents, select the actual directory. With `--root`, paths
must stay inside that root.

## Results

If some entries cannot be removed, syq reports the errors and continues with
independent entries. Completed deletions remain in effect. Use
[automation results](automation.md) for per-path outcomes in scripts.
