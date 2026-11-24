# syq find

List files and directories beneath paths on this machine, on an SSH server,
or in an S3 bucket:

```sh
syq find src --where 'extension = "rs" and size > 10KiB'
syq find --on nas /backup --depth 2 --long
syq find --on s3://backups laptop/photos --json
```

Paths print relative to where the listing starts, beginning with each `PATH`
as you gave it: `syq find src` prints `src/main.rs`, and `syq find` alone lists
the current directory, or the bucket's root on S3, printing `main.rs` without
a `./`. A directory `PATH` lists what it holds, not the directory itself; any
other `PATH` lists only itself. `-C DIR` sets where relative paths start, and
`--root DIR` also refuses paths that lead outside it. Directories print
without a trailing slash.

`--depth N` lists `N` levels beneath each path, counting the entries directly
in it as level 1; [`syq ls`](ls.md) is `syq find --depth 1`. Symlinks inside
directories are listed, never followed; `--follow` follows symlinks only in
the paths you give.

Output streams while the listing runs. Entries in one directory come in byte
order on filesystems; on S3, entries from different directories arrive in no
particular order. A nonzero exit status means the listing is incomplete. An
entry that can't be read is reported on stderr and skipped, and the listing
goes on and fails at its end; a `PATH` that doesn't exist fails the command
before anything prints.

## Output

By default, `find` prints one path per line. Names can hold newlines, so
when another program reads the paths, use `--null`, as in
`syq find -0 | xargs -0 du`.

`--long` prints each entry's kind, size, modification time in UTC, and path,
and `-> TARGET` after a symlink. On S3, the time is the S3 Last-Modified time.

`--json` prints one object per line. On filesystems it holds `path`, `kind`,
`size` for regular files, and `mtime` in Unix seconds; on S3, `path`, `kind`,
`size`, `s3_last_modified` and `etag` from the listing, without a request for
each object:

```json
{"path":"src/main.rs","kind":"file","size":1824,"mtime":1795517300}
```

`--include` chooses the fields after `path` instead, from `kind`, `size`,
`mtime`, `s3_last_modified`, `etag`, `mode`, `uid`, `gid`, `ctime` and
`link_target`. An entry without a field, such as a directory's `size`, leaves
it out. JSON can only hold UTF-8 text, so a name that isn't valid UTF-8 fails
`--json`; `--null` and the other forms print it unchanged.

## Filtering

`--where` filters every entry, directories included, with an
[expression](../expressions.md#find-and-ls). Name fields without `src.`:

```sh
syq find --where 'kind = "dir" and name glob "*-old"'
syq find logs --where 'path glob "logs/2026-*/**" and mtime > now - 7d'
```

`path` in an expression is the path as printed. To skip whole directories
without reading them, use `--ignore PATTERN` or `--ignore-from FILE`; their
gitignore-style rules match paths relative to each `PATH`, as in
[`cp`](../copy-files.md#ignoring-paths).

On S3, see [List objects](../object-storage.md#list-objects) for the requests
`find` makes and the permissions it needs.

<!-- CLI: find -->
```text
syq find [OPTIONS] [PATH]...
```

## What to list

| Argument / option | Meaning |
|---|---|
| `--on <ENDPOINT>` | Endpoint to list ([USER@]HOST[:PORT] or s3://BUCKET); omitted means local |
| `-C, --cwd <DIR>` | Resolve relative paths from DIR; on S3, a key prefix |
| `--root <DIR>` | Resolve paths inside DIR and refuse any that lead outside it |
| `--follow` | Follow symlinks in the paths you give, never inside directories |
| `--follow-src` | Follow symlinks in the paths you give (same as --follow) |
| `[PATH]...` | Paths to list beneath, taken literally (default: the base directory) |

## Selection

| Argument / option | Meaning |
|---|---|
| `-d, --depth <N>` | List at most N levels beneath each path; direct children are level 1 |
| `--ignore <PATTERN>` | Skip paths matching a gitignore-style pattern, with everything beneath them (repeatable) |
| `--ignore-from <FILE>` | Read gitignore-style patterns from FILE (repeatable; applied in command-line order with --ignore) |
| `--where <EXPR>` | List only entries, directories included, that match an expression |

## Output

| Argument / option | Meaning |
|---|---|
| `-l, --long` | Print kind, size, modification time (UTC) and path |
| `--json` | Print one JSON object per line |
| `-0, --null` | End each path with NUL instead of a newline, keeping names exactly |
| `--include <FIELD>` | JSON fields to print after path, instead of the default ones (comma-separated or repeatable)<br><br>[possible values: kind, size, mtime, s3_last_modified, etag, mode, uid, gid, ctime, link_target] |

## Performance tuning

| Argument / option | Meaning |
|---|---|
| `--performance-tuning <KEY=VALUE,...>` | Simultaneous S3 listing requests: [s3-requests=N](../tuning.md#listing) |

## SSH and transport

| Argument / option | Meaning |
|---|---|
| `--rsh <COMMAND>` | Remote shell command (default: ssh) |
| `--syq-path <PATH>` | Run the remote syq at PATH instead of syq's automatically installed copy |
| `--no-bootstrap` | Run the syq found in the remote $PATH instead of syq's automatically installed copy |
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Whose SSH access to use: this machine's own (auto or ssh), or access approved by a receiving machine (@NAME) or SSH authorization provider (HOST) |
| `--pscope <PATH>` | Use the scope that `syq persist on --ephemeral` created at PATH, with its own connections and settings |

## Object storage

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable) |
| `--s3-retries <N>` | Retry each S3 request up to N times after a transient failure or throttling, 0..100 (default 10; 0 disables retries) |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->
