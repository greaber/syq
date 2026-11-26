# syq ls

List the entries directly in a directory, on this machine, on an SSH server,
or in an S3 bucket. `syq ls` is [`syq find`](find.md) with `--depth 1`, and
takes the same options; `--depth N` lists `N` levels instead.

```sh
syq ls
syq ls --long photos
syq ls --on s3://backups laptop/
```

Without a `PATH`, `ls` lists the current directory, or the bucket's root on
S3. A directory `PATH` lists what it holds; any other `PATH` lists only itself.
Paths print starting with each `PATH` as you gave it, and directories print
without a trailing slash.

On S3, `ls` needs only permission to list the bucket, unless `--where` or
`--include` asks for metadata that listings lack; see
[List objects](../object-storage.md#list-objects).

<!-- CLI: ls -->
```text
syq ls [OPTIONS] [PATH]...
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
| `-d, --depth <N>` | List N levels beneath each path instead of 1 |
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
