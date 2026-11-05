# syq rm

Remove local files, files on an SSH server, or S3 objects. See
[Remove files](../remove.md) and, for versioned buckets,
[Versions and deletion](../object-storage.md#versions-and-deletion).

```sh
syq rm --src-dir old-output --dry-run -v
```

In scripts, `SYQ_RM_OPTIONS` adds arguments (see
[environment variables](../environment.md)), and
[Removal records](../automation.md#removal-records) describes `--results`.

<!-- CLI: rm -->
```text
syq rm [OPTIONS] PATH...
syq rm [OPTIONS] --srcs-in DIR
```

## SSH and transport

| Argument / option | Meaning |
|---|---|
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Use approved SSH account access, or request S3 authorization from a receiving machine |
| `--syq-path <PATH>` | Use this exact syq executable on the remote removal endpoint |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a helper |
| `--pscope <PATH>` | Use an isolated persistence domain created by `syq persist on --ephemeral` |

<a id="copy-policy-and-filtering"></a>

## Object storage

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable; S3-to-S3 metadata/tag overrides are refused) |
| `--s3-retries <N>` | Retry each S3 request up to N times after a transient failure or throttling, 0..100 (default 10; 0 disables retries) |
| `--s3-all-versions` | Permanently remove all selected S3 object versions and delete markers |
| `--s3-version-id <ID>` | Permanently remove one version or delete marker of one exact S3 key |

## Sources and selection

| Argument / option | Meaning |
|---|---|
| `--on <ENDPOINT>` | Removal endpoint ([USER@]HOST[:PORT] or s3://BUCKET); omitted means local |
| `-C, --cwd <DIR>` | Resolve relative selectors from DIR at the removal endpoint |
| `--root <DIR>` | Confine resolution and removal beneath DIR |
| `--follow` | Like --follow-src; also follow symlinks in the --results path |
| `--follow-src` | Follow symlinks in --cwd, --root, and selector parent directories; always unlink a final selected symlink |
| `--src <PATH>` | Select a non-directory object (repeatable) |
| `--srcs-in <DIR>` | Recursively select a directory's contents, keeping the directory (repeatable) |
| `--src-non-dir <PATH>` | Select a non-directory object (repeatable) |
| `--src-dir <DIR>` | Select a directory tree (repeatable) |
| `--src-non-dirs <PATH>...` | Select several non-directory objects |
| `--src-dirs <DIR>...` | Select several directory trees |
| `--srcs <PATH>...` | Select several non-directory objects |
| `[PATH]...` | Selected objects (shorthand for --src) |

## Preview and output

| Argument / option | Meaning |
|---|---|
| `-n, --dry-run` | Preview without changing files; remote setup may still install syq, and requested results files are still written |
| `-v, --verbose...` | List removed paths |
| `-q, --quiet` | Suppress non-error messages |

## Performance tuning

| Argument / option | Meaning |
|---|---|
| `--performance-tuning <KEY=VALUE,...>` | Fix deletion concurrency: [workers=N for filesystems or s3-requests=N for S3](../tuning.md#deletion) |

## Progress and results

| Argument / option | Meaning |
|---|---|
| `--progress` | Show progress even when stderr is not a terminal |
| `--no-progress` | Never show the human progress display |
| `--results <FILE>` | Write the machine-readable NDJSON result stream to FILE (created fresh; an existing file is refused) |
| `--results-fd <FD>` | Write the result stream to an inherited file descriptor the caller opened (e.g. `--results-fd 3 3>run.ndjson`); must be above 2 |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Selection rules

Named paths, `--src`, and `--src-non-dir` remove only non-directories. Use
`--src-dir` to remove a directory and its contents, or `--srcs-in` to empty it;
both refuse a final symlink. Syq checks every selector first, so one naming the
wrong kind of object stops the run before anything is removed; a missing one
does not. `rm` has no filters.
