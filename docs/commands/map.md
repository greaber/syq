# syq map

Print source/destination pairs as NDJSON for `syq cp --mapping`:

```sh
syq map --srcs-in photos > photos.ndjson
syq cp --mapping photos.ndjson -C photos --into archive
```

Named selectors must be relative to the source base; use `-C DIR` or `--root DIR`
to choose that base. `--srcs-in` must be the only selector when used. `--as`
requires one named object and cannot combine with `--srcs-in`.

See [Rename and reorganize during a copy](../mappings.md) for worked examples.

<!-- CLI: map -->
```text
syq map [OPTIONS] PATH...
syq map [OPTIONS] --srcs-in DIR
```

## Sources and selection

| Argument / option | Meaning |
|---|---|
| `--from <ENDPOINT>` | Source endpoint ([USER@]HOST[:PORT] or s3://BUCKET); omitted means local |
| `-C, --cwd <DIR>` | Resolve relative source selectors from DIR |
| `--root <DIR>` | Resolve source selectors beneath DIR and refuse any escape |
| `--follow` | Follow symlinks in all directly supplied filesystem paths |
| `--follow-src` | Follow symlinks in directly supplied source paths |
| `--src <PATH>` | Select a named source object (repeatable) |
| `--srcs-in <DIR>` | Select a directory's contents (repeatable) |
| `--src-non-dir <PATH>` | Select a named non-directory source object (repeatable) |
| `--src-dir <DIR>` | Select a named source directory (repeatable) |
| `--src-non-dirs <PATH>...` | Select several named non-directory source objects |
| `--src-dirs <DIR>...` | Select several named source directories |
| `--srcs <PATH>...` | Select several named source objects |
| `[PATH]...` | Named source objects (shorthand for --src) |

## Output fields

| Argument / option | Meaning |
|---|---|
| `--include <FIELD>` | Include optional output fields (comma-separated or repeatable)<br><br>[possible values: kind, size, mtime, s3_last_modified] |

## Copy policy and filtering

| Argument / option | Meaning |
|---|---|
| `--where <EXPR>` | Filter emitted mapping entries with a source expression |

## SSH and transport

| Argument / option | Meaning |
|---|---|
| `--rsh <COMMAND>` | Remote shell command (default: ssh) |
| `--syq-path <PATH>` | Use this remote syq executable instead of installing a helper |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a helper |
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | How to authorize SSH access: auto, ssh (native SSH only), @NAME (a receiving machine), or HOST (an SSH provider) |
| `--pscope <PATH>` | Use an isolated persistence domain created by `syq persist on --ephemeral` |

## Object storage

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable; S3-to-S3 metadata/tag overrides are refused) |
| `--s3-retries <N>` | Retry each S3 request up to N times after a transient failure or throttling, 0..100 (default 10; 0 disables retries) |

## Destination placement

| Argument / option | Meaning |
|---|---|
| `--as <PATH>` | Emit the single selected root at PATH, relative to the future destination container; PATH may be nested |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Mapping format

`cp --mapping` reads one JSON object per line. `syq map` writes this format
from local, SSH, or S3 sources, and other programs can generate it too.

| Field | Meaning |
|---|---|
| `src` | Required path relative to the copy's source base (`-C` or `--root`) |
| `dst` | Required path relative to the destination container (`--into`) |
| `kind` | Optional `file`, `dir`, `symlink`, or `special` precondition |
| `size`, `mtime`, `s3_last_modified` | Optional information for transforms; ignored during execution |
| `metadata` | Optional destination attributes; see below |
| `expected_hash` | Optional whole-file expectation: `{"algorithm":"md5","value":"900150983cd24fb0d6963f7d28e17f72"}` |

Paths use `encoding: "utf-8"`, or `"base64"` with standard base64 of raw
filename bytes. Absolute or empty paths, `.` and `..` components, and unknown
fields are refused.

Each entry copies one object. **A directory entry is not recursive**, so
`syq map` emits a directory's descendants as separate entries. A missing source
or a wrong `kind` fails that entry while the others continue.

By default `map` emits only `src` and `dst`; request other fields with
`--include`, for example `--include kind,size,mtime`. `kind` adds a type check
when the mapping is copied. Sizes and timestamps are information for your own
filters and do not change copying. Both timestamps are Unix seconds: `mtime` is
the file's modification time, which for S3 is the time syq stored and is
omitted when there is none, and `s3_last_modified` is S3's own object time.
`size` and `mtime` appear only on regular files, and only S3 sources can
request `s3_last_modified`. Requesting `kind` or `mtime` from S3 reads object
metadata; `map` never downloads object bodies.

`--where` selects entries with the same [expressions](../expressions.md) as
`cp`, and as in `cp` it does not filter directories. A condition can use fields
you did not include: `--where 'src.kind = "file" and src.size > 1MiB'` emits the
matching files and every directory.

For example, generate a mapping from an S3 prefix and copy selected entries later:

```sh
syq map --from s3://photos --srcs-in originals --include s3_last_modified > photos.ndjson
syq cp --from s3://photos -C originals --mapping photos.ndjson --into restored
```

If scanning or listing fails, `map` exits nonzero, though stdout may already
contain entries. See [checking the producer](../mappings.md#check-the-producer-before-copying).

`expected_hash` checks a regular file's complete contents, including reused
bytes, and a mismatch fails the entry. See
[expected hashes](../integrity-checking.md#expected-hashes) for the algorithms.

To set destination attributes without changing the source, add a `metadata`
object, for example `"metadata": {"mode": 416, "mtime": 1700000000}`, which sets
permissions to `0640` and the modification time to the given Unix second. The
optional fields are `mode` (permission bits, 0–4095), numeric `uid` and `gid`,
`mtime` (Unix seconds), and `mtime_nsec` (0–999999999, requires `mtime`).
Omitted attributes follow normal copy behavior, and the top-level `mtime`
remains informational.

Explicit attributes apply without `--copy-metadata`; S3 uploads store them in
syq's object metadata, and downloads apply them. Ownership requests fail if the
filesystem refuses them, and symlinks cannot have a requested `mode`. Selection rules such as
`--if-exists=keep` still take precedence. A supplied timestamp turns off the
size-and-time comparison for that entry, so use `--hash` when you repeat such a
copy.

## Mapping restrictions

Use `--mapping` instead of source selectors, with `--into`, `--into-new`, or
`--into-existing`. It cannot be combined with `--as`, `--prune`,
`--prune-before`, `--ignore`, `--ignore-from`, or `--detach`; to skip paths,
leave their entries out of the manifest. Use the same source base for `map` and
`cp`. Follow options apply to the paths you supply, never to links inside a
manifest entry. `map` refuses non-UTF-8 names; hand-written manifests may use
base64.

Syq validates the whole manifest before copying: malformed input, duplicate
destination names, and file/ancestor conflicts refuse the run, although the
destination container may already have been created. Memory use grows with the
size of the manifest.

For restricted copies between servers, mapped destinations and their parent
directories count against the receiver's entry limit, each manifest line is
limited to 1 MiB, and each destination path to 4096 bytes.

`kind: "special"` checks the source type; add `--copy-metadata=specials` to
copy those entries. Use `--mapping -` for a pipeline; a named pipe as the
manifest requires Linux with procfs.

## Filter a mapping

Request `--include kind,size` when generating input for these jq filters:

```sh
# Keep files of at least 1 MiB, plus directory and link entries:
jq -c 'select(.kind != "file" or .size >= 1048576)'
# Drop device, FIFO, and socket entries:
jq -c 'select(.kind != "special")'
```
