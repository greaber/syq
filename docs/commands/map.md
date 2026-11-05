# syq map

Write a mapping, a list of source and destination pairs, so you can rename or
reorganize files before copying them with `syq cp --mapping`:

```sh
syq map --srcs-in photos > photos.ndjson
syq cp --mapping photos.ndjson -C photos --into archive
```

Selectors work as in `cp`, except that named selectors must be relative to the
source base (`-C` or `--root`) and `--srcs-in` must be the only selector.
[Rename and reorganize during a copy](../mappings.md) has worked examples.

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
| `--as <PATH>` | Emit the selected object at PATH, relative to the directory it is later copied into; PATH may be nested |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Mapping format

A mapping has one JSON object per line. `syq map` writes it, and you can edit
or generate it with any program:

```json
{"src":{"encoding":"utf-8","value":"2024/IMG_1234.JPG"},"dst":{"encoding":"utf-8","value":"july/IMG_1234.JPG"},"kind":"file","size":4194304}
```

| Field | Meaning |
|---|---|
| `src` | Required path relative to the copy's source base (`-C` or `--root`) |
| `dst` | Required path relative to the destination directory (`--into`) |
| `kind` | Optional `file`, `dir`, `symlink`, or `special`; the entry fails if the source has another type |
| `size`, `mtime`, `s3_last_modified` | Optional information for your own filters; the copy ignores them |
| `metadata` | Optional destination attributes; see below |
| `expected_hash` | Optional whole-file hash, such as `{"algorithm":"md5","value":"900150983cd24fb0d6963f7d28e17f72"}`; the entry fails if the copied file does not match. See [expected hashes](../integrity-checking.md#expected-hashes) |

Each path has an `encoding` and a `value`: `"utf-8"` text, or `"base64"` of the
raw filename bytes for a name that is not UTF-8. `syq map` refuses such names,
but a mapping you write can use them. Paths must be relative, with no `.` or
`..` components, and unknown fields are refused.

Each entry copies one object, and **a directory entry does not copy its
contents**, so `syq map` lists every descendant as its own entry. An entry
whose source is missing or has the wrong `kind` fails, and the others still
copy.

`map` writes only `src` and `dst` unless you ask for more with `--include`, for
example `--include kind,size,mtime`. `size` and `mtime` (the modification time
in Unix seconds) appear only on regular files. For an S3 source, `mtime` is the
time syq stored with the object, if any, and `s3_last_modified` is S3's own
time. `map` never downloads S3 objects, but requesting `kind` or `mtime` reads
each object's metadata.

`--where` selects entries with [expressions](../expressions.md) as in `cp`, and
likewise keeps every directory. It can test fields you did not include:
`--where 'src.kind = "file" and src.size > 1MiB'` emits large files and every
directory.

If scanning fails, `map` exits nonzero but may already have written entries;
see [check the producer](../mappings.md#check-the-producer-before-copying).

To give a destination different attributes from its source, add `metadata`.
For example, `"metadata": {"mode": 416, "mtime": 1700000000}` sets permissions
to `0640` and the modification time to that Unix second. The fields are `mode`
(permission bits, 0–4095; not for symlinks), numeric `uid` and `gid`, `mtime`
(Unix seconds), and `mtime_nsec` (requires `mtime`), all optional. They apply
without `--copy-metadata`; S3 uploads store them, and downloads apply them. A
supplied `mtime` turns off the size-and-time comparison for that entry, so add
`--hash` when you repeat the copy.

## Mapping restrictions

Use `--mapping` in place of source selectors, with `--into`, `--into-new`, or
`--into-existing`, and give `map` and `cp` the same source base. A mapping
cannot be combined with `--as`, `--prune`, `--prune-before`, `--ignore`,
`--ignore-from`, or `--detach`; to skip paths, leave them out of the mapping.
Syq never follows symlinks within an entry's paths; `--follow` and its variants
apply only to paths on the command line.

Syq checks the whole mapping before copying anything, so a malformed line or
two entries with the same destination refuse the run; the destination
directory may already have been created. Memory use grows with the size of the
mapping. Read a mapping from a pipeline with `--mapping -`. Entries with
`kind: "special"` are copied only with `--copy-metadata=specials`.

## Filter a mapping

Request `--include kind,size` when generating input for these jq filters:

```sh
# Keep files of at least 1 MiB, plus directory and link entries:
jq -c 'select(.kind != "file" or .size >= 1048576)'
# Drop device, FIFO, and socket entries:
jq -c 'select(.kind != "special")'
```
