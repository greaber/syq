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
| `--src <PATH>` | Select a named source object; attach =PATH when it begins with `-` (repeatable) |
| `--srcs-in <DIR>` | Select a directory's contents; attach =DIR when it begins with `-` (repeatable) |
| `--src-non-dir <PATH>` | Select a named non-directory source object; attach =PATH when it begins with `-` (repeatable) |
| `--src-dir <DIR>` | Select a named source directory; attach =DIR when it begins with `-` (repeatable) |
| `--src-non-dirs <PATH>...` | Select several named non-directory source objects |
| `--src-dirs <DIR>...` | Select several named source directories |
| `--srcs <PATH>...` | Select several named source objects |
| `[PATH]...` | Named source objects (shorthand for --src) |

## Output fields

| Argument / option | Meaning |
|---|---|
| `--include <FIELD>` | Include optional output fields (comma-separated or repeatable)<br><br>[possible values: kind, size, mtime, s3_last_modified] |

## SSH and transport

| Argument / option | Meaning |
|---|---|
| `--rsh <COMMAND>` | Remote shell command (default: ssh) |
| `--syq-path <PATH>` | Use this remote syq executable instead of installing a helper |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a helper |

## Object storage

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable; S3-to-S3 metadata/tag overrides are refused) |

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

`cp --mapping` reads one JSON object per line. `map` emits this format from
local, SSH, or S3 sources; other programs can generate it too. By default it
emits only `src` and `dst`. Request optional fields explicitly, for example
`--include kind,size,mtime`. Repeat `--include` or separate fields with commas.

`kind` adds a type check when the mapping is copied. Size and timestamps are
information for your filters; they do not change copying. Filesystem sources
emit size and modification time for regular files. S3 size is the object body
size; `mtime` is the filesystem time stored by syq, omitted if unavailable.
`s3_last_modified` is S3's object modification time, available only for S3
sources. Both timestamps use Unix seconds and can be requested independently.
S3 object time comes from listing; requesting `kind` or `mtime` also reads
object metadata. Generating mappings never downloads object bodies.

For example, generate from an S3 prefix and copy selected entries later:

```sh
syq map --from s3://photos --srcs-in originals --include s3_last_modified > photos.ndjson
syq cp --from s3://photos -C originals --mapping photos.ndjson --into restored
```

An S3 prefix without its own directory marker produces child entries only.
Keys that cannot be represented as mapping paths, such as `a//b`, cause an
error. Source scan or listing failures return a nonzero status; stdout may
already contain entries. See [checking the producer](../mappings.md#check-the-producer-before-copying).

| Field | Meaning |
|---|---|
| `src` | Required path relative to the copy's source base (`-C` or `--root`) |
| `dst` | Required path relative to the destination container (`--into`) |
| `kind` | Optional `file`, `dir`, `symlink`, or `special` precondition |
| `size`, `mtime`, `s3_last_modified` | Optional information for transforms; ignored during execution |
| `metadata` | Optional destination attributes; see below |
| `expected_hash` | Optional whole-file expectation: `{"algorithm":"md5","value":"900150983cd24fb0d6963f7d28e17f72"}` |

Paths use `encoding: "utf-8"`, or `"base64"` with standard base64 of raw
filename bytes. Absolute or empty paths, and any `.` or `..` component, are
refused. Unknown fields are refused too.

`expected_hash` checks a regular file's complete contents, including reused
bytes. A mismatch fails the entry. See [expected hashes](../integrity-checking.md#expected-hashes)
for algorithms and behavior with in-place writes.

To set destination attributes without changing the source, add a `metadata`
object, for example `"metadata": {"mode": 416, "mtime": 1700000000}`. This sets
permissions to `0640` and the modification time to the given Unix second.
Optional fields are `mode` (permission bits, 0–4095), numeric `uid` and `gid`,
`mtime` (Unix seconds), and `mtime_nsec` (0–999999999, requires `mtime`).
A supplied `mtime` defaults to zero fractional seconds. Omitted attributes
follow normal copy behavior; the top-level `mtime` remains informational.

Explicit attributes apply without `--preserve`. Ownership requests fail if the
filesystem refuses them; symlinks cannot have a requested `mode`.
S3 uploads store the attributes in syq object metadata; downloads apply them
to the filesystem. S3-to-S3 copies keep other object metadata and stay server-side.
Restricted receivers also require matching `--preserve` permissions in the signed
grant. Selection rules such as `--only-new` still take precedence. Supplied
timestamps disable the size/time shortcut for those entries. Use `--hash` to
compare contents when repeating a copy with a fixed destination timestamp.
Older binaries that do not support `metadata` or `s3_last_modified` reject those
fields. Upgrade the consumer or remove unsupported informational fields before
copying.

Each entry copies one object. **A directory entry is not recursive.**
`syq map` emits its descendants as separate entries. A missing source or
wrong `kind` fails that entry while independent entries continue.

## Mapping restrictions

Use `--mapping` instead of source selectors, with `--into`, `--into-new`, or
`--into-existing`. It cannot combine with `--as`, `--prune`, or `--detach`.
Use the same source base for `map` and `cp`. `--root` confines source selection.
Follow options apply to supplied paths, never to links traversed by a manifest
entry. `map` refuses non-UTF-8 names; hand-written manifests may use base64.

The whole manifest is validated before copying. Malformed input, duplicate
destination names, and declared file/ancestor conflicts refuse the run. The
destination container may already have been created. Memory use grows with
manifest size. Conflicts discovered while copying fail the affected entries.

For restricted copies between servers, mapped destinations and their parent
directories count against the receiver's entry limit. Each line can be up to
1 MiB, and each destination path up to 4096 bytes. There is no separate total
manifest-size limit. Missing parent directories are created; a file or symlink
blocking a parent must be moved or removed before retrying.

`kind: "special"` checks the source type; add `--preserve=specials` to copy those
entries. Use `--mapping -` for a pipeline; a named FIFO manifest requires Linux
with procfs.

## Filter a mapping

Request `--include kind,size` when generating input for these jq filters:

```sh
# Keep files of at least 1 MiB, plus directory and link entries:
jq -c 'select(.kind != "file" or .size >= 1048576)'
# Drop device, FIFO, and socket entries:
jq -c 'select(.kind != "special")'
```
