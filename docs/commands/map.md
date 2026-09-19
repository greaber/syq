# syq map

Print local source/destination pairs as NDJSON for `syq cp --mapping`:

```sh
syq map --srcs-in photos > photos.ndjson
syq cp --mapping photos.ndjson -C photos --into archive
```

See [Rename and reorganize during a copy](../mappings.md) for worked examples.

<!-- CLI: map -->
```text
syq map [OPTIONS] PATH...
syq map [OPTIONS] --srcs-in DIR
```

## Sources and selection

| Argument / option | Meaning |
|---|---|
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

`cp --mapping` reads one JSON object per line. `map` emits this format from local
sources; other programs can generate it too.

| Field | Meaning |
|---|---|
| `src` | Required path relative to the copy's source base (`-C` or `--root`) |
| `dst` | Required path relative to the destination container (`--into`) |
| `kind` | Optional `file`, `dir`, `symlink`, or `special` precondition |
| `size`, `mtime` | Optional information for transforms; ignored during execution |
| `expected_hash` | Optional whole-file expectation: `{"algorithm":"md5","value":"900150983cd24fb0d6963f7d28e17f72"}` |

Paths use `encoding: "utf-8"`, or `"base64"` with standard base64 of raw
filename bytes. Absolute or empty paths, and any `.` or `..` component, are
refused. Unknown fields are refused too.

`expected_hash` checks a regular file's complete contents, including reused
bytes. A mismatch fails the entry. See [expected hashes](../integrity-checking.md#expected-hashes)
for algorithms and behavior with in-place writes.

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

These jq filters keep or remove entries before `cp --mapping` reads them:

```sh
# Keep files of at least 1 MiB, plus directory and link entries:
jq -c 'select(.kind != "file" or .size >= 1048576)'
# Drop device, FIFO, and socket entries:
jq -c 'select(.kind != "special")'
```
