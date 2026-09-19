# Rename and reorganize during a copy

See [`syq map`](commands/map.md) for the option list.

`syq map` lists source/destination pairs as one JSON object per line.
Transform that list with a script, then give it to `syq cp --mapping`.
The copy checks for destination collisions and supports normal resume.

For Python scripts, see the [Python SDK](python.md) and its
[mapping examples](python-guide.md).

## Lowercase destination names

```bash
set -o pipefail
syq map --srcs-in src \
  | jq -c '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C src --to nas --into /pub
```

```text
src/                       nas:/pub/
  Berlin/IMG_1234.JPG         berlin/img_1234.jpg
  Notes.TXT                  notes.txt
```

If another entry also claims `notes.txt`, the copy is refused before files
are transferred. Symlink target text is not rewritten: renaming its target
can leave a link dangling on a case-sensitive destination.

## Group photos by modification month

```bash
set -o pipefail
syq map --srcs-in photos \
  | jq -c 'select(.kind == "file")
        | .dst.value = (.mtime | gmtime | strftime("%Y/%m")) + "/" + .dst.value' \
  | syq cp --mapping - -C photos --to nas --into /archive
```

A July 2024 file `IMG_1234.JPG` lands at `/archive/2024/07/IMG_1234.JPG`.
The filter keeps regular files only; missing parent directories are created.
Dates use file modification time in UTC, not photo EXIF dates.

Other filters can replace the `jq` stage:

```sh
# Keep files of at least 1 MiB, plus directory and link entries:
jq -c 'select(.kind != "file" or .size >= 1048576)'
# Drop device, FIFO, and socket entries:
jq -c 'select(.kind != "special")'
```

## Check the producer before copying

A pipeline's consumer sees only the bytes it receives. If a generator fails
after emitting valid entries, those entries can still be copied.
`set -o pipefail` makes the pipeline report failure, but does not undo writes.

To require successful generation before copying, save the manifest first:

```bash
set -o pipefail
syq map --srcs-in src | jq -c '.dst.value |= ascii_downcase' > m.ndjson \
  && syq cp --mapping m.ndjson -C src --to nas --into /pub
```

Add `--dry-run -v` to `cp` to preview placement.

## The format

A manifest contains one JSON object per line (NDJSON):

```json
{"src":{"encoding":"utf-8","value":"IMG_1234.JPG"},"dst":{"encoding":"utf-8","value":"2024/07/photo.jpg"},"kind":"file","size":4194304,"mtime":1721900000}
```

| Field | Meaning |
|---|---|
| `src` | Required path relative to the copy's source base (`-C` or `--root`) |
| `dst` | Required path relative to the destination container (`--into`) |
| `kind` | Optional `file`, `dir`, `symlink`, or `special` precondition |
| `size`, `mtime` | Optional information for transforms; ignored during execution |
| `expected_digest` | Optional whole-file expectation: `{"algorithm":"md5","value":"900150983cd24fb0d6963f7d28e17f72"}` |

Paths use `encoding: "utf-8"`, or `"base64"` with standard base64 of raw
filename bytes. Absolute or empty paths, and any `.` or `..` component, are
refused. Unknown fields are refused too.

`expected_digest` checks a regular file's complete contents, including reused
bytes. A mismatch fails the entry. See [expected digests](integrity-checking.md#expected-digests)
for algorithms and behavior with in-place writes.

Each entry copies one object. **A directory entry is not recursive.**
`syq map` emits its descendants as separate entries. A missing source or
wrong `kind` fails that entry while independent entries continue.

Any program can generate this format:

```sh
syq cp --mapping pairs.ndjson -C photos --to nas --into /archive
```

## Copy between servers

The manifest is read on the machine where you run the command. Its source
paths resolve on the source server, and its destination paths resolve beneath
the destination container:

```sh
syq cp --from hostA -C /data --mapping pairs.ndjson --to hostB --into /archive
```

`--mapping -` reads the manifest from stdin. File contents travel directly
between the servers. The receiver allows writes at the listed destinations
and creates missing parent directories. If a file or symlink blocks a parent
directory, move or remove it before retrying.

Mapped destinations and their parent directories count against the receiver's
entry limit. Each manifest line can be up to 1 MiB, and each destination path
up to 4096 bytes. There is no separate limit on the total manifest size.

## Emitting a mapping

```sh
syq map --srcs-in photos     # contents; paths relative to photos
syq map photos              # named directory; paths include photos/
syq map photo.jpg --as albums/cover.jpg
```

`map` is local and does not contact a destination. It takes source selectors,
`-C` or `--root`, source follow options, and `--as` for one named selection.
Copy options and filters belong to the later `cp` command or your transform.
`map` refuses non-UTF-8 names; hand-written manifests may use base64.

## Semantics and limits

Use `--mapping` in place of source selectors, with an `--into` placement.
It cannot combine with `--as`, `--prune`, or `--detach`.

Use the same source base for `map` and `cp`. A `--srcs-in photos` mapping uses
paths relative to `photos`, so pass `-C photos` when copying it. `--root`
confines source selection. Follow options apply to supplied paths, never to
links traversed by a manifest entry.

Syq reads and validates the whole manifest before copying. Malformed input,
duplicate destination names, and declared file/ancestor conflicts refuse the
run; memory use grows with manifest size. The destination container may already
have been created. Conflicts discovered while copying fail the affected entries.

`kind: "special"` checks the source type; add `--preserve=specials` to copy
those entries. Use `--mapping -` for a pipeline; a named FIFO manifest requires
Linux with procfs.

## Machine-readable results

Add `--results r.ndjson` to record outcomes in a fresh file outside the copy
trees. After fixing a failure, rerun the original mapping to finish the copy.
For scripts that select only failed entries to retry, see
[Retry failed mapping entries](automation.md#retry-failed-mapping-entries).
