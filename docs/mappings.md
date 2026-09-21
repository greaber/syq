# Rename and reorganize during a copy

List the files, change their destination names, then copy them. `syq map`
produces the list, a script changes it, and `syq cp --mapping` makes the copy.

For Python scripts, see the [Python SDK](python.md) and its
[mapping examples](python.md).

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

## Emitting a mapping

```sh
syq map --srcs-in photos     # contents; paths relative to photos
syq map photos              # named directory; paths include photos/
syq map photo.jpg --as albums/cover.jpg
```

`map` lists local files without copying them. Use the same source directory
when making the copy: a list produced with `--srcs-in photos` needs `-C photos`
on `cp`. Each listed directory includes separate entries for its contents.

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

Each line names a source and destination relative to the directories you give
`cp`. You can generate this list with any program:

```sh
syq cp --mapping pairs.ndjson -C photos --to nas --into /archive
```

See [Mapping format](commands/map.md#mapping-format) for fields, encodings,
and validation rules.

<a id="semantics-and-limits"></a>

Use `--mapping` in place of source selectors, with an `--into` placement.
For supported combinations and path rules, see
[Mapping restrictions](commands/map.md#mapping-restrictions).

## Copy between servers

The manifest is read on the machine where you run the command. Its source
paths resolve on the source server, and its destination paths resolve beneath
the destination container:

```sh
syq cp --from hostA -C /data --mapping pairs.ndjson --to hostB --into /archive
```

File contents travel directly between the servers. See
[Copy between servers](remote-to-remote.md) for setup.

## Machine-readable results

Add `--results r.ndjson` to record outcomes in a fresh file outside the copy
trees. After fixing a failure, rerun the original mapping to finish the copy.
For scripts that select only failed entries to retry, see
[Retry failed mapping entries](automation.md#retry-failed-mapping-entries).
