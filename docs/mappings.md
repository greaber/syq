# Rename and reorganize during a copy

`syq map` lists source/destination pairs as one JSON object per line.
Transform that list with a script, then give it to `syq cp --mapping`.
The copy checks for destination collisions and supports normal resume.

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

Paths use `encoding: "utf-8"`, or `"base64"` with standard base64 of raw
filename bytes. Absolute or empty paths, and any `.` or `..` component, are
refused. Unknown fields are refused too.

Each entry copies one object. **A directory entry is not recursive.**
`syq map` emits its descendants as separate entries. A missing source or
wrong `kind` fails that entry while independent entries continue. A kind
mismatch is a non-retryable conflict; a missing source is an I/O failure
whose retryability is unknown.

Any program can generate this format:

```sh
syq cp --mapping pairs.ndjson -C photos --to nas --into /archive
```

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

- `--mapping` replaces `cp` source selectors. Use `--into`, `--into-new`, or
  `--into-existing` for the destination. It cannot combine with `--as` or
  `--prune`, and a mapping copy requires at least one local endpoint.
- A contents selection emits paths relative to the selected directory. Use
  that same directory as the consuming copy's `-C` base. Named `map`
  selectors must be relative and resolve inside their base; a contents
  selector may point outside it. `--root` confines either kind of selection.
- Follow options apply to command-line paths, never to manifest entries.
  A manifest entry that would traverse a symlink fails. Named `map`
  selectors followed with `--follow-src` emit the referent path relative to
  their base and refuse referents outside it.
- Named manifest paths follow the normal control-path rules: only `--follow`
  permits link traversal in that path. Use `--mapping -` for portable stream
  input; named FIFOs need Linux with procfs.
- The whole manifest is read and validated before copying. Malformed input,
  duplicate destinations (including identical duplicate lines), and declared
  file/ancestor conflicts refuse the run. The destination container may
  already have been created. Memory grows with manifest size.
- Conflicts found only when inspecting actual source or destination objects
  fail individual entries. A missing destination parent is created implicitly.
- Normal native preservation applies. `kind: "special"` checks the type but
  does not enable special-file copying: use `--preserve=specials` or those
  entries are visibly excluded.

## Machine-readable results

Add `--results r.ndjson` to record outcomes in a fresh file outside the copy
trees. See [Automation results](automation.md) for the stream contract.

Failed mapping entries contain `src`, `dst`, and `kind`, so they can form a
retry manifest. First require a terminal `result` with `success` or `partial`:
a missing terminal or an early stop means some entries may have no results.
In those cases, rerun the original copy instead.

```bash
set -o pipefail
syq cp --mapping big.ndjson -C src --to nas --into /data --results r.ndjson
jq -cs 'if (.[-1].type? // "") != "result"
        then "incomplete results stream (no terminal record)" | halt_error
        elif (.[-1].status != "success" and .[-1].status != "partial")
        then "run stopped early (status \(.[-1].status)); rerun it instead of retrying" | halt_error
        else .[] | select(.type == "operation_result"
                          and .disposition == "failed"
                          and .retryable != "no")
             | {src, dst, kind} end' r.ndjson \
  | syq cp --mapping - -C src --to nas --into /data
```

The filter skips non-retryable entries, including failed implicit parent
creation without a source path. It does not guarantee that retrying will
succeed; fix the underlying error first. Unchanged and excluded files appear
only in summary totals, not as individual results.
