# Mappings: placement as data

A mapping is a file (or stream) of explicit source→destination claims that
`syq cp` can execute: each entry names one source path and the destination
path it claims. This document calls that file the manifest. Think of it as
a generalized `--as` covering many entries at once, or a `--files-from`
whose entries can also *re-place* each file. You author selection and
placement, with a script or by transforming a mapping syq itself emits, and
syq does what it always does: parallel transfer, sending only the blocks
that changed, resume, verification, and conflict checking before a single
byte moves.

```bash
set -o pipefail
syq map --srcs-in photos \
  | jq -c '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C photos --to nas --into /pub
```

rsync hardcodes single instances of this idea as flags (`--iconv` is a
filename transform; `-R` with a `/./` marker is a placement transform).
With a mapping, any tool that can edit NDJSON (one JSON object per line)
can do the transform, and syq refuses case-fold collisions that a
hand-rolled rename loop would silently overwrite.

## The format

One JSON object per line (NDJSON):

```json
{"src": {"encoding": "utf-8", "value": "IMG_1234.JPG"},
 "dst": {"encoding": "utf-8", "value": "2024/07/img_1234.jpg"},
 "kind": "file", "size": 4194304, "mtime": 1721900000}
```

- `src`, `dst` (required): paths relative to the source base (`-C DIR`,
  `--root DIR`, or by default the working directory) and the destination container (`--into
  DIR`). Absolute paths, empty paths, and any `.` or `..` component are
  rejected. Paths are tagged: `encoding` is `utf-8`, or `base64` for a
  name that is not valid UTF-8 (`value` is then standard base64 of the
  raw bytes).
- `kind` (optional): `file`, `dir`, `symlink`, or `special`. This
  removes any ambiguity: mapping a file and mapping a directory
  (non-recursively; entries are never recursive) are different
  operations. If the object at `src` (an object is a file, directory,
  symlink, or special file) is not the declared kind, that entry fails,
  exactly as if `src` did not exist. Without `kind`, the entry maps
  whatever is there.
- `size`, `mtime` (optional, informational): emitted by `syq map` for
  transforms to filter on; execution ignores them. Unknown keys are
  rejected, so a typo cannot be silently dropped.

Duplicate destinations, and a destination claimed both as a file and as
a directory ancestor of another entry, are conflicts, detected before
any transfer begins, across the entire manifest. Destination ancestor
directories no entry names are created implicitly, as with
`--files-from`.

## Emitting a mapping

`syq map` takes the same local selectors as `syq cp` and prints the resolved
selection as a mapping instead of copying:

```sh
syq map --srcs-in photos          # contents of photos/, dst == src
syq map photos                    # named object: dst starts with photos/
```

`syq map` refuses to emit names that are not valid UTF-8 (so a
one-line transform you publish never meets a base64 name); mappings you
author yourself may use the base64 form for such names.

`syq map` deliberately knows nothing about the destination. Its options are
`-C`, `--root`, `--follow-src`/`--follow`, the source selectors, and `--as`.
It takes either `--srcs-in DIR` as the only selector or any number of
relative named selectors. `--as PATH` places the single selected path at
`PATH`, which may be nested; `cp --mapping` creates any missing parents.
Options for the destination, filtering, transfer, execution, results,
receiver limits, and receipts (a receipt is a signed record of what the
destination host did, available when the destination is enrolled) belong to
the later `syq cp --mapping` invocation or to a manifest transform, not to
`syq map`.

## Transform in the middle

Because a mapping is plain data, the pipeline
`syq map … | <transform> | syq cp --mapping - …` covers, as one-liners,
things that otherwise need dedicated flags or custom copy scripts.
Re-running any of these converges like any other syq copy: what
already landed is skipped.

As in any shell pipeline, `syq cp` sees only the bytes that reach it:
the examples set `set -o pipefail` (Bash) so a failure in the program
feeding it fails the pipeline. Nothing wrong is copied either way: a
truncated manifest copies only a valid prefix, and re-running the
corrected pipeline converges. To let each stage finish before the next
starts, write the manifest to a file instead:

```bash
set -o pipefail
syq map --srcs-in src | jq -c '.dst.value |= ascii_downcase' > m.ndjson \
  && syq cp --mapping m.ndjson -C src --to nas --into /pub
```

### Lowercase every destination name

A migration to a case-insensitive filesystem:

```bash
set -o pipefail
syq map --srcs-in src \
  | jq -c '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C src --to nas --into /pub
```

```text
src/                          nas:/pub/ afterwards
├── Berlin/                   ├── berlin/
│   ├── IMG_1234.JPG          │   ├── img_1234.jpg
│   └── IMG_1235.JPG          │   └── img_1235.jpg
└── Notes.TXT                 └── notes.txt
```

If `src` also contained `notes.TXT`, the run is refused before any
transfer: two entries claim `notes.txt`.

For a one-shot copy, GNU tar can do this rename more simply:

```sh
tar -C src -cf - --transform='s/.*/\L&/' . | ssh nas 'tar -C /pub -xf -'
```

That is a reasonable choice for a one-time transfer. Its limits:

- The case-fold collision above extracts with exit 0; the last writer
  wins and one file's content is lost without warning.
- Every run resends every byte: no delta, no resume, and an
  interrupted pipe leaves truncated files in place.
- The data moves over one connection, at single-stream ssh speed.
- The transform sees only the name, so the mtime- and size-based
  examples below cannot be expressed.
- Symlink targets are rewritten too by default, which breaks links
  pointing outside the tree. (syq takes the opposite trade: target
  text is copied verbatim, so out-of-tree links survive, but an
  in-tree link does not follow the rename, which is harmless here because the
  case-insensitive destination resolves `Notes.TXT` anyway, dangling
  on a case-sensitive one.)

rsync itself has no rename option. Keeping rsync's delta and resume
means a symlink staging farm: `ln -sf` each file into a lowercased
`staging/` tree, then `rsync -aL staging/ nas:/pub/`. The `-f` again
resolves collisions silently, and the farm must be rebuilt and cleaned
up around every run.

### Repartition into `YEAR/MM/` folders by modification time

```bash
set -o pipefail
syq map --srcs-in photos \
  | jq -c 'select(.kind == "file")
        | .dst.value = (.mtime | gmtime | strftime("%Y/%m")) + "/" + .dst.value' \
  | syq cp --mapping - -C photos --to nas --into /archive
```

The `select` keeps only file entries; the `2024/07/` directories no
entry names are created implicitly.

```text
photos/                          nas:/archive/ afterwards
├── IMG_1234.JPG   (July 2024)   ├── 2024/
├── IMG_8812.JPG   (Nov 2024)    │   ├── 07/IMG_1234.JPG
└── clip.mp4       (Jan 2025)    │   └── 11/IMG_8812.JPG
                                 └── 2025/
                                     └── 01/clip.mp4
```

The rsync equivalent is a hardlink farm maintained beside the photos
(`ln` each file into `farm/YEAR/MM/`, then `rsync -a farm/ nas:/archive/`),
which needs a writable staging tree on the same filesystem and its own
lifecycle (rebuild after changes, clean up after runs).

### Only files of at least 1 MiB

```bash
set -o pipefail
syq map --srcs-in data \
  | jq -c 'select(.kind != "file" or .size >= 1048576)' \
  | syq cp --mapping - -C data --to nas --into /big
```

rsync has a dedicated flag for this exact transform:
`rsync -a --min-size=1M data/ nas:/big/`. A few transforms of this
kind got rsync flags over the years (`--min-size`, `--iconv`); most,
like lowercasing or date partitioning, never did. As mapping
transforms they all have the same shape.

## Producing a mapping yourself

Any program that prints NDJSON can drive `syq cp --mapping`. The
common before/after: a rename copy done today as one `rsync` per file,

```sh
# before: serial, no conflict checking, last writer wins
while IFS=$'\t' read -r src dst; do
  rsync -a "photos/$src" "nas:/archive/$dst"
done < pairs.tsv
```

becomes a single parallel, resumable run whose conflicts are rejected
up front:

```sh
syq cp --mapping pairs.ndjson -C photos --to nas --into /archive
```

where `pairs.ndjson` is whatever your program emitted, one claim per
line:

```json
{"src":{"encoding":"utf-8","value":"IMG_1234.JPG"},"dst":{"encoding":"utf-8","value":"2024/07/berlin/IMG_1234.JPG"}}
{"src":{"encoding":"utf-8","value":"IMG_8812.JPG"},"dst":{"encoding":"utf-8","value":"2024/11/oslo/IMG_8812.JPG"}}
```

For the patterns people build today with hardlink or symlink staging
farms so that plain rsync can mirror a restructured tree, and where
those farms fall short, see [use-cases/link-farms.md](https://github.com/greaber/syq/blob/master/use-cases/link-farms.md).

## Semantics and limits

- `--mapping` replaces source selectors on `syq cp`; it composes with
  `-C`, `--to`, `--into` (and the other `--into-*` placement
  preconditions), `-n`, `-v`, `-q`, and `-j`. It conflicts with `--as`:
  an exact single-path placement cannot host a manifest, because each
  entry's `dst` already is its own `--as`. It exists in native mode
  only; `syq rsync` (rsync mode) is unchanged.
- `syq map` accepts the same local selectors as native `cp`, including the
  typed selectors `--src-file`/`--src-dir`, plus `--as PATH` (which emits the
  single selected path at `PATH`, honoring the whole path rather than only
  its last component). Those selectors are validated exactly as native `cp`
  validates them; see "Emitting a mapping" for the complete list.
- What is preserved follows the native default (the equivalent of rsync's
  `-rlt`). There is no per-entry setting: what is preserved and how files
  are compared stay the same for the whole run.
- An entry claims exactly one object. A `dir` entry claims the
  directory itself, without its contents.
- The command-line path naming a manifest, the `-C`/`--root` source base, and the
  `--into` placement are paths you typed on the command line. Native mode
  refuses to follow symlinks in them by default. `--follow-src` controls the
  source base, `--follow-dst` controls placement, and only the umbrella
  `--follow` also controls the path of the manifest itself. Paths inside the
  manifest are data and are not changed by any follow option. syq opens a
  named manifest once and reads all of it through that open handle before it
  writes anything at the destination, so renaming the manifest, or replacing
  a followed link, afterward cannot change what was read. `--mapping -` is the
  portable stream form. A directly named FIFO keeps its normal blocking-open
  behavior: on Linux with procfs, syq reopens exactly the handle it already
  holds; systems without that ability refuse a FIFO manifest before anything
  is written.
- When `syq map --follow-src` (or `--follow`) resolves a named selector that
  is a symlink, it emits the path of the link's target, relative to the
  source base, so the manifest can be executed without following any link.
  It refuses a target outside that base; pass the real path with a matching
  `-C` base instead. A contents selector (`--srcs-in`) with `--follow-src`
  still emits entries relative to the selected directory, as it does without
  the option, and the `syq cp` that consumes them must select the same base
  with the same source follow option.
- `syq map` opens its source base and each selected directory once and keeps
  that handle open for the whole run, so later work is relative to the handle
  and renaming the path cannot redirect it. Directory listing and metadata
  reads all go through that open handle, so a concurrent rename or symlink
  swap cannot change which tree is emitted. With `--follow-src`, a named
  selector's emitted `src` comes from the same step-by-step walk that opened
  the handle, not from a second `realpath` lookup.
- `-C` is only a base for resolving paths: selectors typed on the command line
  may contain `.` and `..` and may resolve outside it. `--root` is mutually
  exclusive with `-C` and keeps those selectors inside the selected root
  directory, whose open handle syq keeps for the whole run. A mapping emitted
  from a contents selector is relative to the selected directory, so the
  `syq cp` that consumes it must use that directory as its source base. These
  rules for command-line paths do not relax the strict manifest format
  described above.
- Symlinks selected by mapping entries are never resolved by mapping handling:
  a symlink maps as a symlink, and a destination path that would traverse a
  symlink inside the destination container fails that entry. Resolve links before
  emitting the manifest if you want the files they point to instead.
- `kind: "special"` asserts the source's type; it does not override the
  fixed `-rlt` preservation default, which copies no special files. Such an
  entry is excluded by rule, like a file under `--min-size`: the run still
  succeeds and the entry is only counted among the excluded files in the
  summary. Filter with `jq -c 'select(.kind != "special")'` to drop such
  entries up front.
- A mapping does not define a destination area to prune (there is no rule for
  which paths would count as destination-only), so `--mapping` cannot be
  combined with `--prune`.
- Duplicate lines are errors, even identical ones: a duplicate almost
  always means a generator bug. Deduplicate in your generator if you
  union overlapping fragments.
- `syq cp --mapping` reads and validates the whole manifest before
  copying anything: parse errors, duplicate destinations, and
  declared-kind ancestor conflicts refuse the run before any entry is
  applied (the `--into` container itself is created up front, as with
  `--files-from`). The price is memory proportional to the manifest, as
  in a multi-source copy. Sources are then inspected and planned in chunks, and transfers begin once planning completes.
  Conflicts that can only be seen during execution (an undeclared ancestor
  that turns out not to be a directory, or what already exists at the
  destination) still fail entries individually. `syq map` streams its
  output. Exit codes and output are the same as for any other `syq cp`.

## Machine-readable results

`syq cp` (with or without `--prune`) and `syq rm` both accept the same two
result-output options. `--results FILE` writes the results stream, an NDJSON
record of what the run did, to a freshly created file alongside the usual
human output. `--results-fd N` writes to a file descriptor you opened before running syq
instead (`--results-fd 3 3>r.ndjson`, or a pipe). The full contract (every
record type and field, the exit-code table, the JSON Schema, and example
streams) is [Automation results](automation.md). In brief: the stream
carries `schema_version: 1`: a `run` record (run id, mode, endpoints),
sampled `progress` records, one `operation_result` per finished change to
the destination, whether it succeeded or failed, and per failed mapping
entry (with `retryable`, and `class`/`os_kind` where known), `trace`
records instead of results under `--dry-run` (one per change a real run
would make, each with the reason), an `error` record per counted error,
and exactly one flushed terminal `result` whose numbers also render the
human summary. Unchanged and excluded entries appear only in the totals of
that terminal record, and metadata-only updates are not reported per
operation. A missing terminal record means the run did not finish; a
terminal status other than `success` or `partial` means some entries may
never have been resolved.

The results stream is always written on the machine you invoke syq from.
For a remote-to-remote copy through the restricted receiver (the
command-restricted receiver, a forced command on hostB that syq installs
when you enroll a destination), the stream is receiver-attested: built
from hostB's signed receipt rather than from what hostA reported, with
each record marked `"provenance":"receiver_attested"`, while the data
flows directly between the two hosts. Without an enrollment the run fails
unless `--coordinate-at local` explicitly routes the data through your
machine. `--results` cannot be combined with `--detach`, because the
caller would no longer be attached for the complete stream and its
terminal record. A named file is created fresh inside its parent
directory, which syq opens first and keeps open; an existing entry is
refused rather than truncated. With `--follow`, the handle syq keeps is
the link's resolved target, so replacing the link later cannot redirect
the output. Use an inherited `--results-fd` when the caller needs another
kind of output, such as a pipe or socket.

Failed operation records carry `src`, `dst`, and `kind`, so a retry
manifest is one filter away:

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

The jq program first checks the stream's terminal record: a results
file without one is from a run that did not finish (a crash, a kill),
and a terminal status other than `success` or `partial` (an `aborted`
incomplete receipt or a `refused` run) means queued entries were never
resolved or their receipt records may be missing. In both cases, entries
may have no records at all, so a retry manifest built from
what is there would look complete while it is not. With the
terminal record present, the filter is what an exit code cannot
express: which entries failed, and whether a retry could help.
