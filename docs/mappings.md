# Mappings: placement as data

A mapping is a file (or stream) of explicit source→destination claims that
`syq cp` can execute: a generalized `--as` covering many entries at
once, or a `--files-from` whose entries can also *re-place* each file.
You author selection and placement — with a script, or by transforming
a mapping syq itself emits — and syq does what it always does:
parallel transfer, delta, resume, verification, and conflict checking
before a single byte moves.

```bash
set -o pipefail
syq map --src-src photos \
  | jq -c '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C photos --to nas --into /pub
```

rsync hardcodes single instances of this idea as flags (`--iconv` is a
filename transform; `-R` with `/./` anchors is a placement transform).
With a mapping, any tool that can edit JSON lines can do the
transform, and syq refuses case-fold collisions that a hand-rolled
rename loop would silently overwrite.

## The format

One JSON object per line (NDJSON):

```json
{"src": {"encoding": "utf-8", "value": "IMG_1234.JPG"},
 "dst": {"encoding": "utf-8", "value": "2024/07/img_1234.jpg"},
 "kind": "file", "size": 4194304, "mtime": 1721900000}
```

- `src`, `dst` (required): paths relative to the source root (`-C DIR`,
  default the working directory) and the destination container (`--into
  DIR`). Absolute paths, empty paths, and any `.` or `..` component are
  rejected. Paths are tagged: `encoding` is `utf-8`, or `base64` for a
  name that is not valid UTF-8 (`value` is then standard base64 of the
  raw bytes).
- `kind` (optional): `file`, `dir`, `symlink`, or `special`. This
  disambiguates the request — mapping a file and mapping a directory
  (non-recursively; entries are never recursive) are different
  operations. If the object at `src` is not the declared kind, that
  entry fails, exactly as if `src` did not exist. Without `kind`, the
  entry maps whatever is there.
- `size`, `mtime` (optional, informational): emitted by `syq map` for
  transforms to filter on; execution ignores them. Unknown keys are
  rejected, so a typo cannot be silently dropped.

Duplicate destinations, and a destination claimed both as a file and as
a directory ancestor of another entry, are conflicts — detected before
any transfer begins, across the entire manifest. Destination ancestor
directories no entry names are created implicitly, as with
`--files-from`.

## Emitting a mapping

`syq map` takes the same local selectors as `syq cp` and prints the resolved
selection as a mapping instead of copying:

```sh
syq map --src-src photos          # contents of photos/, dst == src
syq map photos                    # named object: dst starts with photos/
```

Emission refuses names that are not valid UTF-8 (so published
one-line transforms are safe by construction); mappings you author
yourself may use the base64 form for such names.

`syq map` deliberately has a destination-independent surface: `-C`,
`--follow-src`/`--follow`, the source-selector family, and `--as`. It takes
either `--src-src DIR` as the only selector or any number of relative named
selectors. `--as` renames the single selected root. Destination, filtering,
transfer, execution, result, receiver-ceiling, and receipt options belong to
the later `syq cp --mapping` invocation or to a manifest transform, not to
`syq map`.

## Transform in the middle

Because a mapping is plain data, the pipeline
`syq map … | <transform> | syq cp --mapping - …` covers, as one-liners,
things that otherwise need dedicated flags or custom copy scripts.
Re-running any of these converges like an ordinary syq copy: what
already landed is skipped.

As in any shell pipeline, `syq cp` sees only the bytes that reach it:
the examples set `set -o pipefail` (Bash) so a failed producer fails
the pipeline. Nothing wrong is copied either way — a truncated
manifest copies only a valid prefix, and re-running the corrected
pipeline converges. For stage-by-stage completion, materialize the
manifest instead:

```bash
set -o pipefail
syq map --src-src src | jq -c '.dst.value |= ascii_downcase' > m.ndjson \
  && syq cp --mapping m.ndjson -C src --to nas --into /pub
```

### Lowercase every destination name

A migration to a case-insensitive filesystem:

```bash
set -o pipefail
syq map --src-src src \
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
  in-tree link does not follow the rename — harmless here because the
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
syq map --src-src photos \
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

The rsync equivalent is a hardlink farm maintained beside the photos —
`ln` each file into `farm/YEAR/MM/`, `rsync -a farm/ nas:/archive/` —
which needs a writable staging tree on the same filesystem and its own
lifecycle (rebuild after changes, clean up after runs).

### Only files of at least 1 MiB

```bash
set -o pipefail
syq map --src-src data \
  | jq -c 'select(.kind != "file" or .size >= 1048576)' \
  | syq cp --mapping - -C data --to nas --into /big
```

rsync has a dedicated flag for this exact transform:
`rsync -a --min-size=1M data/ nas:/big/`. A few transforms of this
kind got rsync flags over the years (`--min-size`, `--iconv`); most,
like lowercasing or date partitioning, never did. As mapping
transforms they all have the same shape.

## Producing a mapping yourself

Any program that prints JSON lines can drive `syq cp --mapping`. The
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
farms so that plain rsync can mirror a restructured tree — and where
those farms fall short — see [use-cases/link-farms.md](https://github.com/greaber/syq/blob/master/use-cases/link-farms.md).

## Semantics and limits

- `--mapping` replaces source selectors on `syq cp`; it composes with
  `-C`, `--to`, `--into` (and the other `--into-*` placement
  preconditions), `-n`, `-v`, `-q`, and `-j`. It conflicts with `--as`:
  an exact single-path placement cannot host a manifest — each entry's
  `dst` already is its own `--as`. It is part of the native surface
  only; `syq rsync` is unchanged.
- `syq map` accepts the local selector grammar, including the typed selectors
  `--src-file`/`--src-dir`, plus `--as PATH` (which emits the single selected
  root under the destination's basename). Those selectors are validated exactly as
  native `cp` validates them; see "Emitting a mapping" for the complete
  surface.
- Fidelity is the native default (`-rlt`). There is no per-entry
  policy: preservation and comparison behavior stay global.
- An entry claims exactly one object. A `dir` entry claims the
  directory itself, without its contents.
- The command-line path naming a manifest, the `-C` source base, and the
  `--into` placement are directly supplied paths. Native mode refuses to
  traverse symlinks in them by default. `--follow-src` controls the source
  base, `--follow-dest` controls placement, and only the `--follow` umbrella
  also controls the coordinator-local manifest path. Paths inside the manifest
  are data and are not changed by any follow option. A named manifest is read
  from the identity retained by that resolution, and all its bytes are acquired
  before destination mutation; replacing its pathname or a followed link
  afterward cannot redirect the read. `--mapping -` is the portable stream
  form. A directly named FIFO preserves blocking-open behavior through an exact
  retained-descriptor reopen on Linux with procfs; systems without that
  primitive refuse it before destination mutation.
- When `syq map --follow-src` (or `--follow`) resolves a named selector, it
  emits the referent's source-base-relative path so the manifest remains
  executable without link traversal. It refuses a referent outside that base;
  pass the real path with a matching `-C` base instead. A followed contents
  selector keeps ordinary contents-relative entries and requires the consumer
  to select the same base with the same source follow option.
- Symlinks selected by mapping entries are never resolved by mapping handling:
  a symlink maps as a symlink, and a destination path that would traverse a
  symlink inside the destination container fails that entry. Resolve links before
  emitting the manifest if you want targets instead.
- `kind: "special"` asserts the source's type; it does not override the
  fixed `-rlt` fidelity, which copies no special files. Such an entry is
  a policy exclusion like `--min-size`: the run still succeeds and the
  entry appears only in the excluded aggregate. Filter with
  `jq -c 'select(.kind != "special")'` to drop such entries up front.
- Mappings define no deletion region, so `--mapping` cannot be combined
  with `--prune`.
- Duplicate lines are errors, even identical ones: a duplicate almost
  always means a generator bug. Deduplicate in your generator if you
  union overlapping fragments.
- `syq cp --mapping` reads and validates the whole manifest before
  copying anything: parse errors, duplicate destinations, and
  declared-kind ancestor conflicts refuse the run before any entry is
  applied (the `--into` container itself is created eagerly, as with
  `--files-from`). The price is memory proportional to the manifest, as
  in a multi-source copy. Sources are then statted and planned in chunks, and transfers begin once planning completes.
  Conflicts only observable at execution — an undeclared ancestor that
  turns out not to be a directory, existing destination state — still
  fail entries individually. `syq map` streams its output. Exit codes
  and output are the ordinary `syq cp` ones.

## Machine-readable results

`syq cp --results FILE` (with or without `--prune`) writes an NDJSON
outcome stream to a freshly created file, alongside the ordinary human
output; `--results-fd N` writes to a caller-opened descriptor instead
(`--results-fd 3 3>r.ndjson`, or a pipe). The
full contract — every record type and field, the exit-code table,
the JSON Schema, and example streams — is
[Automation results](automation-v1.md). In brief: the
stream carries `schema_version: 1`: a `run` record (run id, mode,
endpoints), sampled `progress` records, one `operation_result` per
settled mutation and per failed mapping entry (with `retryable`, and
`class`/`os_kind` where known), `trace` records instead of results
under `--dry-run` (each with the reason a mutation is planned), an
`error` record per counted error, and exactly one flushed terminal
`result` whose numbers also render the human summary. Unchanged and
excluded entries appear only in the terminal aggregates, and
metadata-only updates are not reported per operation. A missing
terminal record means the run did not finish; a terminal status other
than `success` or `partial` means entries may be unsettled.

The results writer lives with the transfer coordinator, so a stream
requires a local coordinator (an explicit `--coordinate-at local` for a
remote-to-remote copy). `--results` cannot be combined with `--detach`,
because the caller would no longer be attached for the complete stream
and its terminal record. Receiver-attested streams for attached direct
copies through a command-restricted receiver — records verified and
decrypted from hostB's receipt, marked `"provenance":"receiver_attested"`
— exist in the engine and return once wired to the file/descriptor
outputs. A named file is created fresh beneath its retained parent; an existing
entry is refused rather than truncated. With `--follow`, that retained
selection is the resolved referent, so replacing the link later cannot redirect
the output. Use an inherited `--results-fd` when the caller needs another kind
of sink.

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
settled or their receipt records may be missing. In both cases, entries
may have no records at all, so a retry manifest built from
what is there would look complete while it is not. With the
terminal record present, the filter is what an exit code cannot
express: which entries failed, and whether a retry could help.
