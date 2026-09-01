# Mappings: placement as data

A mapping is a file (or stream) of explicit source→target claims that
`syq cp` can execute: a generalized `--as` covering many entries at
once, or a `--files-from` whose entries can also *re-place* each file.
You author selection and placement — with a script, or by transforming
a mapping syq itself emits — and syq does what it always does:
parallel transfer, delta, resume, verification, and conflict checking
before a single byte moves.

```sh
syq map --src-src photos \
  | jq '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C photos --to nas --into /pub
```

rsync hardcodes single instances of this idea as flags (`--iconv` is a
filename transform; `-R` with `/./` anchors is a placement transform).
With a mapping, the transform is yours — any tool that can edit JSON
lines — and syq refuses case-fold collisions that a hand-rolled rename
loop would silently overwrite.

## The format

One JSON object per line (NDJSON):

```json
{"src": {"encoding": "utf-8", "value": "IMG_1234.JPG"},
 "dst": {"encoding": "utf-8", "value": "2024/07/img_1234.jpg"},
 "kind": "file", "size": 4194304, "mtime": 1721900000}
```

- `src`, `dst` (required): paths relative to the source root (`-C DIR`,
  default the working directory) and the target container (`--into
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

`syq map` takes the same selectors as `syq cp` and prints the resolved
selection and placement as a mapping instead of copying:

```sh
syq map --src-src photos          # contents of photos/, dst == src
syq map photos                    # named object: dst starts with photos/
```

Emission refuses names that are not valid UTF-8 (so published
one-line transforms are safe by construction); mappings you author
yourself may use the base64 form for such names.

## Transform in the middle

Because a mapping is plain data, the pipeline
`syq map … | <transform> | syq cp --mapping - …` covers, as one-liners,
things that otherwise need dedicated flags or custom copy scripts.
Re-running any of these converges like an ordinary syq copy: what
already landed is skipped.

### Lowercase every destination name

A migration to a case-insensitive filesystem:

```sh
syq map --src-src src \
  | jq '.dst.value |= ascii_downcase' \
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

rsync has no rename option, so its closest equivalent is a symlink
staging farm, dereferenced on the way out:

```sh
find src -type f | while read -r f; do
  d="staging/$(printf %s "${f#src/}" | tr '[:upper:]' '[:lower:]')"
  mkdir -p "$(dirname "$d")" && ln -sf "$(realpath "$f")" "$d"
done
rsync -aL staging/ nas:/pub/
```

— where `ln -sf` resolves the case-fold collision silently,
last writer wins, and the farm must be rebuilt and cleaned up around
every run.

### Repartition into `YEAR/MM/` folders by modification time

```sh
syq map --src-src photos \
  | jq 'select(.kind == "file")
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

```sh
syq map --src-src data \
  | jq 'select(.kind != "file" or .size >= 1048576)' \
  | syq cp --mapping - -C data --to nas --into /big
```

rsync spells this exact transform as a dedicated flag:
`rsync -a --min-size=1M data/ nas:/big/`. That is the pattern in
miniature: a few transforms earned rsync flags over the years
(`--min-size`, `--iconv`); most never will — there is no
`--lowercase` and no `--partition-by-date` — but as mapping transforms
they are all the same one-line shape.

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
those farms fall short — see [use-cases/link-farms.md](use-cases/link-farms.md).

## Semantics and limits

- `--mapping` replaces source selectors on `syq cp`; it composes with
  `-C`, `--to`, `--into` (and the other `--into-*` placement
  preconditions), `-n`, `-v`, `-q`, and `-j`. It is part of the native
  surface only; `syq rsync` is unchanged.
- Fidelity is the native default (`-rlt`). There is no per-entry
  policy: preservation and comparison behavior stay global.
- An entry claims exactly one object. A `dir` entry claims the
  directory itself, without its contents.
- Symlinks are never resolved in mapping handling: a symlink maps as a
  symlink, and a destination path that would traverse a symlink inside
  the target container fails that entry. Resolve links yourself before
  emitting if you want targets instead.
- Mappings define no deletion region, so `--mapping` is not available
  on `cp-prune`.
- Duplicate lines are errors, even identical ones: a duplicate almost
  always means a generator bug. Deduplicate in your generator if you
  union overlapping fragments.
- `syq map` streams as it scans, and `syq cp --mapping -` starts work
  before the stream ends; conflict checks are incremental. Exit codes
  and output are the ordinary `syq cp` ones.
