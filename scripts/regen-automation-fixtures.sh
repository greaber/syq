#!/usr/bin/env bash
# Regenerate the golden automation-v1 fixture streams from real syq runs.
#
# Normalization keeps regeneration deterministic so a diff shows only real
# API changes — fixture review is API review. Volatile identity fields
# (run_id, started_at, syq_version, elapsed_ms) get fixed values, and
# progress records are dropped with seq renumbered: whether a fast run
# emits its first sample before finishing is a race, and a stream with no
# progress records is itself a real possible stream. Requires jq.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
out="$repo/tests/fixtures/automation-v1"
cargo build --quiet --manifest-path "$repo/Cargo.toml"
syq="$repo/target/debug/syq"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

normalize() {
    jq -c -s '
        [ .[] | select(.type != "progress") ]
        | to_entries
        | .[]
        | .value.seq = .key
        | .value
        | if has("elapsed_ms") then .elapsed_ms = 0 else . end
        | if .type == "run" then
            .run_id = "6465616462656566000000000000cafe"
            | .started_at = 1756800000
            | .syq_version = "0.0.0"
          else . end
    '
}

mkdir -p "$out"

mapping_manifest='{"src":{"encoding":"utf-8","value":"Berlin"},"dst":{"encoding":"utf-8","value":"berlin"},"kind":"dir"}
{"src":{"encoding":"utf-8","value":"Berlin/IMG.JPG"},"dst":{"encoding":"utf-8","value":"berlin/2024/07/img.jpg"},"kind":"file"}
{"src":{"encoding":"utf-8","value":"Notes.TXT"},"dst":{"encoding":"utf-8","value":"notes.txt"},"kind":"file"}'

# success: a mapping run renaming into a dated layout (shows src fields,
# tagged paths, directory creation). Exit 0.
dir="$work/success"
mkdir -p "$dir/src/Berlin"
printf 'img' >"$dir/src/Berlin/IMG.JPG"
printf 'hello' >"$dir/src/Notes.TXT"
(cd "$dir" && printf '%s\n' "$mapping_manifest" |
    "$syq" cp -j1 -C src --mapping - --into dst --results raw.ndjson -q)
normalize <"$dir/raw.ndjson" >"$out/success.ndjson"

# partial: one mapping entry's source is missing; the rest settle. Exit 23.
dir="$work/partial"
mkdir -p "$dir/src"
printf 'ok' >"$dir/src/present.txt"
(cd "$dir" && printf '%s\n' \
    '{"src":{"encoding":"utf-8","value":"present.txt"},"dst":{"encoding":"utf-8","value":"present.txt"},"kind":"file"}' \
    '{"src":{"encoding":"utf-8","value":"missing.txt"},"dst":{"encoding":"utf-8","value":"missing.txt"},"kind":"file"}' |
    "$syq" cp -j1 -C src --mapping - --into dst --results raw.ndjson -q) || true
normalize <"$dir/raw.ndjson" >"$out/partial.ndjson"

# dry-run: the success scenario against a stale destination, emitting
# traces (destination_missing, content_differs) instead of results. Exit 0.
dir="$work/dry-run"
mkdir -p "$dir/src/Berlin" "$dir/dst/berlin/2024/07"
printf 'img' >"$dir/src/Berlin/IMG.JPG"
printf 'hello' >"$dir/src/Notes.TXT"
printf 'stale' >"$dir/dst/berlin/2024/07/img.jpg"
# Pin mtimes on both sides: whether the pre-created destination directory
# matches the source's timestamp is otherwise a sub-second race, and the
# guaranteed mismatch keeps a metadata_differs trace in the fixture.
find "$dir/src" -exec touch -h -d '2024-07-01T12:00:00Z' {} +
find "$dir/dst" -exec touch -h -d '2024-01-01T00:00:00Z' {} +
(cd "$dir" && printf '%s\n' "$mapping_manifest" |
    "$syq" cp -j1 -C src --mapping - --into dst -n --results raw.ndjson -q)
normalize <"$dir/raw.ndjson" >"$out/dry-run.ndjson"

# refused: --prune finds more destination-only entries than --max-delete
# allows; deletions are blocked, nothing is removed. Exit 25.
dir="$work/refused"
mkdir -p "$dir/src" "$dir/dst"
printf 'k' >"$dir/src/keep.txt"
printf 'k' >"$dir/dst/keep.txt"
printf 'x' >"$dir/dst/extra-1.txt"
printf 'x' >"$dir/dst/extra-2.txt"
(cd "$dir" &&
    "$syq" cp -j1 --prune --max-delete 1 --src-src src --into dst \
        --results raw.ndjson -q) || true
normalize <"$dir/raw.ndjson" >"$out/refused.ndjson"

# failed: the source does not exist; a fatal setup failure still emits the
# terminal record. Exit 1.
dir="$work/failed"
mkdir -p "$dir"
(cd "$dir" &&
    "$syq" cp -j1 --src-src missing --into dst --results raw.ndjson -q) || true
normalize <"$dir/raw.ndjson" >"$out/failed.ndjson"

# rm-success: one directory tree is removed and one explicit selector is
# already missing. Both selector occurrences remain visible. Exit 0.
dir="$work/rm-success"
mkdir -p "$dir/tree/sub"
printf 'remove' >"$dir/tree/sub/file"
(cd "$dir" &&
    "$syq" rm -j1 --src-dir tree --src missing --results raw.ndjson -q)
normalize <"$dir/raw.ndjson" >"$out/rm-success.ndjson"

# rm-dry-run: removal traces describe every intended mutation and no object is
# changed. Exit 0.
dir="$work/rm-dry-run"
mkdir -p "$dir/tree/sub"
printf 'keep' >"$dir/tree/sub/file"
(cd "$dir" &&
    "$syq" rm -j1 -n --src-dir tree --results raw.ndjson -q)
normalize <"$dir/raw.ndjson" >"$out/rm-dry-run.ndjson"

# rm-dry-partial: preview can resolve the selected root but cannot inspect one
# descendant, so it reports a failed per-path result alongside the incomplete
# plan. Exit 23.
dir="$work/rm-dry-partial"
mkdir -p "$dir/tree/blocked"
chmod 000 "$dir/tree/blocked"
(cd "$dir" &&
    "$syq" rm -j1 -n --src-src tree --results raw.ndjson -q) || true
chmod 700 "$dir/tree/blocked"
normalize <"$dir/raw.ndjson" >"$out/rm-dry-partial.ndjson"

# rm-partial: the selected directory can be read but neither its child nor the
# resulting non-empty parent can be removed. Each entry is reported once. Exit 23.
dir="$work/rm-partial"
mkdir -p "$dir/tree"
printf 'blocked' >"$dir/tree/file"
chmod 500 "$dir/tree"
(cd "$dir" &&
    "$syq" rm -j1 --src-dir tree --results raw.ndjson -q) || true
chmod 700 "$dir/tree"
normalize <"$dir/raw.ndjson" >"$out/rm-partial.ndjson"

# rm-failed: a fatal base-resolution failure still settles the stream. Exit 1.
dir="$work/rm-failed"
mkdir -p "$dir"
(cd "$dir" &&
    "$syq" rm -j1 --cwd missing --src victim --results raw.ndjson -q) || true
normalize <"$dir/raw.ndjson" >"$out/rm-failed.ndjson"

echo "regenerated $(ls "$out" | wc -l) fixtures in $out"
