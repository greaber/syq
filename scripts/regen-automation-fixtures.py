#!/usr/bin/env python3
"""Regenerate the golden automation fixture streams from real syq runs.

Normalization keeps regeneration deterministic so a diff shows only real
API changes — fixture review is API review. Volatile identity and timing
fields (run_id, started_at, syq_version, elapsed_ms, copying_elapsed_ms)
get fixed values, and progress records are dropped with seq renumbered:
whether a fast run emits its first sample before finishing is a race, and a
stream with no progress records is itself a real possible stream.
"""
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


REPOSITORY = Path(os.path.abspath(__file__)).parent.parent
OUT = REPOSITORY / "tests/fixtures/automation"
SYQ = REPOSITORY / "target/debug/syq"

MAPPING_MANIFEST = "\n".join([
    '{"src":{"encoding":"utf-8","value":"Berlin"},"dst":{"encoding":"utf-8","value":"berlin"},'
    '"kind":"dir"}',
    '{"src":{"encoding":"utf-8","value":"Berlin/IMG.JPG"},"dst":{"encoding":"utf-8",'
    '"value":"berlin/2024/07/img.jpg"},"kind":"file"}',
    '{"src":{"encoding":"utf-8","value":"Notes.TXT"},"dst":{"encoding":"utf-8",'
    '"value":"notes.txt"},"kind":"file"}',
]) + "\n"


def normalize(raw, fixture):
    records = [json.loads(line) for line in Path(raw).read_text(encoding="utf-8").splitlines()
               if line.strip()]
    output = []
    for seq, record in enumerate(record for record in records if record.get("type") != "progress"):
        record["seq"] = seq
        for field in ("elapsed_ms", "copying_elapsed_ms"):
            if field in record:
                record[field] = 0
        if record.get("type") == "run":
            record["run_id"] = "6465616462656566000000000000cafe"
            record["started_at"] = 1756800000
            record["syq_version"] = "0.0.0"
        output.append(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
    (OUT / fixture).write_text("".join(output), encoding="utf-8")


def syq(directory, *args, stdin="", check=True):
    completed = subprocess.run([str(SYQ), *args], cwd=directory, input=stdin, text=True)
    if check and completed.returncode:
        sys.exit(completed.returncode)


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def touch_tree(root, stamp):
    """`find ROOT -exec touch -h -d STAMP {} +`."""
    seconds = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    paths = [root]
    for directory, names, files in os.walk(root):
        paths += [os.path.join(directory, name) for name in names + files]
    for path in paths:
        os.utime(path, (seconds, seconds), follow_symlinks=False)


def main():
    subprocess.run(["cargo", "build", "--quiet", "--manifest-path", str(REPOSITORY / "Cargo.toml")],
                   check=True)
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)

        # success: a mapping run renaming into a dated layout (shows src fields,
        # tagged paths, directory creation). Exit 0.
        directory = work / "success"
        write(directory / "src/Berlin/IMG.JPG", "img")
        write(directory / "src/Notes.TXT", "hello")
        syq(directory, "cp", "--performance-tuning", "workers=1", "-C", "src", "--mapping", "-",
            "--into", "dst", "--results", "raw.ndjson", "-q", stdin=MAPPING_MANIFEST)
        normalize(directory / "raw.ndjson", "success.ndjson")

        # partial: one mapping entry's source is missing; the rest settle. Exit 23.
        directory = work / "partial"
        write(directory / "src/present.txt", "ok")
        syq(directory, "cp", "--performance-tuning", "workers=1", "-C", "src", "--mapping", "-",
            "--into", "dst", "--results", "raw.ndjson", "-q", check=False, stdin=(
                '{"src":{"encoding":"utf-8","value":"present.txt"},"dst":{"encoding":"utf-8",'
                '"value":"present.txt"},"kind":"file"}\n'
                '{"src":{"encoding":"utf-8","value":"missing.txt"},"dst":{"encoding":"utf-8",'
                '"value":"missing.txt"},"kind":"file"}\n'))
        normalize(directory / "raw.ndjson", "partial.ndjson")

        # dry-run: the success scenario against a stale destination, emitting
        # traces (destination_missing, content_differs) instead of results. Exit 0.
        directory = work / "dry-run"
        write(directory / "src/Berlin/IMG.JPG", "img")
        write(directory / "src/Notes.TXT", "hello")
        write(directory / "dst/berlin/2024/07/img.jpg", "stale")
        # Pin mtimes on both sides: whether the pre-created destination directory
        # matches the source's timestamp is otherwise a sub-second race, and the
        # guaranteed mismatch keeps a metadata_differs trace in the fixture.
        touch_tree(directory / "src", "2024-07-01T12:00:00Z")
        touch_tree(directory / "dst", "2024-01-01T00:00:00Z")
        syq(directory, "cp", "--performance-tuning", "workers=1", "-C", "src", "--mapping", "-",
            "--into", "dst", "-n", "--results", "raw.ndjson", "-q", stdin=MAPPING_MANIFEST)
        normalize(directory / "raw.ndjson", "dry-run.ndjson")

        # refused: --prune finds more destination-only entries than --max-delete
        # allows; deletions are blocked, nothing is removed. Exit 25.
        directory = work / "refused"
        write(directory / "src/keep.txt", "k")
        write(directory / "dst/keep.txt", "k")
        write(directory / "dst/extra-1.txt", "x")
        write(directory / "dst/extra-2.txt", "x")
        syq(directory, "cp", "--performance-tuning", "workers=1", "--prune", "--max-delete", "1",
            "--srcs-in", "src", "--into", "dst", "--results", "raw.ndjson", "-q", check=False)
        normalize(directory / "raw.ndjson", "refused.ndjson")

        # failed: the source does not exist; a fatal setup failure still emits the
        # terminal record. Exit 1.
        directory = work / "failed"
        directory.mkdir()
        syq(directory, "cp", "--performance-tuning", "workers=1", "--srcs-in", "missing",
            "--into", "dst", "--results", "raw.ndjson", "-q", check=False)
        normalize(directory / "raw.ndjson", "failed.ndjson")

        # rm-success: one directory tree is removed and one explicit selector is
        # already missing. Both selector occurrences remain visible. Exit 0.
        directory = work / "rm-success"
        write(directory / "tree/sub/file", "remove")
        syq(directory, "rm", "--performance-tuning", "workers=1", "--src-dir", "tree", "--src",
            "missing", "--results", "raw.ndjson", "-q")
        normalize(directory / "raw.ndjson", "rm-success.ndjson")

        # rm-dry-run: removal traces describe every intended mutation and no object is
        # changed. Exit 0.
        directory = work / "rm-dry-run"
        write(directory / "tree/sub/file", "keep")
        syq(directory, "rm", "--performance-tuning", "workers=1", "-n", "--src-dir", "tree",
            "--results", "raw.ndjson", "-q")
        normalize(directory / "raw.ndjson", "rm-dry-run.ndjson")

        # rm-dry-partial: preview can resolve the selected root but cannot inspect one
        # descendant, so it reports a failed per-path result alongside the incomplete
        # plan. Exit 23.
        directory = work / "rm-dry-partial"
        (directory / "tree/blocked").mkdir(parents=True)
        os.chmod(directory / "tree/blocked", 0o000)
        syq(directory, "rm", "--performance-tuning", "workers=1", "-n", "--srcs-in", "tree",
            "--results", "raw.ndjson", "-q", check=False)
        os.chmod(directory / "tree/blocked", 0o700)
        normalize(directory / "raw.ndjson", "rm-dry-partial.ndjson")

        # rm-partial: the selected directory can be read but neither its child nor the
        # resulting non-empty parent can be removed. Each entry is reported once. Exit 23.
        directory = work / "rm-partial"
        write(directory / "tree/file", "blocked")
        os.chmod(directory / "tree", 0o500)
        syq(directory, "rm", "--performance-tuning", "workers=1", "--src-dir", "tree",
            "--results", "raw.ndjson", "-q", check=False)
        os.chmod(directory / "tree", 0o700)
        normalize(directory / "raw.ndjson", "rm-partial.ndjson")

        # rm-failed: a fatal base-resolution failure still settles the stream. Exit 1.
        directory = work / "rm-failed"
        directory.mkdir()
        syq(directory, "rm", "--performance-tuning", "workers=1", "--cwd", "missing", "--src",
            "victim", "--results", "raw.ndjson", "-q", check=False)
        normalize(directory / "raw.ndjson", "rm-failed.ndjson")

    count = sum(1 for name in os.listdir(OUT) if not name.startswith("."))
    print(f"regenerated {count} fixtures in {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
