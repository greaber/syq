#!/usr/bin/env python3
"""Check relative Markdown links and heading anchors in the user-facing docs.

Covers README.md and docs/**/*.md. A relative link must point at an existing
file, its #fragment must match a heading in the target, and a link from the
packaged documentation must stay inside the crate package (README.md,
LICENSE, docs/, src/, tests/) so the published crate has no dangling links.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
PACKAGED_DIRS = {"docs", "src", "tests"}
PACKAGED_FILES = {"README.md", "LICENSE", "Cargo.toml", "Cargo.lock", "build.rs"}
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
FENCE = re.compile(r"```.*?```", re.S)


def anchors(text):
    out = set()
    for line in text.splitlines():
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if not m:
            continue
        heading = re.sub(r"`", "", m.group(2).strip()).lower()
        heading = re.sub(r"[^\w\- ]", "", heading).replace(" ", "-")
        out.add(heading)
    return out


def main():
    problems = 0
    for path in FILES:
        text = path.read_text()
        for m in LINK.finditer(FENCE.sub("", text)):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            file_part, _, fragment = target.partition("#")
            resolved = path if file_part == "" else (path.parent / file_part).resolve()
            rel = path.relative_to(ROOT)
            if not resolved.exists():
                print(f"{rel}: missing target {target}")
                problems += 1
                continue
            parts = resolved.relative_to(ROOT).parts
            if parts[0] not in PACKAGED_DIRS and parts[0] not in PACKAGED_FILES:
                print(f"{rel}: link leaves the crate package: {target}")
                problems += 1
            if fragment and resolved.suffix == ".md" and fragment not in anchors(resolved.read_text()):
                print(f"{rel}: missing anchor {target}")
                problems += 1
    print(f"checked {len(FILES)} files; {problems} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
