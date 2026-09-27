#!/usr/bin/env python3
"""Check that workflows and release instructions name scripts that exist.

Scans .github/workflows/*.yml, .agents/skills/, RELEASING.md, and
sdk/RELEASING.md for `scripts/...` paths. Every referenced file must be
tracked. A script run directly as a command in a workflow or a Markdown code
block, rather than through an interpreter such as `python3 scripts/x.py`, must
also be committed as executable with a `#!` line. Release workflows run only
at release time, so this catches a renamed or non-executable script before then.
"""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
REFERENCE = re.compile(r"(?<![\w./-])scripts/[\w./-]*[\w]")
# Text before a reference that makes it the command being run.
COMMAND_START = re.compile(r"(^|[;&|(!]|\b(?:then|do|if|run:|-))\s*$")
INTERPRETERS = re.compile(r"\b(?:python3?|bash|sh|-f|--script)\s+$")


def tracked_modes():
    listing = subprocess.run(["git", "ls-files", "-s", "--", "scripts"], cwd=ROOT, check=True,
                             stdout=subprocess.PIPE, text=True).stdout
    modes = {}
    for line in listing.splitlines():
        metadata, path = line.split("\t", 1)
        modes[path] = metadata.split()[0]
    return modes


def sources():
    paths = sorted(ROOT.glob(".github/workflows/*.yml"))
    paths += sorted(path for path in ROOT.glob(".agents/skills/**/*") if path.is_file())
    paths += [ROOT / "RELEASING.md", ROOT / "sdk/RELEASING.md"]
    return [path for path in paths if path.is_file()]


def main():
    modes = tracked_modes()
    problems = []
    checked = 0
    for source in sources():
        # Prose mentions scripts without running them; check only Markdown code blocks.
        in_code = source.suffix != ".md"
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if source.suffix == ".md" and line.lstrip().startswith("```"):
                in_code = not in_code
                continue
            for match in REFERENCE.finditer(line):
                path = match.group(0).rstrip(".")
                where = f"{source.relative_to(ROOT)}:{number}: {path}"
                checked += 1
                if path not in modes:
                    problems.append(f"{where} is not a tracked file")
                    continue
                before = line[:match.start()]
                if not in_code or INTERPRETERS.search(before) or not COMMAND_START.search(before):
                    continue
                if modes[path] != "100755":
                    problems.append(f"{where} is run directly but is not executable")
                with open(ROOT / path, "rb") as script:
                    if not script.readline().startswith(b"#!/"):
                        problems.append(f"{where} is run directly but has no #! line")
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"{checked} script references checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
