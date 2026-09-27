#!/usr/bin/env python3
"""Run every test-* entry point in tests/tooling, with live output."""
import argparse
from pathlib import Path
import sys

from tooling import ForwardSignals, ToolError, report_errors

ROOT = Path(__file__).resolve().parent.parent
INTERPRETERS = {".py": [sys.executable], ".sh": ["sh"], ".cjs": ["node", "--test"]}


def discover(directory):
    tests = sorted(path for path in directory.glob("test-*") if path.is_file())
    if not tests:
        raise ToolError(f"no tooling tests found in {directory}")
    for path in tests:
        if path.suffix not in INTERPRETERS:
            raise ToolError(f"unknown tooling test type: {path}")
    return tests


def run_tests(tests, root):
    children = ForwardSignals()
    failures = []
    for test in tests:
        print(f"Running {test.name}", flush=True)
        try:
            status, _ = children.run(*INTERPRETERS[test.suffix], str(test), cwd=root)
        except OSError as error:
            print(f"{test.name}: {error}", file=sys.stderr, flush=True)
            status = 1
        if status:
            failures.append(test.name)
        print(f"{test.name}: {'FAILED' if status else 'passed'}", flush=True)
    print(f"Tooling tests: {len(tests) - len(failures)} passed, {len(failures)} failed", flush=True)
    if failures:
        print("Failed: " + ", ".join(failures), file=sys.stderr, flush=True)
    return int(bool(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list discovered tests without running them")
    args = parser.parse_args()
    tests = discover(ROOT / "tests/tooling")
    if args.list:
        for test in tests:
            print(test.relative_to(ROOT))
        return 0
    return run_tests(tests, ROOT)


if __name__ == "__main__":
    sys.exit(report_errors(main))
