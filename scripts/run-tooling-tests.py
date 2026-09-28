#!/usr/bin/env python3
"""Run tooling tests and the rsync harness; --quick selects the cheap default checks."""
import argparse
import os
from pathlib import Path
import sys
import time

from tooling import ForwardSignals, ToolError, report_errors

ROOT = Path(__file__).resolve().parent.parent
INTERPRETERS = {".py": [sys.executable], ".sh": ["sh"], ".cjs": ["node", "--test"]}

# Explicit membership keeps new build/network/slow tests out of the cheap default.
# Aim for 30 seconds total with pinned tools already installed. Re-measure before
# adding tests; the budget guides selection, never skips tests during a run.
QUICK_TESTS = (
    "tests/tooling/test-doc-selector.cjs",
    "tests/tooling/test-doc-site.py",
    "tests/tooling/test-find-release-build.py",
    "tests/tooling/test-generated-sdk-post-merge-ci.py",
    "tests/tooling/test-installer.py",
    "tests/tooling/test-nightly-ci.py",
    "tests/tooling/test-python-sdk-release-tools.py",
    "tests/tooling/test-release-readiness.py",
    "tests/tooling/test-release-test-inputs.py",
    "tests/tooling/test-release-timings.py",
    "tests/tooling/test-run-focused-check.py",
    "tests/tooling/test-setup.sh",
    "tests/tooling/test-tool-examples.py",
    "tests/tooling/test-tooling-discovery.py",
    "tests/tooling/test-tooling.py",
    "tests/rsync-compat/harness_test.py",
)
HARNESS = Path("tests/rsync-compat/harness_test.py")


def discover(directory):
    tests = sorted(path for path in directory.glob("test-*") if path.is_file())
    if not tests:
        raise ToolError(f"no tooling tests found in {directory}")
    for path in tests:
        if path.suffix not in INTERPRETERS:
            raise ToolError(f"unknown tooling test type: {path}")
    return tests


def select_tests(root, quick=False):
    tests = discover(root / "tests/tooling") + [root / HARNESS]
    if quick:
        selected = [root / path for path in QUICK_TESTS]
        unknown = set(selected) - set(tests)
        if unknown:
            raise ToolError("quick tests are not in the full suite: " +
                            ", ".join(str(path) for path in sorted(unknown)))
        tests = selected
    for test in tests:
        if not test.is_file():
            raise ToolError(f"test not found: {test}")
    return tests


def run_tests(tests, root):
    # Tests launch many short-lived Python processes. Keep their import cache
    # enabled and inside ignored target/, independent of the caller's shell.
    env = dict(os.environ, PYTHONPYCACHEPREFIX=str((root / "target/python-cache").resolve()))
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    children = ForwardSignals()
    failures = []
    started = time.monotonic()
    for test in tests:
        print(f"Running {test.name}", flush=True)
        test_started = time.monotonic()
        try:
            status, _ = children.run(*INTERPRETERS[test.suffix], str(test), cwd=root, env=env)
        except OSError as error:
            print(f"{test.name}: {error}", file=sys.stderr, flush=True)
            status = 1
        if status:
            failures.append(test.name)
        print(f"{test.name}: {'FAILED' if status else 'passed'} "
              f"({time.monotonic() - test_started:.2f}s)", flush=True)
    print(f"Tooling tests: {len(tests) - len(failures)} passed, {len(failures)} failed "
          f"in {time.monotonic() - started:.2f}s", flush=True)
    if failures:
        print("Failed: " + ", ".join(failures), file=sys.stderr, flush=True)
    return int(bool(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list discovered tests without running them")
    parser.add_argument("--quick", action="store_true",
                        help="run the measured cheap group (no builds or external services)")
    args = parser.parse_args()
    tests = select_tests(ROOT, quick=args.quick)
    if args.list:
        for test in tests:
            print(test.relative_to(ROOT))
        return 0
    return run_tests(tests, ROOT)


if __name__ == "__main__":
    sys.exit(report_errors(main))
