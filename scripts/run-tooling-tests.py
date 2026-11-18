#!/usr/bin/env python3
"""Run tooling tests and the rsync harness; --quick selects the cheap default checks
and --group the tests of the named groups that scripts/ci-scope.py selects."""
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
    "tests/tooling/test-branch-status.py",
    "tests/tooling/test-dispatched-checks-status.py",
    "tests/tooling/test-doc-selector.cjs",
    "tests/tooling/test-doc-site.py",
    "tests/tooling/test-doc-tools.py",
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
    "tests/tooling/test-rust-test-timeouts.py",
    "tests/tooling/test-tool-examples.py",
    "tests/tooling/test-tooling-discovery.py",
    "tests/tooling/test-tooling.py",
    "tests/rsync-compat/harness_test.py",
)
HARNESS = Path("tests/rsync-compat/harness_test.py")
# The groups scripts/ci-scope.py selects by changed path. Every test in
# tests/tooling belongs to one, so selecting all groups runs all of them.
GROUPS = {
    "package": ("test-cargo-package.py",),
    "installer": ("test-installer.py",),
    "benchmark": ("test-benchmark-concurrency.py", "test-try-benchmark.py"),
    "release": ("test-python-sdk-release-tools.py", "test-release-tools.py"),
    "orchestration": ("test-find-release-build.py", "test-generated-sdk-post-merge-ci.py",
                      "test-nightly-ci.py", "test-release-orchestration.py",
                      "test-release-readiness.py", "test-release-test-inputs.py",
                      "test-release-timings.py", "test-tooling-discovery.py", "test-tooling.py"),
    "focused": ("test-run-focused-check.py",),
    "branch": ("test-agent-coordination.py", "test-branch-status.py",
               "test-dispatched-checks-status.py"),
    # ci.yml also checks workflow syntax and script references for this group.
    "workflows": ("test-doc-selector.cjs", "test-doc-site.py", "test-doc-tools.py",
                  "test-tool-examples.py"),
    "setup": ("test-rust-test-timeouts.py", "test-setup.sh"),
}


def discover(directory):
    tests = sorted(path for path in directory.glob("test-*") if path.is_file())
    if not tests:
        raise ToolError(f"no tooling tests found in {directory}")
    for path in tests:
        if path.suffix not in INTERPRETERS:
            raise ToolError(f"unknown tooling test type: {path}")
    return tests


def select_tests(root, quick=False, groups=()):
    tooling = discover(root / "tests/tooling")
    tests = tooling + [root / HARNESS]
    if groups:
        unknown = [name for name in groups if name not in GROUPS]
        if unknown:
            raise ToolError(f"unknown group: {' '.join(unknown)} (choose from {' '.join(GROUPS)})")
        selected = {root / "tests/tooling" / name for group in groups for name in GROUPS[group]}
        # Discovery order: test-cargo-package.py builds the syq that ci.yml passes
        # to test-release-tools.py.
        tests = [test for test in tooling if test in selected]
    elif quick:
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
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--quick", action="store_true",
                           help="run the measured cheap group (no builds or external services)")
    selection.add_argument("--group", nargs="+", default=[], metavar="NAME",
                           help=f"run the tests of these groups: {' '.join(GROUPS)}")
    args = parser.parse_args()
    tests = select_tests(ROOT, quick=args.quick, groups=args.group)
    if args.list:
        for test in tests:
            print(test.relative_to(ROOT))
        return 0
    return run_tests(tests, ROOT)


if __name__ == "__main__":
    sys.exit(report_errors(main))
