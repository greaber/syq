#!/usr/bin/env python3
"""Lint the macOS build on any host, without a macOS SDK.

Usage: scripts/check-macos-lint.py

Runs the macOS suite's first check, clippy on every Rust target with warnings
as errors, for aarch64-apple-darwin in the checkout containing the current
directory. Code gated to one platform, such as an import only Linux tests use,
fails here as it does on a macOS runner. Clippy compiles without linking, so C
and Objective-C sources are skipped: their warnings and every macOS test still
need the macOS suite.

Exit 0 when the lint passes, 1 when it fails, and 2 when it cannot run.
"""
import os
import shutil
import sys

from tooling import ForwardSignals, ToolError, output, report_errors

TARGET = "aarch64-apple-darwin"


def main():
    if sys.argv[1:]:
        print("usage: scripts/check-macos-lint.py", file=sys.stderr)
        return 2
    for tool in ("rustup", "cargo", "true"):
        if not shutil.which(tool):
            raise ToolError(f"the macOS lint needs {tool}", 2)
    children = ForwardSignals()
    # rust-toolchain.toml in this checkout selects the pinned toolchain.
    if TARGET not in output("rustup", "target", "list", "--installed", status=2).split():
        status, _ = children.run("rustup", "target", "add", TARGET)
        if status:
            raise ToolError(f"cannot add {TARGET} to the pinned Rust toolchain", 2)
    # Build scripts compile C for the target, which needs Apple's SDK. Checking
    # never links those objects, so a compiler that writes nothing suffices.
    environment = dict(os.environ)
    for variable in ("CC", "CXX", "AR"):
        for suffix in (TARGET, TARGET.replace("-", "_")):
            environment[f"{variable}_{suffix}"] = shutil.which("true")
    print(f"Linting every Rust target for {TARGET}", file=sys.stderr, flush=True)
    status, _ = children.run("cargo", "clippy", "--locked", "--all-targets", "--all-features",
                             "--target", TARGET, "--", "-D", "warnings", env=environment)
    return 1 if status else 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
