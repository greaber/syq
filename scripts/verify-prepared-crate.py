#!/usr/bin/env python3
"""Repack cheaply and compare against the package compiled in source-crate.
cargo publish --no-verify uses the same locked inputs after this check.

Usage: scripts/verify-prepared-crate.py vVERSION PREPARED_DIR
"""
import json
import os
import re
import subprocess
import sys


def output(*args):
    completed = subprocess.run(list(args), stdout=subprocess.PIPE, text=True)
    if completed.returncode:
        sys.exit(completed.returncode)
    return completed.stdout


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} vVERSION PREPARED_DIR", file=sys.stderr)
        return 2
    tag, prepared = sys.argv[1:]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        print(f"invalid release tag: {tag}", file=sys.stderr)
        return 2
    version = tag[1:]
    if output("git", "status", "--porcelain").rstrip("\n"):
        print("source package needs a clean checkout", file=sys.stderr)
        return 1
    metadata = json.loads(output("cargo", "metadata", "--locked", "--no-deps",
                                 "--format-version", "1"))
    versions = [package["version"] for package in metadata["packages"] if package["name"] == "syq"]
    if versions != [version]:
        print(f"Cargo metadata reports syq {', '.join(versions) or 'missing'}, not {version}",
              file=sys.stderr)
        return 1
    package = os.path.join(metadata["target_directory"], "package", f"syq-{version}.crate")
    validated = os.path.join(prepared, f"syq-{version}.crate")
    if not os.path.isfile(validated) or os.path.islink(validated):
        print(f"missing regular prepared crate: {validated}", file=sys.stderr)
        return 1
    if os.path.lexists(package):
        os.remove(package)
    packaged = subprocess.run(["cargo", "package", "--locked", "--no-verify"])
    if packaged.returncode:
        return packaged.returncode
    sys.stdout.flush()
    if subprocess.run(["cmp", validated, package]).returncode:
        print("source package differs from the validated artifact; refusing publication",
              file=sys.stderr)
        return 1
    print(f"Source package matches validated {tag} bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
