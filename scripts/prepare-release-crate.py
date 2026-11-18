#!/usr/bin/env python3
"""Compile the registry package before any permanent release publication, or
with --verify, repack cheaply and compare against that compiled package.
cargo publish --no-verify uses the same locked inputs after the comparison.

Usage: scripts/prepare-release-crate.py vVERSION OUTPUT_DIR
       scripts/prepare-release-crate.py --verify vVERSION PREPARED_DIR
"""
import json
import os
import re
import shutil
import subprocess
import sys


def output(*args):
    completed = subprocess.run(list(args), stdout=subprocess.PIPE, text=True)
    if completed.returncode:
        sys.exit(completed.returncode)
    return completed.stdout


def main():
    arguments = sys.argv[1:]
    verify = arguments[:1] == ["--verify"]
    if verify:
        arguments = arguments[1:]
    if len(arguments) != 2:
        print(f"usage: {sys.argv[0]} [--verify] vVERSION DIRECTORY", file=sys.stderr)
        return 2
    tag, directory = arguments
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
    validated = os.path.join(directory, f"syq-{version}.crate")
    if verify and (not os.path.isfile(validated) or os.path.islink(validated)):
        print(f"missing regular prepared crate: {validated}", file=sys.stderr)
        return 1
    package = os.path.join(metadata["target_directory"], "package", f"syq-{version}.crate")
    if os.path.lexists(package):
        os.remove(package)
    packaged = subprocess.run(["cargo", "package", "--locked", *(["--no-verify"] if verify else [])])
    if packaged.returncode:
        return packaged.returncode
    if verify:
        sys.stdout.flush()
        if subprocess.run(["cmp", validated, package]).returncode:
            print("source package differs from the validated artifact; refusing publication",
                  file=sys.stderr)
            return 1
        print(f"Source package matches validated {tag} bytes.")
        return 0
    os.makedirs(directory, exist_ok=True)
    shutil.copy(package, directory)
    head = output("git", "rev-parse", "HEAD").rstrip("\n")
    print(f"Validated source crate {tag} at {head}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
