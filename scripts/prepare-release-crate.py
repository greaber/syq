#!/usr/bin/env python3
"""Compile the registry package before any permanent release publication.

Usage: scripts/prepare-release-crate.py vVERSION OUTPUT_DIR
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
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} vVERSION OUTPUT_DIR", file=sys.stderr)
        return 2
    tag, output_dir = sys.argv[1:]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        return 2
    version = tag[1:]
    if output("git", "status", "--porcelain").rstrip("\n"):
        print("source package needs a clean checkout", file=sys.stderr)
        return 1
    metadata = json.loads(output("cargo", "metadata", "--locked", "--no-deps",
                                 "--format-version", "1"))
    if [package["version"] for package in metadata["packages"]
            if package["name"] == "syq"] != [version]:
        return 1
    package = os.path.join(metadata["target_directory"], "package", f"syq-{version}.crate")
    if os.path.lexists(package):
        os.remove(package)
    packaged = subprocess.run(["cargo", "package", "--locked"])
    if packaged.returncode:
        return packaged.returncode
    os.makedirs(output_dir, exist_ok=True)
    shutil.copy(package, output_dir)
    head = output("git", "rev-parse", "HEAD").rstrip("\n")
    print(f"Validated source crate {tag} at {head}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
