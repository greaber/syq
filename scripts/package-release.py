#!/usr/bin/env python3
"""Validate a complete four-target build and create deterministic release
metadata, checksums, the standalone installer, and the Homebrew formula.

The zstd archives are listed in their own manifest: releases before them parse
syq-release-manifest.json strictly and would refuse one with another field.

Usage: scripts/package-release.py vVERSION DIST_DIR
"""
import difflib
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from tooling import cargo_version, report_errors, sha256_file

SCRIPTS = Path(os.path.abspath(__file__)).parent
MANIFEST = "syq-release-manifest.json"
ZSTD_MANIFEST = "syq-release-zstd.json"
TARGETS = {
    "linux-x86_64": "syq-linux-x86_64",
    "linux-aarch64": "syq-linux-aarch64",
    "macos-arm64": "syq-macos-arm64",
    "macos-x86_64": "syq-macos-x86_64",
}


def regular(path):
    return os.path.isfile(path) and not os.path.islink(path)


def run(*args):
    completed = subprocess.run([str(arg) for arg in args])
    if completed.returncode:
        sys.exit(completed.returncode)


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} vVERSION DIST_DIR", file=sys.stderr)
        return 2
    tag, dist = sys.argv[1:]
    if not fnmatchcase(tag, "v[0-9]*.[0-9]*.[0-9]*"):
        print(f"invalid release tag: {tag}", file=sys.stderr)
        return 2
    version = tag[1:]
    if not os.path.isdir(dist):
        print(f"missing distribution directory: {dist}", file=sys.stderr)
        return 1
    package_version = cargo_version(SCRIPTS.parent / "Cargo.toml")
    if version != package_version:
        print(f"tag {tag} does not match Cargo.toml version {package_version}", file=sys.stderr)
        return 1

    def described(name):
        """Write NAME's checksum file and return its manifest entry."""
        path = os.path.join(dist, name)
        digest = sha256_file(path)
        with open(path + ".sha256", "w") as checksum:
            checksum.write(f"{digest}  {name}\n")
        return {"name": name, "sha256": digest, "size": os.path.getsize(path)}

    artifacts = {}
    zstd_archives = {}
    for target, asset in TARGETS.items():
        for name in (asset, f"{asset}.gz", f"{asset}.zst"):
            if not regular(os.path.join(dist, name)):
                print(f"missing regular asset: {os.path.join(dist, name)}", file=sys.stderr)
                return 1
        artifacts[target] = {"binary": described(asset), "archive": described(f"{asset}.gz")}
        zstd_archives[target] = described(f"{asset}.zst")

    identity = {"schema": 1, "repository": "https://github.com/greaber/syq", "version": version,
                "tag": tag}
    core = dict(identity, artifacts=artifacts)
    zstd_manifest = os.path.join(dist, ZSTD_MANIFEST)
    with open(zstd_manifest, "w") as output:
        output.write(json.dumps(dict(identity, archives=zstd_archives,
                                     signature_scheme="ed25519-jcs-v1"),
                                indent=2, sort_keys=True) + "\n")
    descriptor, manifest_core = tempfile.mkstemp()
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(json.dumps(core, indent=2, sort_keys=True) + "\n")
        installer = os.path.join(dist, "install.sh")
        formula = os.path.join(dist, "syq.rb")
        run(SCRIPTS / "generate-installer.py", manifest_core, zstd_manifest, installer)
        run(SCRIPTS / "generate-homebrew-formula.py", manifest_core, formula)
    finally:
        os.unlink(manifest_core)
    manifest = dict(core)
    manifest.update({
        "installer": {"name": "install.sh", "sha256": sha256_file(installer),
                      "size": os.path.getsize(installer)},
        "homebrew_formula": {"name": "syq.rb", "sha256": sha256_file(formula),
                             "size": os.path.getsize(formula)},
        "signature_scheme": "ed25519-jcs-v1",
    })
    with open(os.path.join(dist, MANIFEST), "w") as output:
        output.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    # Anything unexpected here indicates a partial or contaminated release job.
    expected = sorted([name for asset in TARGETS.values()
                       for file in (asset, f"{asset}.gz", f"{asset}.zst")
                       for name in (file, f"{file}.sha256")]
                      + ["install.sh", MANIFEST, ZSTD_MANIFEST, "syq.rb"])
    actual = sorted(os.listdir(dist))
    if expected != actual:
        sys.stdout.writelines(difflib.unified_diff(
            [name + "\n" for name in expected], [name + "\n" for name in actual],
            "expected", "actual"))
        sys.stdout.flush()
        print("release directory contains missing or unexpected files", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
