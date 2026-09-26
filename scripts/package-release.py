#!/usr/bin/env python3
"""Validate a complete four-target build and create deterministic release
metadata, checksums, the standalone installer, and the Homebrew formula.

Usage: scripts/package-release.py vVERSION DIST_DIR
"""
import difflib
from fnmatch import fnmatchcase
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from tooling import cargo_version, dumps, exit_on_failure, sha256_file

SCRIPTS = Path(os.path.abspath(__file__)).parent
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
    cargo_toml = SCRIPTS.parent / "Cargo.toml"
    try:
        package_version = cargo_version(cargo_toml)
    except OSError as error:
        print(f"sed: can't read {cargo_toml}: {error.strerror}", file=sys.stderr)
        return 2
    if version != package_version:
        print(f"tag {tag} does not match Cargo.toml version {package_version}", file=sys.stderr)
        return 1

    artifacts = {}
    for target, asset in TARGETS.items():
        binary = os.path.join(dist, asset)
        archive = binary + ".gz"
        for path in (binary, archive):
            if not regular(path):
                print(f"missing regular asset: {path}", file=sys.stderr)
                return 1
        binary_hash = sha256_file(binary)
        archive_hash = sha256_file(archive)
        with open(binary + ".sha256", "w") as checksum:
            checksum.write(f"{binary_hash}  {asset}\n")
        with open(archive + ".sha256", "w") as checksum:
            checksum.write(f"{archive_hash}  {asset}.gz\n")
        artifacts[target] = {
            "binary": {"name": asset, "sha256": binary_hash, "size": os.path.getsize(binary)},
            "archive": {"name": f"{asset}.gz", "sha256": archive_hash,
                        "size": os.path.getsize(archive)},
        }

    core = {"schema": 1, "repository": "https://github.com/greaber/syq", "version": version,
            "tag": tag, "artifacts": artifacts}
    descriptor, manifest_core = tempfile.mkstemp()
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(dumps(core, indent=2, sort_keys=True) + "\n")
        installer = os.path.join(dist, "install.sh")
        formula = os.path.join(dist, "syq.rb")
        run(SCRIPTS / "generate-installer.py", manifest_core, installer)
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
    with open(os.path.join(dist, "syq-release-manifest.json"), "w") as output:
        output.write(dumps(manifest, indent=2, sort_keys=True) + "\n")

    # Anything unexpected here indicates a partial or contaminated release job.
    expected = sorted([name for asset in TARGETS.values()
                       for name in (asset, f"{asset}.sha256", f"{asset}.gz", f"{asset}.gz.sha256")]
                      + ["install.sh", "syq-release-manifest.json", "syq.rb"])
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
    sys.exit(exit_on_failure(main))
