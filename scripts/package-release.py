#!/usr/bin/env python3
"""Validate a complete four-target build and create deterministic release
metadata, checksums, the standalone installer, and the Homebrew formula.

The zstd archives are listed in their own manifest: releases before them parse
syq-release-manifest.json strictly and would refuse one with another field.

Usage: scripts/package-release.py vVERSION DIST_DIR
"""
import difflib
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile
import zlib

from tooling import ToolError, cargo_version, report_errors, sha256_file

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


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
GZIP_MAGIC = b"\x1f\x8b"


def unpacked(path):
    """The SHA-256 and size of what the archive at PATH decompresses to,
    unpacked as clients unpack it.

    The zstd command also unpacks gzip, xz, and lz4 when built with them,
    and Python's gzip module reads every member of a concatenated file,
    while clients read zstd frames and a single gzip member. Each archive
    must therefore be in exactly the format its name says.
    """
    digest = hashlib.sha256()
    size = 0

    def add(chunk):
        nonlocal size
        digest.update(chunk)
        size += len(chunk)

    with open(path, "rb") as archive:
        magic = archive.read(4)
        if path.endswith(".gz"):
            if not magic.startswith(GZIP_MAGIC):
                raise ToolError(f"{path} is not a gzip archive")
            archive.seek(0)
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                while chunk := archive.read(1 << 20):
                    add(decompressor.decompress(chunk))
                    if decompressor.eof:
                        break
                add(decompressor.flush())
            except zlib.error as error:
                raise ToolError(f"gzip could not decompress {path}: {error}") from None
            if not decompressor.eof:
                raise ToolError(f"gzip archive {path} is truncated")
            if decompressor.unused_data or archive.read(1):
                raise ToolError(f"{path} has data after its first gzip member")
            return digest.hexdigest(), size
    if magic != ZSTD_MAGIC:
        raise ToolError(f"{path} is not a zstd archive")
    if shutil.which("zstd") is None:
        raise ToolError("checking the zstd archives needs the zstd command")
    with subprocess.Popen(["zstd", "-d", "-q", "-c", "--", path],
                          stdout=subprocess.PIPE) as process:
        while chunk := process.stdout.read(1 << 20):
            add(chunk)
    if process.returncode:
        raise ToolError(f"zstd could not decompress {path}")
    return digest.hexdigest(), size


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
        # Clients check each archive's own digest before unpacking it, so an
        # archive of another binary must never be signed.
        binary = artifacts[target]["binary"]
        for archive in (f"{asset}.gz", f"{asset}.zst"):
            if unpacked(os.path.join(dist, archive)) != (binary["sha256"], binary["size"]):
                raise ToolError(f"{archive} does not decompress to {asset}")

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
