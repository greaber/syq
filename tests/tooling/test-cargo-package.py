#!/usr/bin/env python3
"""Build the registry package outside the checkout and require Cargo's VCS
metadata to produce a stable source identity."""
from support import ROOT

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from tooling import cargo_version

REPOSITORY = ROOT


def run(*args, **kwargs):
    completed = subprocess.run([str(arg) for arg in args], **kwargs)
    if completed.returncode:
        sys.exit(completed.returncode)
    return completed


def main():
    manifest = REPOSITORY / "Cargo.toml"
    version = cargo_version(manifest)
    metadata = run("cargo", "metadata", "--no-deps", "--format-version", "1",
                   "--manifest-path", manifest, stdout=subprocess.PIPE, text=True)
    directories = json.loads(metadata.stdout)
    target_dir = directories["target_directory"]
    package = Path(target_dir, "package", f"syq-{version}.crate")

    # Cargo can leave trailing bytes when replacing a same-version archive with a
    # shorter one. Remove only this generated package so extraction verifies the
    # newly written archive rather than stale local target state.
    package.unlink(missing_ok=True)
    # The extracted build below verifies the package and its identity in one build.
    run("cargo", "package", "--locked", "--no-verify", "--manifest-path", manifest)
    if not package.is_file() or package.is_symlink():
        print(f"cargo did not create {package}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="syq-cargo-package.") as work:
        run("tar", "-xzf", package, "-C", work)
        source_dir = Path(work, f"syq-{version}")
        vcs_info = json.loads((source_dir / ".cargo_vcs_info.json").read_text())
        revision = vcs_info.get("git", {}).get("sha1")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
            print("the package has no Git revision in .cargo_vcs_info.json", file=sys.stderr)
            return 1
        expected = f"v{version}+dev.{revision[:12]}"

        # Cargo archives normalize mtimes. A restored build cache can otherwise mistake
        # a different commit's extracted sources/VCS metadata for the previous package.
        # Rebuild syq itself while keeping compiled dependencies across package checks.
        identity_target = Path(target_dir, "package-identity")
        # Resolve the checkout's intermediate directory before entering the temporary
        # package: a workspace-path template would otherwise create a cold cache each time.
        build_env = {**os.environ, "CARGO_TARGET_DIR": str(identity_target),
                     "CARGO_BUILD_BUILD_DIR": str(Path(directories["build_directory"],
                                                       "package-identity"))}
        run("cargo", "clean", "--manifest-path", source_dir / "Cargo.toml", "--package", "syq",
            env=build_env)
        run("cargo", "build", "--locked", "--manifest-path", source_dir / "Cargo.toml",
            "--bin", "syq", env=build_env)
    actual = run(identity_target / "debug/syq", "--build-identity", stdout=subprocess.PIPE,
                 text=True).stdout.rstrip("\n")
    if actual != expected:
        print(f"packaged source identity is {actual}, expected {expected}", file=sys.stderr)
        return 1
    print(f"cargo package source identity is stable at {expected}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
