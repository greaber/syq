#!/usr/bin/env python3
"""Stage the current Python SDK with the native source of its pinned release."""

import argparse
import io
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile


def make_writable(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        if not path.is_symlink():
            path.chmod(path.stat().st_mode | stat.S_IWUSR)


def stage(root: Path, output: Path, native_source: Path | None = None,
          revision: str | None = None) -> None:
    manifest = json.loads((root / "sdk/python/src/syq/syq-release-manifest.json").read_text())
    tag = manifest["tag"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("invalid pinned release tag")
    if native_source is None:
        revision = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", f"{tag}^{{commit}}"], text=True
        ).strip()
        archive = subprocess.check_output(["git", "-C", str(root), "archive", revision])
        output.mkdir(parents=True, exist_ok=False)
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            if hasattr(tarfile, "data_filter"):
                source.extractall(output, filter="data")
            else:
                # Python 3.10.0–3.10.11 has no extraction filters. This archive was
                # just produced by local Git from the selected source commit; this
                # path does not accept downloaded or user-supplied tar archives.
                source.extractall(output)
    else:
        if revision is None or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("an extracted native source requires its exact revision")
        shutil.copytree(native_source, output, symlinks=True)
        # Nix source trees are read-only; the staged copy must accept the SDK
        # overlay and Cargo's build output. Preserve executable bits and links.
        make_writable(output)
    sdk = output / "sdk/python"
    shutil.rmtree(sdk)
    shutil.copytree(root / "sdk/python", sdk, ignore=shutil.ignore_patterns(
        ".venv", "__pycache__", "*.egg-info", "dist", "target"
    ))
    make_writable(sdk)
    # Maturin moves explicit SDK sdist includes to the archive root, where
    # build.rs expects Cargo's native source provenance metadata.
    (sdk / ".cargo_vcs_info.json").write_text(json.dumps({"git": {"sha1": revision}}))
    print(f"Staged Python SDK with {tag} native source at {revision[:12]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--native-source", type=Path)
    parser.add_argument("--native-revision")
    args = parser.parse_args()
    if bool(args.native_source) != bool(args.native_revision):
        parser.error("--native-source and --native-revision must be supplied together")
    stage(args.root.resolve(), args.out.resolve(), args.native_source, args.native_revision)
