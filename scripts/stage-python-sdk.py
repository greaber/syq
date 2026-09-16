#!/usr/bin/env python3
"""Stage the current Python SDK with the native source of its pinned release."""

import argparse
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile


def stage(root: Path, output: Path) -> None:
    manifest = json.loads((root / "sdk/python/src/syq/syq-release-manifest.json").read_text())
    tag = manifest["tag"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("invalid pinned release tag")
    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", f"{tag}^{{commit}}"], text=True
    ).strip()
    archive = subprocess.check_output(["git", "-C", str(root), "archive", revision])
    output.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(output, filter="data")
    sdk = output / "sdk/python"
    shutil.rmtree(sdk)
    shutil.copytree(root / "sdk/python", sdk, ignore=shutil.ignore_patterns(
        ".venv", "__pycache__", "*.egg-info", "dist", "target"
    ))
    # Maturin moves explicit SDK sdist includes to the archive root, where
    # build.rs expects Cargo's native source provenance metadata.
    (sdk / ".cargo_vcs_info.json").write_text(json.dumps({"git": {"sha1": revision}}))
    print(f"Staged Python SDK with {tag} native source at {revision[:12]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    stage(args.root.resolve(), args.out.resolve())
