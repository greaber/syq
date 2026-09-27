#!/usr/bin/env python3
"""Test prepared Python sources against their published CLI without rebuilding it.

First uv sync --frozen --no-install-project, then uv run --no-sync, so the pinned
metadata backend and test dependencies are available without building the project.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


def verify_executable(executable, manifest, version):
    if manifest["version"] != version:
        raise ValueError("Python version does not match its native release")
    expected = manifest["artifacts"]["linux-x86_64"]["binary"]
    content = executable.read_bytes()
    if len(content) != expected["size"] or hashlib.sha256(content).hexdigest() != expected["sha256"]:
        raise ValueError("Native executable does not match the immutable release manifest")
    executable.chmod(0o755)
    for flag, value in (("--version", f"syq {version}"), ("--build-identity", f"v{version}")):
        actual = subprocess.check_output([str(executable), flag], text=True).strip()
        if actual != value:
            raise ValueError(f"Unexpected native {flag}: {actual}")


def main():
    root = Path(__file__).resolve().parent.parent
    executable = Path(sys.argv[1]).resolve(strict=True)
    project = root / "sdk/python"
    manifest = json.loads((project / "src/syq/syq-release-manifest.json").read_text())
    version = tomllib.loads((project / "pyproject.toml").read_text())["project"]["version"]
    verify_executable(executable, manifest, version)
    with tempfile.TemporaryDirectory(prefix="syq-preparation-metadata-") as metadata:
        # The standard PEP 517 hook produces genuine package metadata, without
        # building a wheel or compiling the bundled executable.
        subprocess.run([sys.executable, "-c",
                        "import maturin, sys; maturin.prepare_metadata_for_build_wheel(sys.argv[1])",
                        metadata], cwd=project, check=True)
        env = os.environ | {
            "PYTHONPATH": os.pathsep.join((str(project / "src"), metadata)),
            "SYQ_CANDIDATE_EXECUTABLE": str(executable),
            "SYQ_CANDIDATE_VERSION": version,
        }
        subprocess.run([sys.executable, "-m", "unittest", "discover",
                        "-s", str(project / "tests")], cwd=root, env=env, check=True)


if __name__ == "__main__":
    main()
