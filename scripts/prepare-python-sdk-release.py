#!/usr/bin/env python3
"""Prepare a Python SDK patch release for one immutable syq manifest."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any


SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
EXPECTED_REPOSITORY = "https://github.com/greaber/syq"
EXPECTED_TARGETS = {
    "linux-aarch64",
    "linux-x86_64",
    "macos-arm64",
    "macos-x86_64",
}


def version_tuple(value: str, *, label: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(value)
    if match is None:
        raise ValueError(f"{label} must be an X.Y.Z version, got {value!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def digest(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"manifest {label} is not a lowercase SHA-256 digest")
    return value


def positive_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"manifest {label} is not a positive integer")
    return value


def load_manifest(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("release manifest is unexpectedly large")
    manifest = json.loads(raw)
    if not isinstance(manifest, dict):
        raise ValueError("release manifest is not an object")
    if manifest.get("schema") != 1:
        raise ValueError("release manifest schema is not 1")
    if manifest.get("repository") != EXPECTED_REPOSITORY:
        raise ValueError("release manifest repository is unexpected")
    version = manifest.get("version")
    if not isinstance(version, str) or manifest.get("tag") != f"v{version}":
        raise ValueError("release manifest version and tag do not match")
    version_tuple(version, label="syq release")
    try:
        signature = base64.b64decode(manifest["signature"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as error:
        raise ValueError("release manifest has no valid base64 signature") from error
    if len(signature) != 64:
        raise ValueError("release manifest signature is not 64 bytes")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != EXPECTED_TARGETS:
        raise ValueError("release manifest does not contain every SDK target")
    for target, entry in artifacts.items():
        if not isinstance(entry, dict):
            raise ValueError(f"release manifest target {target} is not an object")
        for kind in ("archive", "binary"):
            artifact = entry.get(kind)
            if not isinstance(artifact, dict):
                raise ValueError(f"release manifest {target} {kind} is not an object")
            name = artifact.get("name")
            if not isinstance(name, str) or not name.startswith("syq-"):
                raise ValueError(f"release manifest {target} {kind} name is invalid")
            digest(artifact.get("sha256"), label=f"{target} {kind} digest")
            positive_integer(artifact.get("size"), label=f"{target} {kind} size")
    return raw, manifest


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"expected exactly one {label} marker, found {text.count(old)}")
    return text.replace(old, new)


def prepare(root: Path, manifest_path: Path) -> bool:
    raw_manifest, manifest = load_manifest(manifest_path)
    new_syq_version = str(manifest["version"])
    packaged_manifest = root / "sdk/python/src/syq/syq-release-manifest.json"
    current_manifest = json.loads(packaged_manifest.read_bytes())
    current_syq_version = str(current_manifest["version"])
    if version_tuple(new_syq_version, label="new syq release") <= version_tuple(
        current_syq_version, label="current syq release"
    ):
        print(
            f"Python SDK already pins syq {current_syq_version}; "
            f"not preparing {new_syq_version}"
        )
        return False

    pyproject_path = root / "sdk/python/pyproject.toml"
    pyproject = pyproject_path.read_text(encoding="utf-8")
    version_match = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
    if version_match is None:
        raise ValueError("could not find the Python package version")
    current_python_version = version_match.group(1)
    major, minor, patch = version_tuple(
        current_python_version, label="current Python SDK"
    )
    new_python_version = f"{major}.{minor}.{patch + 1}"
    pyproject = replace_once(
        pyproject,
        f'version = "{current_python_version}"',
        f'version = "{new_python_version}"',
        label="Python package version",
    )

    python_readme_path = root / "sdk/python/README.md"
    python_readme = python_readme_path.read_text(encoding="utf-8")
    python_readme = replace_once(
        python_readme,
        f"For Python package `{current_python_version}`, that release is syq "
        f"`{current_syq_version}`.",
        f"For Python package `{new_python_version}`, that release is syq "
        f"`{new_syq_version}`.",
        label="Python README release mapping",
    )
    old_cache_path = f"syq/sdk/python/v{current_syq_version}/"
    if python_readme.count(old_cache_path) != 2:
        raise ValueError("expected two Python README cache-version markers")
    python_readme = python_readme.replace(
        old_cache_path,
        f"syq/sdk/python/v{new_syq_version}/",
    )
    if old_cache_path in python_readme:
        raise ValueError("the Python README retained the old cache version")

    sdk_readme_path = root / "sdk/README.md"
    sdk_readme = sdk_readme_path.read_text(encoding="utf-8")
    current_row = f"| `{current_python_version}` | `{current_syq_version}` |"
    new_row = f"| `{new_python_version}` | `{new_syq_version}` |"
    sdk_readme = replace_once(
        sdk_readme,
        current_row,
        f"{current_row}\n{new_row}",
        label="SDK mapping table row",
    )

    pyproject_path.write_text(pyproject, encoding="utf-8")
    python_readme_path.write_text(python_readme, encoding="utf-8")
    sdk_readme_path.write_text(sdk_readme, encoding="utf-8")
    packaged_manifest.write_bytes(raw_manifest)
    print(
        f"prepared Python SDK {new_python_version} for syq {new_syq_version}"
    )
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    arguments = parser.parse_args()
    prepare(arguments.root.resolve(), arguments.manifest.resolve())


if __name__ == "__main__":
    main()
