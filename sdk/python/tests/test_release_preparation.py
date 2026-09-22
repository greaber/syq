"""Preparation must verify the downloaded native executable before running it."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[3] / "scripts/test-python-release-preparation.py"
spec = importlib.util.spec_from_file_location("preparation", SCRIPT)
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)


class PreparationTests(unittest.TestCase):
    def test_rejects_wrong_version_size_and_hash_before_execution(self):
        content = b"release executable"
        binary = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "syq"
            executable.write_bytes(content)
            for version, expected in (("0.8.0", binary),
                                      ("0.7.0", binary | {"size": len(content) + 1}),
                                      ("0.7.0", binary | {"sha256": "0" * 64})):
                manifest = {"version": version, "artifacts": {"linux-x86_64": {"binary": expected}}}
                with self.subTest(version=version, expected=expected), patch.object(
                        preparation.subprocess, "check_output") as execute:
                    with self.assertRaises(ValueError):
                        preparation.verify_executable(executable, manifest, "0.7.0")
                    execute.assert_not_called()

    def test_requires_release_identity_after_hash_matches(self):
        content = b"release executable"
        manifest = {"version": "0.7.0", "artifacts": {"linux-x86_64": {"binary": {
            "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}}}}
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "syq"
            executable.write_bytes(content)
            for replies, succeeds in ((["syq 0.6.0"], False),
                                      (["syq 0.7.0", "development-sha"], False),
                                      (["syq 0.7.0", "v0.7.0"], True)):
                with self.subTest(replies=replies), patch.object(
                        preparation.subprocess, "check_output", side_effect=replies):
                    if succeeds:
                        preparation.verify_executable(executable, manifest, "0.7.0")
                    else:
                        with self.assertRaises(ValueError):
                            preparation.verify_executable(executable, manifest, "0.7.0")
