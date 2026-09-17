"""Release packaging must pair current Python code with pinned native source."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile
from types import SimpleNamespace
from unittest.mock import patch
import unittest


SCRIPT = Path(__file__).resolve().parents[3] / "scripts/stage-python-sdk.py"
spec = importlib.util.spec_from_file_location("stage_python_sdk", SCRIPT)
assert spec is not None and spec.loader is not None
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)


class PackagingTests(unittest.TestCase):
    def test_stage_uses_release_native_source_and_current_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()

            def git(*args):
                return subprocess.check_output([
                    "git", "-C", str(root), "-c", "user.name=SDK test",
                    "-c", "user.email=sdk-test@example.invalid", *args,
                ], text=True).strip()

            git("init", "-q")
            sdk = root / "sdk/python"
            package = sdk / "src/syq"
            package.mkdir(parents=True)
            (package / "syq-release-manifest.json").write_text(json.dumps({
                "tag": "v9.8.7", "version": "9.8.7",
            }))
            (root / "native.rs").write_text("released native source")
            (package / "client.py").write_text("old Python")
            git("add", ".")
            git("commit", "-qm", "release")
            git("tag", "v9.8.7")
            revision = git("rev-parse", "HEAD")
            (root / "native.rs").write_text("later native changes")
            (package / "client.py").write_text("current Python")
            (sdk / ".venv").mkdir()
            output = Path(directory) / "stage"
            staging.stage(root, output)
            self.assertEqual((output / "native.rs").read_text(), "released native source")
            self.assertEqual(
                (output / "sdk/python/src/syq/client.py").read_text(), "current Python"
            )
            metadata = json.loads((output / "sdk/python/.cargo_vcs_info.json").read_text())
            self.assertEqual(metadata["git"]["sha1"], revision)
            self.assertFalse((output / "sdk/python/.venv").exists())

    def test_stage_on_python_without_tar_extraction_filters(self):
        extract = tarfile.TarFile.extractall

        def old_extract(archive, path):
            # The pre-3.10.12 signature rejects a filter keyword.
            return extract(archive, path)

        with patch.object(staging, "tarfile", SimpleNamespace(open=tarfile.open)), \
                patch.object(tarfile.TarFile, "extractall", old_extract):
            self.test_stage_uses_release_native_source_and_current_python()
