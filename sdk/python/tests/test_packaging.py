"""Release packaging must pair current Python code with pinned native source."""

import importlib.util
import json
import os
import shutil
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

    def test_stage_readonly_extracted_source_without_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sdk-checkout"
            native = Path(directory) / "native"
            output = Path(directory) / "out"
            sdk = root / "sdk/python"
            (sdk / "src/syq").mkdir(parents=True)
            (sdk / "src/syq/syq-release-manifest.json").write_text(
                json.dumps({"tag": "v9.8.7", "version": "9.8.7"}))
            (sdk / "src/syq/client.py").write_text("current Python")
            (sdk / ".cargo_vcs_info.json").write_text("old provenance")
            (native / "sdk/python").mkdir(parents=True)
            (native / "native.rs").write_text("pinned native source")
            (native / "executable").write_text("#!/bin/sh\n")
            (native / "executable").chmod(0o755)
            (native / "link").symlink_to("native.rs")
            for parent in (root, native):
                for path in [parent, *parent.rglob("*")]:
                    if not path.is_symlink():
                        path.chmod(path.stat().st_mode & ~0o222)
            try:
                with patch.object(staging.subprocess, "check_output", side_effect=AssertionError("Git used")):
                    staging.stage(root, output, native, "a" * 40)
                self.assertEqual((output / "native.rs").read_text(), "pinned native source")
                self.assertTrue((output / "executable").stat().st_mode & 0o100)
                self.assertTrue((output / "link").is_symlink())
                self.assertEqual((output / "sdk/python/src/syq/client.py").read_text(), "current Python")
                self.assertEqual(json.loads((output / "sdk/python/.cargo_vcs_info.json").read_text()),
                                 {"git": {"sha1": "a" * 40}})
            finally:
                staging.make_writable(root)
                staging.make_writable(native)

    def test_source_pin_uses_release_tag_instead_of_current_head(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            script = root / "scripts/pin-python-native-source.sh"
            shutil.copyfile(SCRIPT.with_name("pin-python-native-source.sh"), script)
            (root / "sdk/python/src/syq").mkdir(parents=True)
            manifest = root / "sdk/python/src/syq/syq-release-manifest.json"
            manifest.write_text(json.dumps({"tag": "v9.8.7"}))

            def git(*args):
                return subprocess.check_output([
                    "git", "-C", str(root), "-c", "user.name=SDK test",
                    "-c", "user.email=sdk-test@example.invalid", *args,
                ], text=True).strip()

            git("init", "-q")
            git("add", ".")
            git("commit", "-qm", "native release")
            git("tag", "v9.8.7")
            revision = git("rev-parse", "HEAD")
            (root / "later").write_text("later changes")
            git("add", ".")
            git("commit", "-qm", "later SDK")
            tools = root / "tools"
            tools.mkdir()
            nix = tools / "nix"
            nix.write_text(
                "#!/bin/sh\n"
                + 'test "$6" = "github:greaber/syq/' + revision + '" || exit 1\n'
                + "echo '{\"hash\":\"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}'\n"
            )
            nix.chmod(0o755)
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"])
            subprocess.run(["bash", str(script)], env=env, check=True)
            pin = root / "sdk/python/native-source.json"
            self.assertEqual(json.loads(pin.read_text()), {
                "tag": "v9.8.7", "rev": revision,
                "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            })
            previous = pin.read_bytes()
            subprocess.run(["bash", str(script)], env=env, check=True)
            self.assertEqual(previous, pin.read_bytes())
            manifest.write_text(json.dumps({"tag": "../invalid"}))
            result = subprocess.run(["bash", str(script)], env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(previous, pin.read_bytes())
