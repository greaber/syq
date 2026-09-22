"""Release wheels preserve the shipped executable and have valid reproducible records."""
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[3] / "scripts/package-python-wheel.py"
spec = importlib.util.spec_from_file_location("release_wheel", SCRIPT)
wheels = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wheels)


class ReleaseWheelTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.project = self.root / "project"
        self.source = self.project / "src/syq"
        self.source.mkdir(parents=True)
        (self.project / "pyproject.toml").write_text('[project]\nversion = "0.7.0"\n')
        (self.source / "__init__.py").write_text('version = "0.7.0"\n')
        (self.source / "py.typed").touch()
        (self.source / "__pycache__").mkdir()
        (self.source / "__pycache__/stale.pyc").write_bytes(b"stale")
        self.binary = self.root / "binary"
        self.binary.write_bytes(b"unchanged native executable and signature")
        payload = self.binary.read_bytes()
        self.manifest = {"version": "0.7.0", "tag": "v0.7.0", "artifacts": {
            platform: {"binary": {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}}
            for platform in wheels.PLATFORMS}}
        self.manifest_path = self.source / "syq-release-manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.metadata = self.root / "metadata"
        info = self.metadata / "syq-0.7.0.dist-info"
        (info / "licenses").mkdir(parents=True)
        (info / "METADATA").write_text('Metadata-Version: 2.4\nName: syq\nVersion: 0.7.0\n\nREADME\n')
        (info / "licenses/LICENSE-PYTHON").write_text("MIT license")
        (info / "WHEEL").write_text("discard backend host tag")
        self.sbom = self.root / "sbom.json"
        self.sbom.write_text('{"bomFormat":"CycloneDX","components":[]}')

    def build(self, platform="linux-x86_64", output="dist"):
        return wheels.package(self.project, self.metadata, self.binary, platform,
                              self.sbom, 1789948800, self.root / output)

    def test_records_permissions_payload_and_repeatability(self):
        first = self.build()
        os.utime(self.binary, (1, 1))
        os.utime(self.source / "__init__.py", (2, 2))
        second = self.build(output="second")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            names = archive.namelist()
            self.assertFalse(any("__pycache__" in name for name in names))
            binary = "syq-0.7.0.data/scripts/syq"
            self.assertEqual(archive.read(binary), self.binary.read_bytes())
            self.assertEqual(archive.getinfo(binary).external_attr >> 16 & 0o777, 0o755)
            self.assertEqual(archive.read("syq-0.7.0.dist-info/licenses/LICENSE-PYTHON"), b"MIT license")
            self.assertEqual(archive.read("syq-0.7.0.dist-info/sboms/syq.cyclonedx.json"), self.sbom.read_bytes())
            record = "syq-0.7.0.dist-info/RECORD"
            rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
            self.assertEqual({row[0] for row in rows}, set(names))
            for name, digest, size in rows:
                if name == record:
                    self.assertEqual((digest, size), ("", ""))
                    continue
                data = archive.read(name)
                expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                self.assertEqual(digest, "sha256=" + expected)
                self.assertEqual(int(size), len(data))

    def test_platform_tags_agree_with_filename(self):
        for platform, tags in wheels.PLATFORMS.items():
            with self.subTest(platform=platform):
                wheel = self.build(platform)
                self.assertTrue(wheel.name.endswith(f"-py3-none-{tags}.whl"))
                with zipfile.ZipFile(wheel) as archive:
                    metadata = archive.read("syq-0.7.0.dist-info/WHEEL").decode()
                    for tag in tags.split("."):
                        self.assertIn(f"Tag: py3-none-{tag}\n", metadata)

    def test_corrupt_native_binary_is_rejected(self):
        self.binary.write_bytes(b"wrong bytes")
        with self.assertRaisesRegex(ValueError, "release manifest"):
            self.build()

    def test_version_or_metadata_mismatch_is_rejected(self):
        self.manifest["version"] = "0.6.0"
        self.manifest_path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "native release"):
            self.build()
        self.manifest["version"] = "0.7.0"
        self.manifest_path.write_text(json.dumps(self.manifest))
        (self.metadata / "syq-0.7.0.dist-info/METADATA").write_text('Name: syq\nVersion: 0.6.0\n')
        with self.assertRaisesRegex(ValueError, "package metadata"):
            self.build()
