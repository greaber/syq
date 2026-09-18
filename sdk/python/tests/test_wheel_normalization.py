"""Wheel normalization retains payloads, metadata, and valid installed records."""

import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[3] / "scripts/normalize-python-wheel.py"
spec = importlib.util.spec_from_file_location("normalize_python_wheel", SCRIPT)
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)

SBOM = "syq-0.6.0.dist-info/sboms/syq.cyclonedx.json"
RECORD = "syq-0.6.0.dist-info/RECORD"
BINARY = "syq-0.6.0.data/scripts/syq"


def fixture(path, source_root):
    reference = f"path+file://{source_root}#syq@0.6.0"
    sbom = {
        "metadata": {"component": {"bom-ref": reference, "name": "syq"}},
        "components": [{"bom-ref": reference + " bin-target-0"},
                       {"bom-ref": "path+file:///external#other@1.0.0"}],
        "dependencies": [{"ref": reference, "dependsOn": ["registry+https://example.invalid/#other@1.0.0"]}],
    }
    contents = {SBOM: json.dumps(sbom).encode(), BINARY: b"signed binary payload\x00\xff",
                "syq/client.py": b"# unchanged Python\n"}
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in contents.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(data))])
    writer.writerow([RECORD, "", ""])
    contents[RECORD] = record.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        archive.comment = b"preserve archive comment"
        for name, data in contents.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 2, 3, 4, 6))
            info.external_attr = (0o100755 if name == BINARY else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


class WheelNormalizationTests(unittest.TestCase):
    def test_different_build_roots_produce_same_wheel_and_keep_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = (Path(directory) / name for name in ("a.whl", "b.whl"))
            fixture(a, "/tmp/one")
            fixture(b, "/private/var/two")
            original = a.read_bytes()
            with zipfile.ZipFile(a) as archive:
                metadata = [(i.filename, i.date_time, i.external_attr, i.compress_type)
                            for i in archive.infolist()]
                binary = archive.read(BINARY)
                python = archive.read("syq/client.py")
            normalizer.normalize(a)
            normalizer.normalize(b)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            self.assertNotEqual(a.read_bytes(), original)
            with zipfile.ZipFile(a) as archive:
                self.assertEqual(archive.comment, b"preserve archive comment")
                self.assertEqual(metadata, [(i.filename, i.date_time, i.external_attr, i.compress_type)
                                            for i in archive.infolist()])
                self.assertEqual(archive.read(BINARY), binary)
                self.assertEqual(archive.read("syq/client.py"), python)
                sbom = json.loads(archive.read(SBOM))
                self.assertEqual(sbom["components"][1]["bom-ref"], "path+file:///external#other@1.0.0")
                rows = list(csv.reader(io.StringIO(archive.read(RECORD).decode())))
                self.assertEqual({r[0] for r in rows}, set(archive.namelist()))
                for name, digest, size in rows:
                    if name == RECORD:
                        self.assertEqual((digest, size), ("", ""))
                        continue
                    data = archive.read(name)
                    self.assertEqual(int(size), len(data))
                    actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                    self.assertEqual(digest, "sha256=" + actual)
            normalized = a.read_bytes()
            normalizer.normalize(a)
            self.assertEqual(a.read_bytes(), normalized)

    def test_unknown_sbom_layout_leaves_original_wheel_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "a.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(SBOM, b'{"metadata":{"component":{"bom-ref":"unexpected"}}}')
                archive.writestr(RECORD, b"")
            original = wheel.read_bytes()
            with self.assertRaises(ValueError):
                normalizer.normalize(wheel)
            self.assertEqual(wheel.read_bytes(), original)
            self.assertEqual(list(Path(directory).iterdir()), [wheel])
