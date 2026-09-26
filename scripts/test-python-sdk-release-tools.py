#!/usr/bin/env python3
"""Exercise Python SDK release preparation and trusted pull-request selection.

select-trusted-pr.jq runs in the prepare-python-sdk workflow, so its checks
need jq.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
REPOSITORY = SCRIPTS.parent
SDK = REPOSITORY / "sdk/python"
MANIFEST = SDK / "src/syq/syq-release-manifest.json"


def pyproject_version(path):
    match = re.search(r'^version = "(.*)"', Path(path).read_text(), re.M)
    return match.group(1) if match else ""


def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(path for path in Path(root).rglob("*") if path.is_file()):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syq-python-sdk-release-test.")
        self.work = Path(self.temp.name)
        self.current_syq_version = json.loads(MANIFEST.read_text())["version"]
        major, minor, _ = self.current_syq_version.split(".", 2)
        # Use a non-patch increment so the test proves that the incoming syq version is
        # copied instead of independently incrementing the Python patch component.
        self.next_version = f"{major}.{int(minor) + 1}.0"
        current = json.loads(MANIFEST.read_text())
        candidate = {key: current[key] for key in ("schema", "repository")}
        candidate.update(version=self.next_version, tag=f"v{self.next_version}")
        candidate.update({key: current[key] for key in ("artifacts", "installer", "homebrew_formula",
                                                          "signature_scheme", "signature")})
        self.candidate = self.work / "candidate.json"
        self.candidate.write_text(json.dumps(candidate, indent=2, ensure_ascii=False) + "\n")

    def tearDown(self):
        self.temp.cleanup()

    def checkout(self, name):
        root = self.work / name
        (root / "sdk/python/src/syq").mkdir(parents=True)
        for relative in ("README-PYTHON.md", "pyproject.toml", "src/syq/syq-release-manifest.json"):
            shutil.copyfile(SDK / relative, root / "sdk/python" / relative)
        return root

    def prepare(self, root, manifest):
        return subprocess.run([sys.executable, str(SCRIPTS / "prepare-python-sdk-release.py"),
                               "--root", str(root), "--manifest", str(manifest)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def test_current_sdk_matches_its_pinned_syq_version(self):
        self.assertEqual(pyproject_version(SDK / "pyproject.toml"), self.current_syq_version)

    def test_preparation_copies_the_release_and_is_idempotent(self):
        root = self.checkout("sdk")
        result = self.prepare(root, self.candidate)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(f'version = "{self.next_version}"',
                      (root / "sdk/python/pyproject.toml").read_text().splitlines())
        self.assertEqual((SDK / "README-PYTHON.md").read_bytes(),
                         (root / "sdk/python/README-PYTHON.md").read_bytes())
        self.assertEqual(self.candidate.read_bytes(),
                         (root / "sdk/python/src/syq/syq-release-manifest.json").read_bytes())
        before = tree_digest(root / "sdk")
        result = self.prepare(root, self.candidate)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(tree_digest(root / "sdk"), before)

    def test_misaligned_python_and_syq_versions_fail(self):
        root = self.checkout("misaligned")
        pyproject = root / "sdk/python/pyproject.toml"
        pyproject.write_text(re.sub(r'(?m)^version = ".*"', 'version = "0.0.0"', pyproject.read_text()))
        result = self.prepare(root, self.candidate)
        self.assertNotEqual(result.returncode, 0, "misaligned Python and syq versions unexpectedly succeeded")
        self.assertIn(f"current Python SDK 0.0.0 does not match pinned syq {self.current_syq_version}",
                      result.stdout)

    def test_manifest_without_signature_or_with_extra_fields_fails(self):
        root = self.checkout("sdk")
        invalid = self.work / "invalid.json"
        manifest = json.loads(self.candidate.read_text())
        invalid.write_text(json.dumps({key: value for key, value in manifest.items() if key != "signature"}))
        result = self.prepare(root, invalid)
        self.assertNotEqual(result.returncode, 0, "manifest without a signature unexpectedly succeeded")
        self.assertIn("release manifest has no valid base64 signature", result.stdout)
        invalid.write_text(json.dumps({**manifest, "unexpected": True}))
        result = self.prepare(root, invalid)
        self.assertNotEqual(result.returncode, 0, "manifest with an unexpected field succeeded")
        self.assertIn("release manifest fields do not match the current schema", result.stdout)


class TrustedPullRequestTests(unittest.TestCase):
    def select(self, pull_requests):
        return subprocess.run(["jq", "-r", "--arg", "repository", "greaber/syq", "-f",
                               str(SCRIPTS / "select-trusted-pr.jq")],
                              input=json.dumps(pull_requests), stdout=subprocess.PIPE, text=True,
                              check=True).stdout.rstrip("\n")

    def test_selects_only_the_trusted_repository(self):
        trusted = "https://github.com/greaber/syq/pull/123"
        pull_requests = [
            {"headRepository": {"nameWithOwner": "attacker/syq"},
             "url": "https://github.com/greaber/syq/pull/122"},
            {"headRepository": {"nameWithOwner": "greaber/syq"}, "url": trusted},
        ]
        self.assertEqual(self.select(pull_requests), trusted)
        untrusted = [pr for pr in pull_requests if pr["headRepository"]["nameWithOwner"] != "greaber/syq"]
        self.assertEqual(self.select(untrusted), "")


if __name__ == "__main__":
    unittest.main()
