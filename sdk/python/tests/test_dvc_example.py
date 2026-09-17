"""Run examples/dvc_syq.py against a DVC-layout repository built by hand.

The fixture writes the cache and remote layouts literally, so the test pins
the formats DVC 2 and DVC 3 produce without needing DVC installed.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

EXECUTABLE = os.environ.get("SYQ_CANDIDATE_EXECUTABLE")
SCRIPT = Path(__file__).resolve().parents[3] / "examples" / "dvc_syq.py"

FILES = {"data/a.txt": b"alpha\n", "data/sub/b.bin": bytes(range(256)) * 40, "model.bin": b"m" * 70000}
LEGACY = {"old.txt": b"written by DVC 2\r\n"}


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def store(remote: Path, digest: str, data: bytes, *, legacy: bool = False) -> None:
    tail = Path(digest[:2]) / digest[2:]
    path = remote / tail if legacy else remote / "files" / "md5" / tail
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


@unittest.skipUnless(EXECUTABLE, "the DVC example needs SYQ_CANDIDATE_EXECUTABLE")
class DvcExample(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo, self.remote, self.second = (self.base / n for n in ("repo", "remote", "second"))
        (self.repo / ".dvc").mkdir(parents=True)
        self.second.mkdir()
        (self.repo / ".dvc" / "config").write_text(
            f"[core]\n    remote = main\n['remote \"main\"']\n    url = {self.remote}\n"
            f"['remote \"second\"']\n    url = {self.second}\n"
        )
        listing = []
        for name, data in FILES.items():
            store(self.remote, md5(data), data)
            if name.startswith("data/"):
                listing.append({"md5": md5(data), "relpath": name.removeprefix("data/")})
        directory = json.dumps(listing).encode()
        store(self.remote, md5(directory) + ".dir", directory)
        (self.repo / "data.dvc").write_text(
            f"outs:\n- md5: {md5(directory)}.dir\n  nfiles: 2\n  hash: md5\n  path: data\n"
        )
        (self.repo / "model.bin.dvc").write_text(
            f"outs:\n- md5: {md5(FILES['model.bin'])}\n  hash: md5\n  path: model.bin\n"
        )
        for name, data in LEGACY.items():
            # DVC 2 named a text file after the MD5 of its contents with CRLF turned into LF.
            self.legacy_md5 = md5(data.replace(b"\r\n", b"\n"))
            store(self.remote, self.legacy_md5, data, legacy=True)
            (self.repo / f"{name}.dvc").write_text(f"outs:\n- md5: {self.legacy_md5}\n  path: {name}\n")

    def run_example(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args, "--syq", str(EXECUTABLE)],
            cwd=self.repo, capture_output=True, text=True, timeout=120,
        )

    def test_pull_then_push_round_trips_both_layouts(self) -> None:
        self.assertNotEqual(self.run_example("pull", ".").returncode, 0, "a directory needs -R")
        pulled = self.run_example("pull", "--verify", "-R", ".")
        self.assertEqual(pulled.returncode, 0, pulled.stderr)
        for name, data in {**FILES, **LEGACY}.items():
            self.assertEqual((self.repo / name).read_bytes(), data, name)
        self.assertEqual(tree(self.repo / ".dvc" / "cache"), tree(self.remote))

        again = self.run_example("pull", "-R", ".")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("0 not in the cache", again.stdout)

        (self.repo / "data" / "a.txt").write_bytes(b"edited locally\n")
        (self.repo / "data" / "stray.txt").write_bytes(b"not tracked\n")
        refused = self.run_example("pull", "data")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("data/a.txt", refused.stderr)
        self.assertIn("data/stray.txt", refused.stderr)
        self.assertEqual((self.repo / "data" / "a.txt").read_bytes(), b"edited locally\n")
        forced = self.run_example("pull", "--force", "data")
        self.assertEqual(forced.returncode, 0, forced.stderr)
        self.assertEqual((self.repo / "data" / "a.txt").read_bytes(), FILES["data/a.txt"])
        self.assertFalse((self.repo / "data" / "stray.txt").exists())

        pushed = self.run_example("push", "-r", "second", "-R", ".")
        self.assertEqual(pushed.returncode, 0, pushed.stderr)
        self.assertEqual(tree(self.second), tree(self.remote))

    def test_imported_data_is_left_to_dvc(self) -> None:
        (self.repo / "imported.dvc").write_text(
            "deps:\n- path: x\n  repo:\n    url: https://example.invalid/registry\n"
            "outs:\n- md5: 00000000000000000000000000000000\n  hash: md5\n  path: imported\n"
        )
        pulled = self.run_example("pull", "-R", ".")
        self.assertEqual(pulled.returncode, 0, pulled.stderr)
        self.assertIn("skipping imported.dvc", pulled.stdout)
        self.assertFalse((self.repo / "imported").exists())

    def test_a_corrupt_directory_listing_is_rejected(self) -> None:
        listing = next(self.remote.rglob("*.dir"))
        listing.write_bytes(b"[]")
        pulled = self.run_example("fetch", "--verify", "data")
        self.assertEqual(pulled.returncode, 23, pulled.stdout + pulled.stderr)

    def test_verify_covers_dvc2_files_and_is_off_by_default(self) -> None:
        store(self.remote, self.legacy_md5, b"not what DVC 2 stored", legacy=True)
        cached = self.repo / ".dvc" / "cache" / self.legacy_md5[:2] / self.legacy_md5[2:]
        checked = self.run_example("fetch", "--verify", "old.txt")
        self.assertNotEqual(checked.returncode, 0)
        self.assertFalse(cached.exists())
        unchecked = self.run_example("fetch", "old.txt")
        self.assertEqual(unchecked.returncode, 0, unchecked.stderr)
        self.assertTrue(cached.exists())

    def test_a_corrupt_object_fails_only_its_own_file(self) -> None:
        store(self.remote, md5(FILES["model.bin"]), b"not the model")
        pulled = self.run_example("fetch", "--verify", "-R", ".")
        self.assertEqual(pulled.returncode, 23, pulled.stdout + pulled.stderr)
        cache = tree(self.repo / ".dvc" / "cache")
        self.assertNotIn(f"files/md5/{md5(FILES['model.bin'])[:2]}/{md5(FILES['model.bin'])[2:]}", cache)
        self.assertIn(f"files/md5/{md5(FILES['data/a.txt'])[:2]}/{md5(FILES['data/a.txt'])[2:]}", cache)


if __name__ == "__main__":
    unittest.main()
