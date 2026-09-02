from __future__ import annotations

import gzip
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import syq
from syq import bootstrap


FAKE_BINARY = b"""#!/bin/sh
case "$1" in
  --version) printf 'syq 9.8.7\\n' ;;
  --build-identity) printf 'v9.8.7\\n' ;;
  *) exit 2 ;;
esac
"""
FAKE_ARCHIVE = gzip.compress(FAKE_BINARY, mtime=0)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _release(binary_bytes: bytes = FAKE_BINARY) -> dict[str, object]:
    archive_bytes = gzip.compress(binary_bytes, mtime=0)
    return {
        "repository": "https://github.com/greaber/syq",
        "tag": "v9.8.7",
        "version": "9.8.7",
        "artifacts": {
            "linux-x86_64": {
                "archive": {
                    "name": "syq-linux-x86_64.gz",
                    "sha256": _sha256(archive_bytes),
                    "size": len(archive_bytes),
                },
                "binary": {
                    "name": "syq-linux-x86_64",
                    "sha256": _sha256(binary_bytes),
                    "size": len(binary_bytes),
                },
            }
        },
    }


class _Response(io.BytesIO):
    def geturl(self) -> str:
        return "https://release-assets.githubusercontent.com/pinned"

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class BootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.cache = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _patch_release(self) -> tuple[mock._patch, mock._patch]:
        return (
            mock.patch.object(
                bootstrap, "_load_release_manifest", return_value=_release()
            ),
            mock.patch.object(bootstrap, "_host_target", return_value="linux-x86_64"),
        )

    def test_package_pin_matches_embedded_manifest(self) -> None:
        manifest_path = Path(bootstrap.__file__).with_name("syq-release-manifest.json")
        manifest = json.loads(manifest_path.read_bytes())
        self.assertEqual(syq.PINNED_SYQ_VERSION, manifest["version"])

    def test_downloads_validates_and_reuses_the_exact_binary(self) -> None:
        manifest_patch, target_patch = self._patch_release()
        download = mock.Mock(side_effect=lambda *args, **kwargs: _Response(FAKE_ARCHIVE))
        with manifest_patch, target_patch, mock.patch.object(
            bootstrap.urllib.request, "urlopen", download
        ):
            first = bootstrap.managed_executable(cache_dir=self.cache)
            second = bootstrap.managed_executable(cache_dir=self.cache)

        self.assertEqual(first, second)
        self.assertEqual(first.read_bytes(), FAKE_BINARY)
        self.assertTrue(first.stat().st_mode & 0o100)
        self.assertEqual(download.call_count, 1)

    def test_corrupt_cached_binary_is_replaced(self) -> None:
        manifest_patch, target_patch = self._patch_release()
        download = mock.Mock(side_effect=lambda *args, **kwargs: _Response(FAKE_ARCHIVE))
        with manifest_patch, target_patch, mock.patch.object(
            bootstrap.urllib.request, "urlopen", download
        ):
            executable = bootstrap.managed_executable(cache_dir=self.cache)
            executable.write_bytes(b"tampered")
            repaired = bootstrap.managed_executable(cache_dir=self.cache)

        self.assertEqual(repaired.read_bytes(), FAKE_BINARY)
        self.assertEqual(download.call_count, 2)

    def test_corrupt_download_is_rejected_without_installing(self) -> None:
        manifest_patch, target_patch = self._patch_release()
        corrupted = bytes([FAKE_ARCHIVE[0] ^ 1]) + FAKE_ARCHIVE[1:]
        with manifest_patch, target_patch, mock.patch.object(
            bootstrap.urllib.request,
            "urlopen",
            return_value=_Response(corrupted),
        ):
            with self.assertRaisesRegex(syq.SyqInstallError, "SHA-256"):
                bootstrap.managed_executable(cache_dir=self.cache)

        install_dir = (
            self.cache / "syq" / "sdk" / "python" / "v9.8.7" / "linux-x86_64"
        )
        self.assertEqual(list(install_dir.iterdir()), [])

    def test_hash_valid_binary_with_wrong_release_identity_is_rejected(self) -> None:
        wrong_binary = FAKE_BINARY.replace(b"v9.8.7", b"source-build")
        wrong_archive = gzip.compress(wrong_binary, mtime=0)
        with mock.patch.object(
            bootstrap, "_load_release_manifest", return_value=_release(wrong_binary)
        ), mock.patch.object(
            bootstrap, "_host_target", return_value="linux-x86_64"
        ), mock.patch.object(
            bootstrap.urllib.request,
            "urlopen",
            return_value=_Response(wrong_archive),
        ):
            with self.assertRaisesRegex(syq.SyqInstallError, "build identity"):
                bootstrap.managed_executable(cache_dir=self.cache)

    def test_supported_host_aliases_select_release_targets(self) -> None:
        cases = [
            ("Linux", "x86_64", "linux-x86_64"),
            ("Linux", "arm64", "linux-aarch64"),
            ("Darwin", "arm64", "macos-arm64"),
            ("Darwin", "amd64", "macos-x86_64"),
        ]
        for system, machine, expected in cases:
            with self.subTest(system=system, machine=machine), mock.patch.object(
                bootstrap.platform, "system", return_value=system
            ), mock.patch.object(
                bootstrap.platform, "machine", return_value=machine
            ):
                self.assertEqual(bootstrap._host_target(), expected)

    def test_unsupported_host_fails_before_downloading(self) -> None:
        with mock.patch.object(
            bootstrap.platform, "system", return_value="Windows"
        ), mock.patch.object(
            bootstrap.platform, "machine", return_value="x86_64"
        ), self.assertRaisesRegex(syq.SyqInstallError, "no binary"):
            bootstrap.managed_executable(cache_dir=self.cache)


if __name__ == "__main__":
    unittest.main()
