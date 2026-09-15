from pathlib import Path
from importlib.metadata import PackageNotFoundError, PackagePath
import tempfile
import unittest
from unittest.mock import Mock, patch

import syq
from syq.bundled import bundled_executable


class BundledTests(unittest.TestCase):
    def test_distribution_record_selects_its_own_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "syq"
            executable.write_bytes(b"binary")
            package = Mock()
            package.files = [PackagePath("../../../bin/syq"), PackagePath("syq/client.py")]
            package.locate_file.return_value = executable
            with patch("syq.bundled.distribution", return_value=package):
                self.assertEqual(bundled_executable(), executable)
            package.locate_file.assert_called_once_with(PackagePath("../../../bin/syq"))

    def test_missing_distribution_has_actionable_error(self):
        with patch("syq.bundled.distribution", side_effect=PackageNotFoundError):
            with self.assertRaisesRegex(syq.SyqInstallError, "install its wheel"):
                bundled_executable()

    def test_missing_binary_does_not_fall_back_to_path_or_download(self):
        package = Mock(files=[PackagePath("syq/client.py")])
        with patch("syq.bundled.distribution", return_value=package):
            with self.assertRaisesRegex(syq.SyqInstallError, "no bundled executable"):
                bundled_executable()

    def test_explicit_cache_preserves_managed_download_selection(self):
        with patch("syq.client.managed_executable", return_value=Path("/cached/syq")) as managed:
            self.assertEqual(syq.Client(cache_dir="/cache")._executable_value(), "/cached/syq")
            managed.assert_called_once_with(cache_dir="/cache")
