from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import syq


EXECUTABLE = os.environ.get("SYQ_CANDIDATE_EXECUTABLE")
EXPECTED_VERSION = os.environ.get("SYQ_CANDIDATE_VERSION")


@unittest.skipUnless(
    EXECUTABLE and EXPECTED_VERSION,
    "candidate compatibility requires SYQ_CANDIDATE_EXECUTABLE and version",
)
class CandidateCompatibilityTests(unittest.TestCase):
    def test_candidate_version_and_local_copy(self) -> None:
        assert EXECUTABLE is not None
        assert EXPECTED_VERSION is not None
        executable = Path(EXECUTABLE)
        self.assertEqual(syq.version(executable=executable), EXPECTED_VERSION)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source; $(not-a-command)"
            destination = root / "destination"
            source.write_bytes(b"candidate compatibility\n")

            result = syq.run(
                ["cp", source, "--as-new", destination, "--quiet"],
                executable=executable,
            )

            self.assertEqual(result.returncode, 0)
            self.assertEqual(destination.read_bytes(), source.read_bytes())

    def test_candidate_failure_is_retained(self) -> None:
        assert EXECUTABLE is not None
        result = syq.run(
            ["not-a-syq-command"],
            executable=EXECUTABLE,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)


if __name__ == "__main__":
    unittest.main()
