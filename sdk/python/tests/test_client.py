from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import syq


FAKE_SYQ = """#!/bin/sh
case "$1" in
  --version)
    printf 'syq 9.8.7\\n'
    ;;
  emit)
    printf '%s' "$2"
    printf 'diagnostic' >&2
    ;;
  fail)
    printf 'partial'
    printf 'failed' >&2
    exit 23
    ;;
  *)
    exit 2
    ;;
esac
"""


class ClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.executable = Path(self.temporary_directory.name) / "syq"
        self.executable.write_text(FAKE_SYQ, encoding="utf-8")
        self.executable.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_version(self) -> None:
        self.assertRegex(syq.__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(syq.version(executable=self.executable), "9.8.7")

    def test_run_preserves_one_argument_with_shell_metacharacters(self) -> None:
        argument = "a path; $(not-a-command)"
        result = syq.run(["emit", argument], executable=self.executable)
        self.assertEqual(result.argv, (os.fspath(self.executable), "emit", argument))
        self.assertEqual(result.stdout, argument.encode())
        self.assertEqual(result.stderr, b"diagnostic")

    def test_nonzero_result_is_retained(self) -> None:
        with self.assertRaises(syq.SyqProcessError) as caught:
            syq.run(["fail"], executable=self.executable)

        self.assertEqual(caught.exception.result.returncode, 23)
        self.assertEqual(caught.exception.result.stdout, b"partial")
        self.assertEqual(caught.exception.result.stderr, b"failed")

    def test_nonzero_result_can_be_returned(self) -> None:
        result = syq.run(["fail"], executable=self.executable, check=False)
        self.assertEqual(result.returncode, 23)

    def test_one_string_is_not_treated_as_an_argument_sequence(self) -> None:
        with self.assertRaisesRegex(TypeError, "individual arguments"):
            syq.run("emit", executable=self.executable)


if __name__ == "__main__":
    unittest.main()
