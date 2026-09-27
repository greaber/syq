#!/usr/bin/env python3
"""New tooling tests are discovered; failures do not hide later results."""
from support import SCRIPTS

import contextlib
import importlib.util
import io
from pathlib import Path
import signal
import tempfile
import unittest

from tooling import ToolError

spec = importlib.util.spec_from_file_location("runner", SCRIPTS / "run-tooling-tests.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class DiscoveryTests(unittest.TestCase):
    def test_new_tests_run_and_failures_do_not_stop_discovery(self):
        with tempfile.TemporaryDirectory(prefix="syq-tooling-discovery-") as temporary:
            root = Path(temporary)
            (root / "support.py").write_text("raise AssertionError('not a test')\n")
            (root / "test-a.py").write_text("raise SystemExit(7)\n")
            (root / "test-b.sh").write_text("printf 'ran' > shell-result\n")
            handlers = {sig: signal.getsignal(sig) for sig in runner.ForwardSignals.SIGNALS}
            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    self.assertEqual(runner.run_tests(runner.discover(root), root), 1)
                self.assertIn("1 passed, 1 failed", output.getvalue())
                self.assertEqual((root / "shell-result").read_text(), "ran")
                (root / "test-a.py").write_text("pass\n")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(runner.run_tests(runner.discover(root), root), 0)
            finally:
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)

    def test_empty_directory_and_unknown_test_type_are_errors(self):
        with tempfile.TemporaryDirectory(prefix="syq-tooling-discovery-") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ToolError, "no tooling tests"):
                runner.discover(root)
            (root / "test-new.rb").write_text("")
            with self.assertRaisesRegex(ToolError, "unknown tooling test type"):
                runner.discover(root)


if __name__ == "__main__":
    unittest.main()
