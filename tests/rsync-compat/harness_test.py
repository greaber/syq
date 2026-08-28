#!/usr/bin/env python3
"""Focused tests for the rsync compatibility harness itself."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "rsync-compat.py"
SPEC = importlib.util.spec_from_file_location("rsync_compat", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rsync_compat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rsync_compat)


class HarnessTests(unittest.TestCase):
    def test_stream_command_replaces_non_utf8_output(self) -> None:
        returncode, log = rsync_compat.stream_command(
            [sys.executable, "-c", "import os; os.write(1, b'before\\xffafter\\n')"],
            cwd=ROOT,
            env=os.environ.copy(),
        )

        self.assertEqual(returncode, 0)
        self.assertEqual(log, "before\N{REPLACEMENT CHARACTER}after\n")

    def test_parse_results_ignores_framed_test_logs(self) -> None:
        log = """----- alpha log follows
PASS beta
FAIL alpha
----- alpha log ends
FAIL    alpha
PASS    beta (0.12 seconds)
"""

        outcomes, errors = rsync_compat.parse_results(log, {"alpha", "beta"})

        self.assertEqual(outcomes, {"alpha": "fail", "beta": "pass"})
        self.assertEqual(errors, [])

    def test_parse_results_reports_duplicate_unknown_and_missing_results(self) -> None:
        log = """PASS    alpha
FAIL    alpha
PASS    stranger
"""

        outcomes, errors = rsync_compat.parse_results(log, {"alpha", "beta"})

        self.assertEqual(outcomes, {"alpha": "pass"})
        self.assertTrue(any("duplicate result for alpha" in error for error in errors))
        self.assertTrue(any("unexpected result for stranger" in error for error in errors))
        self.assertTrue(any("missing result for beta" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
