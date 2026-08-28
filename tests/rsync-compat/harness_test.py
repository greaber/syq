#!/usr/bin/env python3
"""Focused tests for the rsync compatibility harness itself."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "rsync-compat.py"
SPEC = importlib.util.spec_from_file_location("rsync_compat", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rsync_compat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rsync_compat)


class HarnessTests(unittest.TestCase):
    def test_adaptation_scope_rejects_deletion_outside_testsuite(self) -> None:
        patch = """diff --git a/testsuite/old b/testsuite/old
deleted file mode 100644
--- a/flist.c
+++ /dev/null
"""

        with self.assertRaisesRegex(rsync_compat.CompatError, "testsuite files"):
            rsync_compat.validate_adaptation_patch("bad-delete", patch)

    def test_adaptation_scope_rejects_rename_metadata_outside_testsuite(self) -> None:
        patch = """diff --git a/testsuite/old b/testsuite/new
similarity index 100%
rename from flist.c
rename to testsuite/new
"""

        with self.assertRaisesRegex(rsync_compat.CompatError, "testsuite files"):
            rsync_compat.validate_adaptation_patch("bad-rename", patch)

    def test_adaptation_scope_allows_testsuite_deletion(self) -> None:
        patch = """diff --git a/testsuite/old b/testsuite/old
deleted file mode 100644
--- a/testsuite/old
+++ /dev/null
"""

        rsync_compat.validate_adaptation_patch("good-delete", patch)

    def test_ledger_requires_expectations_for_every_enabled_profile(self) -> None:
        manifest = {
            "profiles": {
                "default": {"enabled": True},
                "strict": {"enabled": False},
            },
            "reasons": {},
            "tests": [
                {
                    "name": "root-only",
                    "classification": "conformance",
                    "expect": {},
                    "run_as": "root",
                }
            ],
        }
        inventory = {"root-only": ("conformance", None)}

        with mock.patch.object(
            rsync_compat, "upstream_test_names", return_value={"root-only"}
        ):
            with self.assertRaisesRegex(
                rsync_compat.CompatError, "no expectation for 'default'"
            ):
                rsync_compat.validate_ledger(manifest, inventory, ROOT)

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

    def test_runner_failure_suppresses_compatibility_score(self) -> None:
        report = {
            "upstream_commit": "abc123",
            "profile": "default",
            "platform": "linux",
            "run_as": "non-root",
            "applicable": 2,
            "passing": 1,
            "known_failures": 0,
            "skipped": 0,
            "adapted": 0,
            "ledger": {
                "out-of-scope": 0,
                "unsupported": 0,
                "unassessed": 0,
            },
            "score_percent": None,
            "tests": [
                {
                    "name": "alpha",
                    "actual": "pass",
                    "expected": "pass",
                    "matches": True,
                    "tags": [],
                    "note": "",
                },
                {
                    "name": "beta",
                    "actual": "notrun",
                    "expected": "pass",
                    "matches": False,
                    "tags": [],
                    "note": "",
                },
            ],
            "runner_exit_code": 2,
            "parser_errors": ["missing result for beta"],
        }

        markdown = rsync_compat.markdown_report(report)

        self.assertIn("Harness status: **FAILED**", markdown)
        self.assertIn("runner exit code `2`", markdown)
        self.assertIn("Compatibility score is unavailable", markdown)
        self.assertIn("Unreported after runner failure | 1", markdown)
        self.assertNotIn("Classified runnable-test pass rate", markdown)


if __name__ == "__main__":
    unittest.main()
