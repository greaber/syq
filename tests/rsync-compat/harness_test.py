#!/usr/bin/env python3
"""Focused tests for the rsync compatibility harness itself."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "rsync-compat.py"
SPEC = importlib.util.spec_from_file_location("rsync_compat", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rsync_compat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rsync_compat)


def sample_report(tests: list[dict] | None = None) -> dict:
    tests = tests or []
    return {
        "upstream_commit": "abc123",
        "target_name": "rsync",
        "target_args": [],
        "platform": "linux",
        "run_as": "non-root",
        "selected_areas": [],
        "environment_excluded": [],
        "selection_excluded": [],
        "applicable": len(tests),
        "position_counts": {
            position: sum(test["position"] == position for test in tests)
            for position in rsync_compat.VALID_POSITIONS
        },
        "adapted": sum(test["classification"] == "adapted" for test in tests),
        "ledger": {
            "out-of-scope": 50,
            "unsupported": 30,
            "unassessed": 4,
        },
        "unsupported_features": [
            {
                "area": "filters",
                "reason": "unsupported-filters",
                "tests": 30,
                "description": "Filter behavior is not implemented.",
            }
        ],
        "tests": tests,
        "runner_exit_code": 0,
        "expected_runner_exit_code": 0,
        "parser_errors": [],
        "harness_errors": [],
        "harness_ok": True,
    }


class HarnessTests(unittest.TestCase):
    def test_scope_rejects_later_file_in_traditional_multi_file_patch(self) -> None:
        patch = b"""--- a/testsuite/README.md
+++ b/testsuite/README.md
@@ -1 +1 @@
-old
+new
--- a/flist.c
+++ b/flist.c
@@ -1 +1 @@
-old
+new
"""

        with self.assertRaisesRegex(rsync_compat.CompatError, "testsuite files"):
            rsync_compat.validate_adaptation_patch("bad-multi-file", patch)

    def test_scope_rejects_rename_source_outside_testsuite(self) -> None:
        patch = b"""diff --git a/flist.c b/testsuite/flist.c
similarity index 100%
rename from flist.c
rename to testsuite/flist.c
"""

        with self.assertRaisesRegex(rsync_compat.CompatError, "testsuite files"):
            rsync_compat.validate_adaptation_patch("bad-rename", patch)

    def test_scope_rejects_copy_source_outside_testsuite(self) -> None:
        patch = b"""diff --git a/flist.c b/testsuite/flist.c
similarity index 100%
copy from flist.c
copy to testsuite/flist.c
"""

        with self.assertRaisesRegex(rsync_compat.CompatError, "testsuite files"):
            rsync_compat.validate_adaptation_patch("bad-copy", patch)

    def test_scope_allows_testsuite_deletion(self) -> None:
        patch = b"""diff --git a/testsuite/old b/testsuite/old
deleted file mode 100644
--- a/testsuite/old
+++ /dev/null
@@ -1 +0,0 @@
-old
"""

        rsync_compat.validate_adaptation_patch("good-delete", patch)

    def test_ledger_requires_target_and_product_metadata(self) -> None:
        manifest = {
            "target": {"name": "rsync", "args": []},
            "reasons": {},
            "tests": [
                {
                    "name": "alpha",
                    "classification": "conformance",
                    "baseline": "pass",
                    "position": "compatible",
                }
            ],
        }
        inventory = {"alpha": ("conformance", None)}

        with mock.patch.object(
            rsync_compat, "upstream_test_names", return_value={"alpha"}
        ):
            with self.assertRaisesRegex(rsync_compat.CompatError, "area"):
                rsync_compat.validate_ledger(manifest, inventory, ROOT)

    def test_target_arguments_are_inserted_before_upstream_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper = Path(temporary) / "wrapper"
            rsync_compat.make_wrapper(
                wrapper,
                Path(sys.executable),
                ["-c", "import sys; print('|'.join(sys.argv[1:]))", "rsync"],
            )

            result = subprocess.run(
                [wrapper, "-a", "src", "dst"],
                text=True,
                capture_output=True,
                check=True,
            )

        self.assertEqual(result.stdout, "rsync|-a|src|dst\n")

    def test_adapted_scenario_provenance_names_its_upstream_source(self) -> None:
        test = {
            "name": "alpha-subcase",
            "upstream_test": "alpha",
            "classification": "adapted",
            "adaptation_kind": "subset",
            "adaptation": "alpha-split",
        }

        self.assertEqual(
            rsync_compat.provenance(test),
            "subset adaptation (alpha-split) of upstream alpha",
        )

    def test_unmodified_test_is_its_own_upstream_source(self) -> None:
        test = {"name": "alpha", "classification": "conformance"}

        self.assertEqual(rsync_compat.upstream_test_name(test), "alpha")

    def test_area_selection_precedes_environment_selection(self) -> None:
        manifest = {
            "tests": [
                {"name": "security-user", "area": "security"},
                {"name": "security-root", "area": "security", "run_as": "root"},
                {"name": "paths-user", "area": "paths"},
            ]
        }

        with mock.patch.object(rsync_compat, "platform_name", return_value="linux"):
            with mock.patch.object(rsync_compat, "running_as", return_value="non-root"):
                selected, environment_excluded, selection_excluded = (
                    rsync_compat.select_tests(manifest, {"security"})
                )

        self.assertEqual([test["name"] for test in selected], ["security-user"])
        self.assertEqual(
            [test["name"] for test in environment_excluded], ["security-root"]
        )
        self.assertEqual(
            [test["name"] for test in selection_excluded], ["paths-user"]
        )

    def test_historical_regression_refs_resolve(self) -> None:
        manifest = rsync_compat.load_manifest()
        regressions = rsync_compat.load_regressions()

        rsync_compat.validate_regressions(regressions, manifest)
        rendered = rsync_compat.render_regressions(regressions)

        self.assertIn("rsync-359", rendered)
        self.assertIn("source-read-failure-continues", rendered)

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

    def test_expected_failure_is_not_a_harness_error(self) -> None:
        expected, errors = rsync_compat.assess_harness(
            1, {"alpha": "fail", "beta": "pass"}, [], require_tests=True, applicable=2
        )

        self.assertEqual(expected, 1)
        self.assertEqual(errors, [])

    def test_runner_status_inconsistent_with_results_is_a_harness_error(self) -> None:
        expected, errors = rsync_compat.assess_harness(
            2, {"alpha": "fail"}, [], require_tests=True, applicable=1
        )

        self.assertEqual(expected, 1)
        self.assertRegex(errors[0], "runner exit code 2")

    def test_zero_applicable_tests_render_without_a_score(self) -> None:
        report = sample_report()

        markdown = rsync_compat.markdown_report(report)
        html = rsync_compat.html_report(report)

        self.assertIn("No tests apply", markdown)
        self.assertIn("No tests apply", html)
        self.assertNotIn("score", markdown.lower())

    def test_baseline_change_is_separate_from_harness_health(self) -> None:
        test = {
            "name": "alpha",
            "classification": "conformance",
            "adaptation": None,
            "adaptation_kind": None,
            "area": "paths",
            "position": "policy-open",
            "baseline": "pass",
            "actual": "fail",
            "baseline_matches": False,
            "circumstances": [],
            "note": "A <review> is needed.",
        }
        report = sample_report([test])

        markdown = rsync_compat.markdown_report(report)
        html = rsync_compat.html_report(report)

        self.assertIn("Harness execution: **complete**", markdown)
        self.assertIn("Observation changes requiring review", markdown)
        self.assertIn("A &lt;review&gt; is needed.", html)


if __name__ == "__main__":
    unittest.main()
