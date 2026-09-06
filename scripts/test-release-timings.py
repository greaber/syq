#!/usr/bin/env python3
"""Unit checks for release timing selection and calculations."""

import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().with_name("release-timings.py")
SPEC = importlib.util.spec_from_file_location("release_timings", SCRIPT)
assert SPEC and SPEC.loader
release_timings = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_timings)


class ReleaseTimingTests(unittest.TestCase):
    def test_duration_and_display(self):
        self.assertEqual(
            release_timings.duration("2026-09-06T11:49:29Z", "2026-09-06T11:56:12Z"),
            403,
        )
        self.assertEqual(release_timings.format_duration(403), "6m 43s")
        self.assertIsNone(release_timings.duration("2026-09-06T11:49:29Z", None))

    def test_certification_prefers_latest_success(self):
        runs = [
            {"conclusion": "success", "created_at": "2026-09-06T01:00:00Z"},
            {"conclusion": "failure", "created_at": "2026-09-06T02:00:00Z"},
        ]
        self.assertIs(release_timings.selected_run("ci.yml", runs), runs[0])
        self.assertIs(release_timings.selected_run("release.yml", runs), runs[1])


if __name__ == "__main__":
    unittest.main()
