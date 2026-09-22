"""Check nightly selection without dispatching CI or requiring credentials."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("nightly", Path(__file__).with_name("nightly-ci.py"))
nightly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nightly)


class NightlyTests(unittest.TestCase):
    def invoke(self, runs, fingerprints):
        env = {"GITHUB_REPOSITORY": "example/repo", "GITHUB_WORKFLOW_REF":
               "example/repo/.github/workflows/ci.yml@refs/heads/master",
               "GITHUB_REF_NAME": "master", "GITHUB_SHA": "current"}
        with patch.dict(os.environ, env), patch.object(nightly.subprocess, "check_output",
                return_value=json.dumps({"workflow_runs": runs})) as api, \
                patch.object(nightly, "fingerprint", side_effect=fingerprints), \
                contextlib.redirect_stderr(io.StringIO()):
            result = nightly.main()
        self.assertIn("event=schedule&status=success&branch=master", api.call_args.args[0][-1])
        return result

    def test_first_night_runs(self):
        self.assertEqual(self.invoke([], []), 0)

    def test_same_inputs_skip_even_if_commit_changed(self):
        self.assertEqual(self.invoke([{"head_sha": "previous"}], ["same", "same"]), 3)

    def test_changed_inputs_run(self):
        self.assertEqual(self.invoke([{"head_sha": "previous"}], ["old", "new"]), 0)

    def test_comparison_errors_do_not_skip(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke([{"head_sha": "missing"}], subprocess.CalledProcessError(128, "git"))

    def test_schedule_scope_runs_skips_and_propagates_api_failure(self):
        root = Path(__file__).resolve().parent.parent
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"
            event.write_text(json.dumps({"schedule": "17 2 * * *"}))
            gh = Path(tmp) / "gh"
            gh.write_text("#!/bin/sh\n[ \"$FAIL_API\" != 1 ] || exit 1\nprintf '%s\\n' \"$RUNS\"\n")
            gh.chmod(0o755)
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"],
                       GITHUB_EVENT_NAME="schedule", GITHUB_REPOSITORY="example/repo",
                       GITHUB_WORKFLOW_REF="example/repo/.github/workflows/ci.yml@refs/heads/master",
                       GITHUB_REF_NAME="master", GITHUB_SHA=sha)
            for runs, full in [([], "true"), ([{"head_sha": sha}], "false")]:
                env["RUNS"] = json.dumps({"workflow_runs": runs})
                result = subprocess.run(["scripts/ci-scope.sh", str(event)], cwd=root, env=env,
                                        text=True, capture_output=True, check=True)
                self.assertIn(f"full_suite={full}\n", result.stdout)
                self.assertIn(f"linux_arm64={full}\n", result.stdout)
            env["FAIL_API"] = "1"
            result = subprocess.run(["scripts/ci-scope.sh", str(event)], cwd=root, env=env,
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("full_suite=false", result.stdout)


if __name__ == "__main__":
    unittest.main()
