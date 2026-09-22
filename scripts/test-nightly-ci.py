"""Check nightly selection without dispatching CI or requiring credentials."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
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


if __name__ == "__main__":
    unittest.main()
