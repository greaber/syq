#!/usr/bin/env python3
"""Check dispatch quoting, revision selection, and exact-run failure propagation."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "focused_check", Path(__file__).with_name("run-focused-check.py")
)
focused = importlib.util.module_from_spec(spec)
spec.loader.exec_module(focused)
SHA = "a" * 40


class DispatchTests(unittest.TestCase):
    def invoke(self, args, *, dirty=False, remote=SHA, watch_status=0, response=None):
        self.payload = None

        def output(*cmd, **kwargs):
            if cmd[:3] == ("gh", "repo", "view"):
                return "example/syq"
            if cmd[:2] == ("gh", "api"):
                if cmd[2].endswith("/dispatches"):
                    self.payload = json.loads(kwargs["input"])
                    self.assertIn("X-GitHub-Api-Version: 2026-03-10", cmd)
                    return json.dumps(response if response is not None else {"workflow_run_id": 123})
                self.assertIn("/commits/", cmd[2])
                return remote
            if cmd[:2] == ("git", "symbolic-ref"):
                return "task/example"
            if cmd[:2] == ("git", "status"):
                return " M file" if dirty else ""
            if cmd[:2] == ("git", "rev-parse"):
                return SHA
            self.fail(f"unexpected call: {cmd}")

        with patch.object(focused, "output", side_effect=output), \
                patch.object(focused.subprocess, "call", return_value=watch_status) as watch, \
                patch("sys.argv", ["run-focused-check.py", "--runner", "macos", *args]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            result = focused.main()
        self.watch = watch
        return result

    def test_command_arguments_stay_literal_and_exact_run_is_watched(self):
        command = ["printf", "%s\\n", "space and 'quotes'", "$(touch /unwanted)", "line\nbreak"]
        self.assertEqual(self.invoke(["--", *command]), 0)
        self.assertEqual(shlex.split(self.payload["inputs"]["script"]), command)
        self.assertEqual(self.payload["inputs"]["revision"], SHA)
        self.assertEqual(self.payload["ref"], "task/example")
        self.watch.assert_called_once_with(
            ["gh", "run", "watch", "123", "--repo", "example/syq", "--exit-status"]
        )

    def test_script_preserves_multiline_shell_and_failure_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "check.sh"
            script = "value='literal $HOME'\nprintf '%s\\n' \"$value\"\nfalse\n"
            path.write_text(script)
            self.assertEqual(self.invoke(["--script", str(path)], watch_status=1), 1)
            self.assertEqual(self.payload["inputs"]["script"], script)

    def test_default_ref_requires_clean_pushed_head(self):
        for options in ({"dirty": True}, {"remote": "b" * 40}):
            with self.subTest(options=options), self.assertRaises(SystemExit):
                self.invoke(["--", "true"], **options)
            self.assertIsNone(self.payload)

    def test_explicit_ref_can_test_remote_commit(self):
        self.invoke(["--ref", "other", "--cargo-cache", "--timeout", "3", "--", "true"],
                    dirty=True, remote="b" * 40)
        self.assertEqual(self.payload["ref"], "other")
        self.assertEqual(self.payload["inputs"]["revision"], "b" * 40)
        self.assertTrue(self.payload["inputs"]["cargo_cache"])
        self.assertEqual(self.payload["inputs"]["timeout"], 3)

    def test_missing_run_id_is_not_success(self):
        with self.assertRaises(ValueError):
            self.invoke(["--", "true"], response={})

    def test_invalid_request_does_not_dispatch(self):
        for args in ([], ["--timeout", "0", "--", "true"],
                     ["--script", "unused", "--", "true"]):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                self.invoke(args)
            self.assertIsNone(self.payload)


if __name__ == "__main__":
    unittest.main()
