#!/usr/bin/env python3
"""Reproduce Actions resolving a recently advanced branch to its old commit.

Exercises scripts/run-generated-sdk-post-merge-ci.py against a fake gh, and the
ci.yml `sdks` aggregate job against every dependency result.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
MERGE_SHA = "0123456789abcdef0123456789abcdef01234567"
STALE_SHA = "a" * 40
BRANCH = "automation/python-sdk-v0.1.9"

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
state = Path(os.environ["SYQ_TEST_STATE"])
args = sys.argv[1:]
with open(state / "calls", "a") as calls:
    calls.write(" ".join(args) + "\n")
count = int((state / "count").read_text())
merge = os.environ["SYQ_TEST_MERGE_SHA"]
stale_attempts = int(os.environ.get("SYQ_TEST_STALE_ATTEMPTS", "0"))
joined = " " + " ".join(args) + " "
def emit(value):
    print(json.dumps(value))
    sys.exit(0)
if args[:1] == ["api"]:
    if "/git/ref/heads/automation/python-sdk-v0.1.9 " in joined:
        sha = merge
        if os.environ.get("SYQ_TEST_REF_WRONG") == "true" or (
                os.environ.get("SYQ_TEST_REF_DRIFT") == "true" and count > 0):
            sha = "a" * 40
        emit({"object": {"sha": sha}})
    if "/actions/workflows/ci.yml/dispatches " in joined:
        if f" inputs[scope_commit]={merge} " not in joined:
            sys.exit("dispatch omitted scope commit")
        if " X-GitHub-Api-Version: 2026-03-10 " not in joined:
            sys.exit("dispatch omitted API version")
        count += 1
        (state / "count").write_text(f"{count}\n")
        if os.environ.get("SYQ_TEST_INVALID_RESPONSE") == "true":
            emit({})
        emit({"workflow_run_id": 500 + count})
    if "/jobs?per_page=100 " in joined:
        conclusion = os.environ.get("SYQ_TEST_SDK_CONCLUSION", "success")
        emit({"jobs": [{"name": "sdk-languages (python)", "status": "completed", "conclusion": conclusion},
                       {"name": "sdks", "status": "completed", "conclusion": conclusion}]})
    if "/actions/runs/" in joined:
        run_id = int(args[1].rsplit("/", 1)[1])
        sha = merge if count > stale_attempts else "a" * 40
        status = "queued"
        if (state / f"watched-{run_id}").exists() and os.environ.get("SYQ_TEST_UNFINISHED") != "true":
            status = "completed"
        emit({"id": run_id, "event": "workflow_dispatch", "head_sha": sha,
              "head_branch": os.environ.get("SYQ_TEST_RUN_BRANCH", "automation/python-sdk-v0.1.9"),
              "head_repository": {"full_name": "greaber/syq"}, "status": status})
    sys.exit(f"unexpected fake gh api invocation: {' '.join(args)}")
if args[:2] == ["run", "watch"]:
    (state / f"watched-{args[2]}").touch()
    sys.exit(0 if count > stale_attempts and os.environ.get("SYQ_TEST_WATCH_FAIL") != "true" else 1)
sys.exit(f"unexpected fake gh invocation: {' '.join(args)}")
'''

FAKE_SLEEP = '''#!/bin/sh
set -eu
[ "$1" = 5 ]
printf 'sleep %s\\n' "$1" >>"$SYQ_TEST_STATE/calls"
'''


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syq-sdk-dispatch-test.")
        self.state = Path(self.temp.name)
        bin_dir = self.state / "bin"
        bin_dir.mkdir()
        for name, content in (("gh", FAKE_GH), ("sleep", FAKE_SLEEP)):
            (bin_dir / name).write_text(content)
            (bin_dir / name).chmod(0o755)
        self.env = {**os.environ, "SYQ_TEST_STATE": str(self.state),
                    "SYQ_TEST_MERGE_SHA": MERGE_SHA,
                    "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}

    def tearDown(self):
        self.temp.cleanup()

    def dispatch(self, expected, dispatches, **variables):
        """Run one case; `expected` is "success", a failure message, or "" for
        any failure."""
        (self.state / "count").write_text("0\n")
        (self.state / "calls").write_text("")
        # Each case has its own monitor markers.
        for marker in self.state.glob("watched-*"):
            marker.unlink()
        result = subprocess.run(
            [str(SCRIPTS / "run-generated-sdk-post-merge-ci.py"), "greaber/syq", BRANCH, MERGE_SHA],
            env={**self.env, **variables}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if expected == "success":
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn(f"Post-merge Python SDK validation passed for {MERGE_SHA}", result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, "unexpected dispatch success")
            if expected:
                self.assertIn(expected, result.stdout)
        self.assertEqual(int((self.state / "count").read_text()), dispatches)
        return (self.state / "calls").read_text().splitlines()

    def test_immediate_success_watches_only_the_returned_run(self):
        calls = self.dispatch("success", 1)
        # A run-list lookup is deliberately unsupported: only the returned run can count.
        self.assertTrue(any(call.startswith("run watch 501 ") for call in calls), calls)

    def test_stale_run_finishes_and_backs_off_before_redispatch(self):
        calls = self.dispatch("success", 2, SYQ_TEST_STALE_ATTEMPTS="1")
        dispatches = [index for index, call in enumerate(calls) if "/dispatches " in call]
        watch = next(index for index, call in enumerate(calls) if call.startswith("run watch 501 "))
        self.assertLess(dispatches[0], watch)
        self.assertLess(watch, calls.index("sleep 5"))
        self.assertLess(calls.index("sleep 5"), dispatches[1])
        self.assertTrue(any(call.startswith("run watch 502 ") for call in calls))
        self.assertTrue(calls[-1].endswith("/actions/runs/502/jobs?per_page=100"))

    def test_gives_up_after_three_stale_runs(self):
        self.dispatch("after 3 attempts (last run 503)", 3, SYQ_TEST_STALE_ATTEMPTS="3")

    def test_unfinished_stale_run_blocks_redispatch(self):
        self.dispatch("not completed; refusing another dispatch", 1,
                      SYQ_TEST_STALE_ATTEMPTS="1", SYQ_TEST_UNFINISHED="true")

    def test_branch_must_point_to_the_merge_commit(self):
        self.dispatch("does not point to expected merge commit", 0, SYQ_TEST_REF_WRONG="true")
        self.dispatch("does not point to expected merge commit", 1,
                      SYQ_TEST_STALE_ATTEMPTS="1", SYQ_TEST_REF_DRIFT="true")

    def test_rejects_unexpected_or_invalid_dispatch_results(self):
        self.dispatch("unexpected workflow run", 1, SYQ_TEST_RUN_BRANCH="unrelated")
        self.dispatch("", 1, SYQ_TEST_INVALID_RESPONSE="true")
        self.dispatch("", 1, SYQ_TEST_WATCH_FAIL="true")

    def test_requires_a_successful_sdks_job(self):
        self.dispatch("sdks job is completed/failure", 1, SYQ_TEST_SDK_CONCLUSION="failure")
        self.dispatch("sdks job is completed/skipped", 1, SYQ_TEST_SDK_CONCLUSION="skipped")


class AggregateTests(unittest.TestCase):
    """Execute the `sdks` aggregate job's actual shell body."""

    def test_aggregate_requires_every_dependency_to_succeed(self):
        workflow = (SCRIPTS.parent / ".github/workflows/ci.yml").read_text()
        self.assertIn("\n    needs: [scope, sdk-languages]\n", workflow)
        job = re.search(r"^  sdks:\n(.*?)^  # The release workflow builds", workflow, re.M | re.S)
        self.assertIsNotNone(job)
        body = re.search(r"^        run: \|\n(.*?)(?:\n\n|\Z)", job.group(1), re.M | re.S)
        self.assertIsNotNone(body)
        aggregate = "\n".join(line.removeprefix("          ")
                              for line in body.group(1).splitlines() if line)
        self.assertTrue(aggregate)

        def passes(scope, sdk):
            return subprocess.run(["bash", "-euo", "pipefail", "-c", aggregate],
                                  env={**os.environ, "SCOPE_RESULT": scope, "SDK_RESULT": sdk}
                                  ).returncode == 0

        self.assertTrue(passes("success", "success"))
        for result in ("failure", "cancelled", "skipped"):
            self.assertFalse(passes("success", result), f"SDK aggregate accepted {result}")
            self.assertFalse(passes(result, "success"), f"SDK aggregate accepted failed scope {result}")


if __name__ == "__main__":
    unittest.main()
