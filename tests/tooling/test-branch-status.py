#!/usr/bin/env python3
"""Exercise scripts/branch-status.py against a scratch repository and a fake gh
that serves controlled run and pull-request JSON."""
from support import SCRIPTS

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

STATUS = SCRIPTS / "branch-status.py"

FAKE_GH = """#!/bin/sh
case "$1:$2" in
  run:list)
    shift 2
    workflow=
    event=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --workflow) workflow=$2; shift 2 ;;
        --event) event=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    cat "$SYQ_TEST_RUNS_DIR/$workflow.$event.json"
    ;;
  pr:list)
    if [ "${SYQ_TEST_PR_JSON:-}" = FAIL ]; then
      echo 'GraphQL: simulated GraphQL failure' >&2
      exit 1
    elif [ -n "${SYQ_TEST_PR_JSON:-}" ]; then
      printf '[%s]\\n' "$SYQ_TEST_PR_JSON"
    else
      echo '[]'
    fi
    ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 2 ;;
esac
"""


class BranchStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syq-branch-status-test.")
        work = Path(self.temp.name)
        self.fakebin = work / "fakebin"
        self.runs = work / "runs"
        self.fakebin.mkdir()
        self.runs.mkdir()
        self.write_fake("gh", FAKE_GH)

        # A scratch repository with master and a task branch two commits ahead.
        self.repo = work / "repo"
        subprocess.run(["git", "init", "-q", "-b", "master", str(self.repo)], check=True)
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "test")
        self.git("commit", "-q", "--allow-empty", "-m", "initial")
        self.git("checkout", "-q", "-b", "task")
        self.git("commit", "-q", "--allow-empty", "-m", "first task commit")
        self.git("commit", "-q", "--allow-empty", "-m", "second task commit")
        self.head = self.git("rev-parse", "HEAD")
        self.short = self.git("rev-parse", "--short", "HEAD")
        self.previous = self.git("rev-parse", "HEAD^")
        self.master = self.git("rev-parse", "master")
        # The script fetches master from origin; a local bare repository stands in.
        self.origin = work / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "master", str(self.origin)], check=True)
        self.git("push", "-q", str(self.origin), "master")
        self.git("remote", "add", "origin", str(self.origin))
        self.missing_origin = work / "missing.git"

        for workflow in ("ci.yml", "rsync-compat.yml", "macos.yml"):
            self.set_run(workflow, "completed", "success")
            self.set_run(workflow, "completed", "success", "schedule")
        self.pr = {
            "number": 7, "url": "https://example.invalid/pull/7", "state": "OPEN",
            "isDraft": False, "baseRefName": "master", "headRefOid": self.head,
            "reviewDecision": "", "mergeStateStatus": "CLEAN",
            "statusCheckRollup": [{"name": "rust", "status": "COMPLETED", "conclusion": "SUCCESS"},
                                  {"name": "macos", "status": "COMPLETED", "conclusion": "SKIPPED"}]}

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              stdout=subprocess.PIPE, text=True).stdout.strip()

    def write_fake(self, name, content):
        path = self.fakebin / name
        path.write_text(content)
        path.chmod(0o755)

    def set_run(self, workflow, status, conclusion, event="push"):
        """Post-merge (push) runs by default; pass schedule for the nightly run."""
        (self.runs / f"{workflow}.{event}.json").write_text(json.dumps([{
            "headSha": self.master, "status": status, "conclusion": conclusion or None,
            "url": f"https://example.invalid/{workflow}/{event}",
            "createdAt": "2026-01-01T00:00:00Z", "databaseId": 1}]))

    def status(self, *args, pr=None, expected=0, split=False):
        result = subprocess.run(
            [str(STATUS), *args], cwd=self.repo, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if split else subprocess.STDOUT,
            env={**os.environ, "SYQ_TEST_RUNS_DIR": str(self.runs),
                 "SYQ_TEST_PR_JSON": "" if pr is None else pr if isinstance(pr, str) else json.dumps(pr),
                 "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}"})
        self.assertEqual(result.returncode, expected, result.stdout + (result.stderr or ""))
        return result if split else result.stdout

    def with_pr(self, **changes):
        return {**self.pr, **changes}

    def test_clean_branch_green_master_no_pull_request(self):
        output = self.status()
        self.assertIn(f"Branch:   task at {self.short} (clean)", output)
        self.assertIn("branch is ahead 2, behind 0", output)
        self.assertIn("ci.yml           success", output)
        self.assertIn("macos.yml        success", output)
        self.assertIn("Pull request: none for task", output)
        self.assertNotIn("WARNING", output)

    def test_matching_pull_request_with_passing_checks(self):
        output = self.status(pr=self.pr)
        self.assertIn("Pull request: #7 https://example.invalid/pull/7", output)
        self.assertIn(f"GitHub head {self.head[:7]}: matches local {self.short}", output)
        self.assertIn("checks: all completed successfully", output)
        self.assertNotIn("WARNING", output)

    def test_github_head_lagging_an_unpushed_commit(self):
        output = self.status(pr=self.with_pr(headRefOid=self.previous), expected=1)
        self.assertIn(f"GitHub head {self.previous[:7]}: github-behind local {self.short}", output)
        self.assertIn(f"WARNING: PR #7 head {self.previous[:7]} is behind local {self.short}; "
                      "push before reporting", output)

    def test_pull_request_checks_are_informational(self):
        # Failed pull-request checks do not gate the branch.
        rollup = [dict(self.pr["statusCheckRollup"][0], conclusion="FAILURE"),
                  self.pr["statusCheckRollup"][1]]
        output = self.status(pr=self.with_pr(statusCheckRollup=rollup))
        self.assertIn("failed checks: rust failure", output)
        self.assertNotIn("WARNING", output)
        # A failed commit status context is informational too.
        rollup = self.pr["statusCheckRollup"] + [{"context": "external", "state": "FAILURE"}]
        output = self.status(pr=self.with_pr(statusCheckRollup=rollup))
        self.assertIn("failed checks: external failure", output)
        self.assertNotIn("WARNING", output)
        # A pending commit status context is neither green nor a failure.
        rollup = self.pr["statusCheckRollup"] + [{"context": "external", "state": "PENDING"}]
        output = self.status(pr=self.with_pr(statusCheckRollup=rollup))
        self.assertIn("pending checks: external", output)
        self.assertNotIn("WARNING", output)
        # A pending pull-request check is reported without a warning.
        rollup = [{"name": "rust", "status": "IN_PROGRESS", "conclusion": None},
                  self.pr["statusCheckRollup"][1]]
        output = self.status(pr=self.with_pr(statusCheckRollup=rollup))
        self.assertIn("pending checks: rust", output)
        self.assertNotIn("WARNING", output)

    def test_empty_rollup_is_not_success(self):
        output = self.status(pr=self.with_pr(statusCheckRollup=[]))
        self.assertIn("checks: none registered yet", output)
        self.assertNotIn("all completed successfully", output)

    def test_pull_request_lookup_failure_is_an_error(self):
        output = self.status(pr="FAIL", expected=2)
        self.assertIn("could not look up the pull request for task", output)
        self.assertIn("simulated GraphQL failure", output)
        self.assertNotIn("Pull request: none", output)

    def test_red_post_merge_run_is_an_alert(self):
        self.set_run("macos.yml", "completed", "failure")
        output = self.status(expected=1)
        self.assertIn("macos.yml        failure", output)
        self.assertIn(f"WARNING: master is red: macos.yml post-merge failure at {self.master[:7]} "
                      "https://example.invalid/macos.yml/push", output)

    def test_run_in_progress_is_not_an_alert(self):
        self.set_run("macos.yml", "in_progress", "")
        output = self.status()
        self.assertIn("macos.yml        in_progress", output)
        self.assertNotIn("WARNING", output)

    def test_red_nightly_behind_a_green_post_merge_run(self):
        # A green post-merge run can skip checks that the red nightly full suite ran.
        self.set_run("rsync-compat.yml", "completed", "failure", "schedule")
        output = self.status(expected=1)
        self.assertIn("rsync-compat.yml success", output)
        self.assertIn(f"  nightly        failure      {self.master[:7]}  "
                      "https://example.invalid/rsync-compat.yml/schedule", output)
        self.assertIn(f"WARNING: master is red: rsync-compat.yml nightly failure at {self.master[:7]}",
                      output)
        report = json.loads(self.status("--json", expected=1))
        self.assertEqual(report["master_ci"][1]["state"], "success")
        self.assertEqual(report["master_ci"][1]["nightly"]["state"], "failure")
        self.assertEqual(report["exit_status"], 1)

    def test_nightly_in_progress_is_not_an_alert(self):
        self.set_run("rsync-compat.yml", "in_progress", "", "schedule")
        output = self.status()
        self.assertIn("  nightly        in_progress", output)
        self.assertNotIn("WARNING", output)

    def test_master_comes_from_a_fresh_fetch(self):
        # Not a stale local branch or tracking ref.
        self.git("push", "-q", "origin", f"{self.previous}:refs/heads/master")
        self.git("update-ref", "refs/remotes/origin/master", self.master)
        report = json.loads(self.status("--json"))
        self.assertEqual(report["worktree"]["master_ref"], "refs/remotes/origin/master")
        self.assertEqual(report["worktree"]["master"], self.previous)
        self.assertEqual(report["worktree"]["ahead_of_master"], 1)
        self.assertEqual(self.git("rev-parse", "master"), self.master)

    def test_unavailable_master_fails_without_a_report(self):
        # Without current master, ahead/behind counts would mislead; fail instead.
        self.git("remote", "set-url", "origin", str(self.missing_origin))
        output = self.status(expected=2)
        self.assertIn("could not fetch master from origin", output)
        self.assertNotIn("Master:", output)

    def test_dirty_worktree_is_stated_but_not_a_failure(self):
        (self.repo / "scratch").touch()
        output = self.status()
        self.assertIn(f"Branch:   task at {self.short} (dirty: 0 staged, 0 unstaged, 1 untracked)",
                      output)
        self.assertIn("WARNING: worktree is dirty: 0 staged, 0 unstaged, 1 untracked", output)

    def test_json_carries_the_same_facts(self):
        report = json.loads(self.status("--json", pr=self.pr))
        worktree = report["worktree"]
        self.assertEqual(worktree["branch"], "task")
        self.assertEqual(worktree["head"], self.head)
        self.assertIs(worktree["clean"], True)
        self.assertEqual(worktree["master"], self.master)
        self.assertEqual(worktree["ahead_of_master"], 2)
        self.assertEqual(worktree["behind_master"], 0)
        self.assertEqual([entry["state"] for entry in report["master_ci"]], ["success"] * 3)
        self.assertEqual([entry["nightly"]["state"] for entry in report["master_ci"]], ["success"] * 3)
        self.assertEqual(report["pull_request"]["number"], 7)
        self.assertEqual(report["pull_request_head"], "matches")
        self.assertEqual(report["warnings"], [])
        self.assertEqual(report["exit_status"], 0)
        self.set_run("ci.yml", "completed", "failure")
        report = json.loads(self.status("--json", expected=1))
        self.assertEqual(report["exit_status"], 1)
        self.assertEqual(len(report["warnings"]), 1)
        self.assertEqual(report["master_ci"][0]["state"], "failure")

    def test_json_check_stays_one_document(self):
        # --json --check stays one JSON document even when the checks write to stdout.
        self.write_fake("cargo", '#!/bin/sh\necho "fake cargo $*"\n[ "$1" != clippy ] || exit 1\n')
        result = self.status("--json", "--check", expected=1, split=True)
        self.assertIn("fake cargo clippy", result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["checks"], [
            {"name": "fmt", "command": "cargo fmt --all -- --check", "result": "pass"},
            {"name": "clippy", "command": "cargo clippy --locked --all-targets --all-features -- -D warnings",
             "result": "fail"},
            {"name": "unit-tests", "command": "cargo test --locked --bin syq", "result": "pass"}])
        self.assertEqual(report["warnings"], ["clippy failed"])
        self.assertEqual(report["exit_status"], 1)

    def test_check_generated_changes_fail_validation(self):
        # Check-generated changes must be visible in the final report.
        self.write_fake("cargo", "#!/bin/sh\ntouch generated\n")
        report = json.loads(self.status("--json", "--check", expected=1))
        self.assertIs(report["worktree"]["clean"], False)
        self.assertEqual(report["worktree"]["untracked"], 1)
        self.assertIn("worktree status changed during baseline checks; inspect changes and rerun "
                      "affected checks", report["warnings"])

    def test_check_that_moves_head_reports_nothing(self):
        # A check that moves HEAD cannot report its results against the new commit.
        self.write_fake("cargo", "#!/bin/sh\nif [ \"$1\" = test ]; then "
                                 "git commit -q --allow-empty -m 'moved during check'; fi\n")
        output = self.status("--check", expected=2)
        self.assertIn("HEAD changed during baseline checks", output)
        self.assertNotIn("Baseline checks (", output)

    def test_usage_errors(self):
        self.assertIn("usage:", self.status("--bogus", expected=2))


if __name__ == "__main__":
    unittest.main()
