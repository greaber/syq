#!/usr/bin/env python3
"""Exercise scripts/branch-status.py against a scratch repository and a fake gh
that serves controlled run, job, and pull-request JSON."""
from support import SCRIPTS

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

STATUS = SCRIPTS / "branch-status.py"
PR_CHECKS = SCRIPTS / "pr-checks.py"

FAKE_GH = """#!/bin/sh
case "$1:$2" in
  api:--method)
    python3 - "$@" <<'FAKE_POST'
import json, os, sys
from pathlib import Path
data = Path(os.environ["SYQ_TEST_RUNS_DIR"])
args = sys.argv[1:]
assert args[:3] == ["api", "--method", "POST"]
fields = dict(value.split("=", 1) for value in args[5::2])
(data / "posted.json").write_text(json.dumps({"endpoint": args[3], **fields}))
path = data / "statuses.json"
pages = json.loads(path.read_text()) if path.exists() else [[]]
pages[0].insert(0, dict(fields, creator={"login": "maintainer"},
                        created_at="2026-02-04T00:00:00Z", url="https://api.example/status/1"))
path.write_text(json.dumps(pages))
print("{}")
FAKE_POST
    ;;
  api:repos/*/commits/*)
    if [ -f "$SYQ_TEST_RUNS_DIR/fail-status-read" ]; then
      echo 'simulated status read failure' >&2
      exit 1
    fi
    printf '%s\\n' "$2" >> "$SYQ_TEST_RUNS_DIR/status-requests"
    file="$SYQ_TEST_RUNS_DIR/statuses.json"
    if [ -f "$file" ]; then cat "$file"; else echo '[[]]'; fi
    ;;
  run:list)
    shift 2
    workflow=
    event=
    branch=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --workflow) workflow=$2; shift 2 ;;
        --event) event=$2; shift 2 ;;
        --branch) branch=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    # A branch-specific file stands in for runs that a query across every
    # branch would not reach. Runs without headBranch are on master.
    file="$SYQ_TEST_RUNS_DIR/$workflow.$event.json"
    if [ -n "$branch" ] && [ -f "$SYQ_TEST_RUNS_DIR/$workflow.$event.branch-$branch.json" ]; then
      file="$SYQ_TEST_RUNS_DIR/$workflow.$event.branch-$branch.json"
    fi
    if [ ! -f "$file" ]; then
      echo '[]'
    elif [ -n "$branch" ]; then
      python3 -c 'import json, sys; print(json.dumps([run for run in json.load(open(sys.argv[1]))
        if run.get("headBranch", "master") == sys.argv[2]]))' "$file" "$branch"
    else
      cat "$file"
    fi
    ;;
  run:view)
    cat "$SYQ_TEST_RUNS_DIR/jobs-$3.json"
    ;;
  pr:view)
    printf '%s\n' "$SYQ_TEST_PR_JSON"
    ;;
  pr:list)
    case " $* " in
      *" merged "*"--head "*) printf '%s\n' "${SYQ_TEST_BRANCH_MERGED_JSON:-${SYQ_TEST_MERGED_JSON:-[]}}"; exit 0 ;;
      *" merged "*) printf '%s\n' "${SYQ_TEST_MERGED_JSON:-[]}"; exit 0 ;;
    esac
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
        # The master runs above are not full-suite runs.
        (self.runs / "jobs-1.json").write_text('{"jobs": []}')
        self.pr = {
            "number": 7, "url": "https://example.invalid/pull/7", "state": "OPEN",
            "isDraft": False, "baseRefName": "master", "headRefOid": self.head,
            "reviewDecision": "", "mergeStateStatus": "CLEAN",
            "statusCheckRollup": [{"name": "rust", "status": "COMPLETED", "conclusion": "SUCCESS"},
                                  {"name": "macos", "status": "COMPLETED", "conclusion": "SKIPPED"}]}
        self.merged = []
        self.branch_merged = None
        self.dispatched = {}

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              stdout=subprocess.PIPE, text=True).stdout.strip()

    def write_fake(self, name, content):
        path = self.fakebin / name
        path.write_text(content)
        path.chmod(0o755)

    def set_run(self, workflow, status, conclusion, event="push", run_id=1, attempt=1):
        """Post-merge (push) runs by default; pass schedule for the nightly run."""
        (self.runs / f"{workflow}.{event}.json").write_text(json.dumps([{
            "headSha": self.master, "status": status, "conclusion": conclusion or None,
            "url": f"https://example.invalid/{workflow}/{event}",
            "createdAt": "2026-01-01T00:00:00Z", "databaseId": run_id, "attempt": attempt}]))

    def dispatch(self, workflow, run_id, created, jobs, branch="task", status="completed",
                 head=None):
        """Record a manually dispatched run and its jobs as {name: conclusion}."""
        # As on GitHub, one cancelled job makes the whole run cancelled.
        conclusions = [conclusion for conclusion in jobs.values() if conclusion]
        conclusion = ("" if status != "completed" else "cancelled" if "cancelled" in conclusions
                      else "failure" if set(conclusions) & {"failure", "timed_out"}
                      else "success")
        self.dispatched.setdefault(workflow, []).append({
            "databaseId": run_id, "headBranch": branch, "headSha": head or self.head,
            "createdAt": created, "status": status, "conclusion": conclusion,
            "url": f"https://example.invalid/runs/{run_id}"})
        (self.runs / f"{workflow}.workflow_dispatch.json").write_text(
            json.dumps(self.dispatched[workflow]))
        (self.runs / f"jobs-{run_id}.json").write_text(json.dumps({"jobs": [
            {"name": name, "conclusion": conclusion, "databaseId": run_id * 100 + index,
             "url": f"https://example.invalid/runs/{run_id}/{name}"}
            for index, (name, conclusion) in enumerate(jobs.items())]}))

    def full_run(self, workflow, run_id, created, event="schedule", jobs=None):
        """Add a successful run on master with the given (default certified) jobs,
        after the runs that the master status lines report."""
        path = self.runs / f"{workflow}.{event}.json"
        runs = json.loads(path.read_text()) if path.exists() else []
        path.write_text(json.dumps(runs + [{
            "databaseId": run_id, "headSha": self.master, "createdAt": created,
            "status": "completed", "conclusion": "success",
            "url": f"https://example.invalid/runs/{run_id}"}]))
        jobs = jobs or {"rust": "success", "release-certification": "success"}
        (self.runs / f"jobs-{run_id}.json").write_text(json.dumps({"jobs": [
            {"name": name, "conclusion": conclusion} for name, conclusion in jobs.items()]}))

    def status(self, *args, pr=None, expected=0, split=False, script=STATUS):
        result = subprocess.run(
            [str(script), *args], cwd=self.repo, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if split else subprocess.STDOUT,
            env={**os.environ, "SYQ_TEST_RUNS_DIR": str(self.runs),
                 "SYQ_TEST_MERGED_JSON": json.dumps(self.merged),
                 "SYQ_TEST_BRANCH_MERGED_JSON": "" if self.branch_merged is None
                 else json.dumps(self.branch_merged),
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

    def test_red_post_merge_run_is_noted_without_failing_the_branch(self):
        self.set_run("macos.yml", "completed", "failure")
        output = self.status()
        self.assertIn("macos.yml        failure", output)
        self.assertIn(f"NOTE: master is red: macos.yml post-merge failure at {self.master[:7]} "
                      "https://example.invalid/macos.yml/push", output)
        self.assertNotIn("WARNING", output)

    def test_run_in_progress_is_not_an_alert(self):
        self.set_run("macos.yml", "in_progress", "")
        output = self.status()
        self.assertIn("macos.yml        in_progress", output)
        self.assertNotIn("WARNING", output)

    def test_red_nightly_behind_a_green_post_merge_run(self):
        # A green post-merge run can skip checks that the red nightly full suite ran.
        self.set_run("rsync-compat.yml", "completed", "failure", "schedule")
        output = self.status()
        self.assertIn("rsync-compat.yml success", output)
        self.assertIn(f"  nightly        failure      {self.master[:7]}  "
                      "https://example.invalid/rsync-compat.yml/schedule", output)
        self.assertIn(f"NOTE: master is red: rsync-compat.yml nightly failure at {self.master[:7]}",
                      output)
        report = json.loads(self.status("--json"))
        self.assertEqual(report["master_ci"][1]["state"], "success")
        self.assertEqual(report["master_ci"][1]["nightly"]["state"], "failure")
        self.assertEqual(len(report["notes"]), 1)
        self.assertEqual(report["exit_status"], 0)

    def address(self, run_id=101, reason="Repair merged; focused checks passed",
                fix="https://example.invalid/pull/9", expected=0):
        return self.status("--address-master-run", str(run_id), "--reason", reason,
                           "--fix", fix, expected=expected)

    def test_addressed_nightly_preserves_failure_without_repeating_note(self):
        self.set_run("macos.yml", "completed", "failure", "schedule", run_id=101)
        self.address()
        posted = json.loads((self.runs / "posted.json").read_text())
        self.assertEqual(posted, {
            "endpoint": f"repos/greaber/syq/statuses/{self.master}",
            "state": "success", "context": "master-ci-addressed/101/1",
            "description": "Repair merged; focused checks passed",
            "target_url": "https://example.invalid/pull/9"})
        report = json.loads(self.status("--json"))
        nightly = report["master_ci"][2]["nightly"]
        self.assertEqual(nightly["state"], "failure")
        self.assertEqual(nightly["run"]["conclusion"], "failure")
        self.assertEqual(nightly["run"]["resolution"]["actor"], "maintainer")
        self.assertEqual(report["notes"], [])
        text = self.status()
        self.assertIn("nightly        addressed", text)
        self.assertIn("original result: failure", text)
        self.assertIn("https://example.invalid/pull/9", text)
        self.assertNotIn("master is red", text)

    def test_addressing_does_not_hide_other_runs_reruns_or_branch_failures(self):
        self.set_run("macos.yml", "completed", "failure", "schedule", run_id=101)
        self.address()
        self.set_run("ci.yml", "completed", "failure", run_id=102)
        self.dispatch("ci.yml", 201, "2026-02-01T00:00:00Z", {"rust": "failure"})
        report = json.loads(self.status("--json", pr=self.pr, expected=1))
        self.assertEqual(len(report["notes"]), 1)
        self.assertIn("ci.yml post-merge failure", report["notes"][0])
        self.assertEqual(len(report["dispatched"]["failed"]), 1)
        self.set_run("macos.yml", "completed", "failure", "schedule", run_id=101, attempt=2)
        report = json.loads(self.status("--json", expected=1))
        self.assertEqual(len(report["notes"]), 2)
        self.assertNotIn("resolution", report["master_ci"][2]["nightly"]["run"])
        self.set_run("macos.yml", "completed", "failure", "schedule", run_id=103)
        self.assertIn("macos.yml nightly failure", self.status(expected=1))

    def test_addressing_post_merge_run_and_revoking_acknowledgment(self):
        self.set_run("ci.yml", "completed", "failure", run_id=101)
        self.address()
        self.assertNotIn("master is red", self.status())
        path = self.runs / "statuses.json"
        pages = json.loads(path.read_text())
        pages[0].insert(0, dict(pages[0][0], state="failure"))
        path.write_text(json.dumps(pages))
        self.assertIn("ci.yml post-merge failure", self.status())

    def test_invalid_or_unreadable_acknowledgments_do_not_suppress_failure(self):
        self.set_run("macos.yml", "completed", "failure", "schedule", run_id=101)
        self.address()
        path = self.runs / "statuses.json"
        resolution = json.loads(path.read_text())[0][0]
        for change in ({"description": ""}, {"target_url": None}, {"state": "pending"},
                       {"context": "dispatched-resolution/7/101"}):
            with self.subTest(change=change):
                path.write_text(json.dumps([[dict(resolution, **change)]]))
                self.assertIn("macos.yml nightly failure", self.status())
        (self.runs / "fail-status-read").touch()
        result = self.status("--json", expected=2, split=True)
        self.assertEqual(result.stdout, "")
        self.assertIn("simulated status read failure", result.stderr)

    def test_address_requires_current_failed_master_run(self):
        self.address(expected=2)
        self.set_run("macos.yml", "in_progress", "", "schedule", run_id=101)
        self.address(expected=2)
        self.set_run("macos.yml", "completed", "success", "schedule", run_id=101)
        self.address(expected=2)
        self.set_run("macos.yml", "completed", "failure", "schedule", run_id=102)
        self.address(expected=2)
        self.assertFalse((self.runs / "posted.json").exists())

    def test_address_requires_reason_fix_and_no_report_flags(self):
        self.set_run("macos.yml", "completed", "failure", "schedule", run_id=101)
        for reason in ("", "two\nlines", "x" * 141):
            self.address(reason=reason, expected=2)
        for fix in ("", "http://example.invalid/fix", "https://example.invalid/two words"):
            self.address(fix=fix, expected=2)
        self.address(run_id=-1, expected=2)
        self.status("--reason", "missing run", expected=2)
        self.status("--address-master-run", "101", expected=2)
        for flag in ("--json", "--check"):
            self.status("--address-master-run", "101", "--reason", "fixed", "--fix",
                        "https://example.invalid/fix", flag, expected=2)
        self.assertFalse((self.runs / "posted.json").exists())

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
        report = json.loads(self.status("--json"))
        self.assertEqual(report["exit_status"], 0)
        self.assertEqual(len(report["notes"]), 1)
        self.assertEqual(report["master_ci"][0]["state"], "failure")
        report = json.loads(self.status("--json", pr=self.with_pr(headRefOid=self.previous),
                                        expected=1))
        self.assertEqual(report["exit_status"], 1)
        self.assertEqual(len(report["warnings"]), 1)

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
            {"name": "unit-tests", "command": "cargo nextest run --locked --bin syq", "result": "pass"}])
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

    def test_failed_dispatched_check_blocks_until_a_later_run_passes(self):
        self.dispatch("ci.yml", 11, "2026-02-01T00:00:00Z",
                      {"s3": "failure", "real-ssh (core, default)": "success"}, head=self.previous)
        output = self.status(expected=1)
        self.assertIn(f"  failed   ci.yml s3 at {self.previous[:7]}  "
                      "https://example.invalid/runs/11/s3", output)
        self.assertIn(f"WARNING: ci.yml s3 failure at {self.previous[:7]} on this branch, and no "
                      "later run passed it https://example.invalid/runs/11/s3", output)
        # A later run of other checks does not resolve it; a still-running one is listed.
        self.dispatch("ci.yml", 12, "2026-02-02T00:00:00Z", {"rust": "success"})
        self.dispatch("ci.yml", 13, "2026-02-03T00:00:00Z", {"s3": None}, status="in_progress")
        report = json.loads(self.status("--json", expected=1))
        self.assertEqual([entry["job"] for entry in report["dispatched"]["failed"]], ["s3"])
        self.assertEqual([run["databaseId"] for run in report["dispatched"]["running"]], [13])
        # Passed checks are listed with the commit they ran at.
        self.assertEqual([(entry["job"], entry["conclusion"]) for entry in report["dispatched"]["results"]],
                         [("s3", "failure"), ("real-ssh (core, default)", "success"), ("rust", "success")])
        # A later pass of the same job resolves it.
        self.dispatch("ci.yml", 14, "2026-02-04T00:00:00Z", {"s3": "success"})
        output = self.status()
        self.assertIn(f"  passed   ci.yml s3 at {self.short}  https://example.invalid/runs/14/s3", output)
        self.assertIn(f"  passed   ci.yml real-ssh (core, default) at {self.previous[:7]}", output)
        self.assertIn(f"  running  ci.yml at {self.short}  https://example.invalid/runs/13", output)
        self.assertNotIn("failed   ci.yml", output)
        self.assertNotIn("WARNING", output)

    def test_failure_in_a_cancelled_run_is_reported(self):
        self.dispatch("ci.yml", 15, "2026-02-01T00:00:00Z",
                      {"real-ssh (core, default)": "failure", "object-storage": "cancelled"})
        report = json.loads(self.status("--json", expected=1))
        self.assertEqual([entry["job"] for entry in report["dispatched"]["failed"]],
                         ["real-ssh (core, default)"])

    def test_a_cancelled_rerun_does_not_replace_a_result(self):
        self.dispatch("ci.yml", 17, "2026-02-01T00:00:00Z", {"s3": "failure", "rust": "success"})
        self.dispatch("ci.yml", 18, "2026-02-02T00:00:00Z",
                      {"s3": "cancelled", "rust": "cancelled", "sdks": "cancelled",
                       "macos": "skipped"})
        report = json.loads(self.status("--json", expected=1))
        self.assertEqual([(entry["job"], entry["conclusion"]) for entry in report["dispatched"]["results"]],
                         [("s3", "failure"), ("rust", "success"), ("sdks", "cancelled")])
        self.assertIn("  cancelled ci.yml sdks at", self.status(expected=1))

    def test_this_branch_is_queried_beyond_the_shared_window(self):
        # Runs on busy branches can push this branch's run out of the shared list.
        self.dispatch("ci.yml", 16, "2026-02-01T00:00:00Z", {"s3": "failure"})
        (self.runs / "ci.yml.workflow_dispatch.branch-task.json").write_text(
            json.dumps(self.dispatched["ci.yml"]))
        (self.runs / "ci.yml.workflow_dispatch.json").write_text("[]")
        self.assertIn("  failed   ci.yml s3", self.status(expected=1))

    def test_checks_are_matched_by_workflow_and_job_name(self):
        self.dispatch("focused-check.yml", 21, "2026-02-01T00:00:00Z",
                      {"check (linux, namespace, script aaa)": "failure"})
        self.dispatch("focused-check.yml", 22, "2026-02-02T00:00:00Z",
                      {"check (linux, namespace, script bbb)": "success"})
        self.dispatch("macos.yml", 23, "2026-02-03T00:00:00Z",
                      {"check (linux, namespace, script aaa)": "success"})
        report = json.loads(self.status("--json", expected=1))
        self.assertEqual([(entry["workflow"], entry["job"]) for entry in report["dispatched"]["failed"]],
                         [("focused-check.yml", "check (linux, namespace, script aaa)")])

    def test_other_branches_and_an_earlier_pull_request_are_ignored(self):
        self.dispatch("ci.yml", 31, "2026-02-01T00:00:00Z", {"s3": "failure"}, branch="other")
        # An earlier pull request from the same branch name merged after this failure.
        self.dispatch("ci.yml", 32, "2026-02-01T00:00:00Z", {"rust": "failure"})
        self.merged = [{"number": 5, "url": "https://example.invalid/pull/5", "headRefName": "task",
                        "mergedAt": "2026-02-02T00:00:00Z", "isCrossRepository": False}]
        self.full_run("ci.yml", 90, "2026-02-03T00:00:00Z")
        output = self.status()
        self.assertIn("Dispatched checks on task (latest result of each, then unfinished runs):\n  none\n", output)
        self.assertNotIn("WARNING", output)

    def test_an_old_merge_of_this_branch_name_is_found_directly(self):
        # The earlier pull request from this branch name is older than the recent
        # merges shared with other branches, so it is looked up by name.
        self.dispatch("ci.yml", 33, "2026-01-01T00:00:00Z", {"s3": "failure"})
        self.branch_merged = [{"number": 2, "url": "https://example.invalid/pull/2",
                               "headRefName": "task", "mergedAt": "2026-01-02T00:00:00Z",
                               "isCrossRepository": False}]
        self.assertIn("unfinished runs):\n  none\n", self.status())

    def test_failure_left_by_a_merge_is_reported_until_a_full_run_on_master(self):
        self.dispatch("ci.yml", 41, "2026-02-01T00:00:00Z", {"s3": "failure"}, branch="merged-task")
        # Runs after the merge belong to later work that reuses the branch name.
        self.dispatch("ci.yml", 42, "2026-02-05T00:00:00Z", {"s3": "success"}, branch="merged-task")
        self.merged = [{"number": 6, "url": "https://example.invalid/pull/6",
                        "headRefName": "merged-task", "mergedAt": "2026-02-02T00:00:00Z",
                        "isCrossRepository": False}]
        # A failure elsewhere is noted without failing this branch.
        output = self.status()
        self.assertIn("Failures left by merged pull requests (until a full run on master passes):",
                      output)
        self.assertIn(f"  #6 ci.yml s3 at {self.head[:7]}", output)
        self.assertIn("NOTE: #6 merged with ci.yml s3 failure", output)
        self.assertNotIn("WARNING", output)
        # A nightly that skipped unchanged inputs, or one before the merge, does not clear it.
        self.full_run("ci.yml", 91, "2026-02-03T00:00:00Z",
                      jobs={"rust": "success", "nightly-unchanged": "success"})
        self.assertIn("NOTE: #6", self.status())
        self.full_run("ci.yml", 92, "2026-02-01T12:00:00Z")
        self.assertIn("NOTE: #6", self.status())
        self.full_run("ci.yml", 93, "2026-02-03T00:00:00Z", event="workflow_dispatch")
        output = self.status()
        self.assertNotIn("Failures left by merged", output)
        # Many later pushes do not hide the full run that cleared it.
        (self.runs / "ci.yml.push.json").write_text(json.dumps([
            {"headSha": self.master, "status": "completed", "conclusion": "success",
             "url": "https://example.invalid/push", "createdAt": f"2026-02-04T00:{minute:02}:00Z",
             "databaseId": 200 + minute} for minute in range(30)]))
        self.assertNotIn("NOTE: #6", self.status())
        # A cross-repository pull request's branch name says nothing about these runs.
        self.merged[0]["isCrossRepository"] = True
        (self.runs / "ci.yml.workflow_dispatch.json").write_text(
            json.dumps(self.dispatched["ci.yml"]))
        self.assertNotIn("NOTE: #6", self.status())

    def test_merged_focused_failure_waits_for_both_native_suites(self):
        self.dispatch("focused-check.yml", 51, "2026-02-01T00:00:00Z",
                      {"check (macos, namespace, script ccc)": "failure"}, branch="merged-task")
        self.merged = [{"number": 8, "url": "https://example.invalid/pull/8",
                        "headRefName": "merged-task", "mergedAt": "2026-02-02T00:00:00Z",
                        "isCrossRepository": False}]
        self.full_run("ci.yml", 94, "2026-02-03T00:00:00Z")
        self.assertIn("NOTE: #8", self.status())
        self.full_run("macos.yml", 95, "2026-02-03T00:00:00Z")
        self.assertNotIn("NOTE: #8", self.status())

    def test_usage_errors(self):
        self.assertIn("usage:", self.status("--bogus", expected=2))
        for args in ([], ["7", "8"], ["--bogus"]):
            self.assertIn("usage:", self.status(*args, expected=2, script=PR_CHECKS))

    def pr_checks(self, *args, expected=0, **changes):
        pr = {"number": 7, "url": "https://example.invalid/pull/7", "state": "OPEN",
              "headRefName": "task", "headRefOid": self.head, "mergedAt": None,
              "isCrossRepository": False, **changes}
        return self.status(*args, "7", pr=pr, expected=expected, script=PR_CHECKS)

    def test_pr_checks_lists_the_branch_results(self):
        self.dispatch("ci.yml", 61, "2026-02-01T00:00:00Z", {"s3": "failure", "rust": "success"},
                      head=self.previous)
        self.dispatch("macos.yml", 62, "2026-02-02T00:00:00Z", {"macos": "success"})
        self.dispatch("ci.yml", 63, "2026-02-03T00:00:00Z", {"s3": None}, status="queued")
        self.dispatch("ci.yml", 64, "2026-02-01T00:00:00Z", {"s3": "success"}, branch="other")
        output = self.pr_checks(expected=1)
        self.assertIn(f"  branch task, GitHub head {self.short}", output)
        lines = output.splitlines()
        start = lines.index("Dispatched checks (latest result of each, then unfinished runs):")
        self.assertEqual(lines[start + 1:], [
            f"  failed   ci.yml s3 at {self.previous[:7]}  https://example.invalid/runs/61/s3",
            f"  passed   ci.yml rust at {self.previous[:7]}  https://example.invalid/runs/61/rust",
            f"  passed   macos.yml macos at {self.short}  https://example.invalid/runs/62/macos",
            f"  queued   ci.yml at {self.short}  https://example.invalid/runs/63"])
        report = json.loads(self.pr_checks("--json", expected=1))
        self.assertEqual([run["databaseId"] for run in report["running"]], [63])
        self.assertEqual(report["exit_status"], 1)

    def test_pr_checks_of_a_merged_pull_request(self):
        # Runs dispatched before the merge still count while they finish; a
        # later run on the reused branch name and an earlier merge's runs do not.
        self.dispatch("ci.yml", 71, "2026-01-01T00:00:00Z", {"rust": "failure"})
        self.dispatch("ci.yml", 72, "2026-02-01T00:00:00Z", {"s3": "success"})
        self.dispatch("ci.yml", 73, "2026-02-03T00:00:00Z", {"s3": "failure"})
        self.branch_merged = [
            {"number": 2, "url": "https://example.invalid/pull/2", "headRefName": "task",
             "mergedAt": "2026-01-02T00:00:00Z", "isCrossRepository": False},
            {"number": 7, "url": "https://example.invalid/pull/7", "headRefName": "task",
             "mergedAt": "2026-02-02T00:00:00Z", "isCrossRepository": False}]
        report = json.loads(self.pr_checks("--json", state="MERGED",
                                           mergedAt="2026-02-02T00:00:00Z"))
        self.assertEqual([(entry["job"], entry["conclusion"]) for entry in report["results"]],
                         [("s3", "success")])

    def test_pr_checks_of_a_fork_lists_nothing(self):
        self.dispatch("ci.yml", 81, "2026-02-01T00:00:00Z", {"s3": "failure"})
        self.assertIn("unfinished runs):\n  none\n", self.pr_checks(isCrossRepository=True))

    def test_resolutions_are_visible_in_both_reports_and_keep_the_failed_conclusion(self):
        self.dispatch("focused-check.yml", 86, "2026-02-01T00:00:00Z", {"btrfs": "failure"})
        resolution = {"context": "dispatched-resolution/7/8600", "state": "success",
                      "description": "Mistaken runner setup; replacement passed",
                      "creator": {"login": "maintainer"}, "created_at": "2026-02-02T00:00:00Z",
                      "target_url": "https://example.invalid/replacement"}
        (self.runs / "statuses.json").write_text(json.dumps([[resolution]]))
        branch = json.loads(self.status("--json", pr=self.pr))
        pr = json.loads(self.pr_checks("--json"))
        self.assertEqual(branch["dispatched"]["results"], pr["results"])
        self.assertEqual(branch["dispatched"]["failed"], [])
        [entry] = pr["results"]
        self.assertEqual(entry["conclusion"], "failure")
        self.assertEqual(entry["resolution"]["reason"], resolution["description"])
        self.assertEqual(entry["resolution"]["actor"], "maintainer")
        for report in (self.status(pr=self.pr), self.pr_checks()):
            self.assertIn("  resolved focused-check.yml btrfs", report)
            self.assertIn("failure; resolved by maintainer at 2026-02-02", report)
            self.assertIn(resolution["description"], report)
            self.assertIn("replacement: https://example.invalid/replacement", report)
        self.dispatch("ci.yml", 87, "2026-02-03T00:00:00Z", {"rust": "failure"})
        self.assertIn("WARNING", self.status(pr=self.pr, expected=1))
        self.assertEqual(json.loads(self.pr_checks("--json", expected=1))["exit_status"], 1)

    def test_resolved_merged_failure_does_not_return_as_a_warning(self):
        self.dispatch("focused-check.yml", 88, "2026-02-01T00:00:00Z", {"btrfs": "failure"},
                      branch="merged-task")
        self.merged = [{"number": 8, "url": "https://example.invalid/pull/8",
                        "headRefName": "merged-task", "mergedAt": "2026-02-02T00:00:00Z"}]
        (self.runs / "statuses.json").write_text(json.dumps([[{
            "context": "dispatched-resolution/8/8800", "state": "success",
            "description": "Mistaken fixture removed"}]]))
        self.assertNotIn("NOTE: #8", self.status())

    def test_merged_prs_share_a_commit_lookup_but_keep_separate_resolutions(self):
        self.dispatch("focused-check.yml", 88, "2026-02-01T00:00:00Z", {"btrfs": "failure"},
                      branch="merged-task")
        self.dispatch("focused-check.yml", 89, "2026-02-01T00:00:00Z", {"btrfs": "failure"},
                      branch="other-task")
        self.merged = [{"number": number, "url": f"https://example.invalid/pull/{number}",
                        "headRefName": branch, "mergedAt": "2026-02-02T00:00:00Z"}
                       for number, branch in [(8, "merged-task"), (9, "other-task")]]
        (self.runs / "statuses.json").write_text(json.dumps([[{
            "context": "dispatched-resolution/8/8800", "state": "success",
            "description": "Mistaken fixture removed"}]]))
        report = json.loads(self.status("--json"))
        self.assertEqual([entry["number"] for entry in report["merged_failures"]], [9])
        requests = (self.runs / "status-requests").read_text().splitlines()
        self.assertEqual(len(requests), 1)


if __name__ == "__main__":
    unittest.main()
