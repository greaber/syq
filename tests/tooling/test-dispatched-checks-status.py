#!/usr/bin/env python3
"""Exercise scripts/dispatched-checks-status.py with a fake gh that serves
controlled pull requests, runs, and jobs, and records the statuses it posts."""
from support import SCRIPTS

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

STATUS = SCRIPTS / "dispatched-checks-status.py"
REPOSITORY = "example/syq"

FAKE_GH = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
data = Path(os.environ["SYQ_TEST_DATA"])
args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1] if name in args else None
if args[:2] == ["pr", "list"]:
    if option("--state") == "merged":
        merged = json.loads((data / "merged.json").read_text())
        print(json.dumps([pr for pr in merged if pr["headRefName"] == option("--head")]))
    else:
        prs = json.loads((data / "prs.json").read_text())
        head = option("--head")
        print(json.dumps([pr for pr in prs if head is None or pr["headRefName"] == head]))
elif args[:2] == ["pr", "view"]:
    prs = json.loads((data / "prs.json").read_text())
    print(json.dumps(next(pr for pr in prs if str(pr["number"]) == args[2])))
elif args[:2] == ["run", "list"]:
    runs = json.loads((data / "runs.json").read_text()).get(option("--workflow"), [])
    print(json.dumps([run for run in runs if run["headBranch"] == option("--branch")]))
elif args[:2] == ["run", "view"]:
    path = data / f"jobs-{args[2]}.json"
    if not path.exists():
        sys.exit(f"simulated failure reading run {args[2]}")
    print(path.read_text())
elif args[:3] == ["api", "--method", "POST"]:
    fields = dict(value.split("=", 1) for value in args[5::2])
    with open(data / "posted.jsonl", "a") as posted:
        posted.write(json.dumps({"endpoint": args[3], **fields}) + "\\n")
    path = data / ("statuses-" + args[3].rsplit("/", 1)[1] + ".json")
    statuses = json.loads(path.read_text()) if path.exists() else []
    statuses.insert(0, dict(fields, creator={"login": "maintainer"},
                           created_at="2026-02-04T00:00:00Z", url="https://api.example/status/1"))
    path.write_text(json.dumps(statuses))
    print("{}")
elif args[0] == "api" and "/commits/" in args[1]:
    path = data / ("statuses-" + args[1].split("/commits/")[1].split("/")[0] + ".json")
    if (data / "fail-status-read").exists():
        sys.exit("simulated status read failure")
    statuses = json.loads(path.read_text()) if path.exists() else []
    assert "--paginate" in args and "--slurp" in args
    print(json.dumps([statuses[:100], statuses[100:]]))
else:
    sys.exit(f"unexpected fake gh invocation: {args}")
"""


class DispatchedChecksStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syq-dispatched-checks-test.")
        work = Path(self.temp.name)
        self.data = work / "data"
        fakebin = work / "fakebin"
        self.data.mkdir()
        fakebin.mkdir()
        gh = fakebin / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        self.path = f"{fakebin}{os.pathsep}{os.environ['PATH']}"
        self.prs = [{"number": 7, "headRefName": "task", "headRefOid": "a" * 40,
                     "isCrossRepository": False, "labels": [], "state": "OPEN"}]
        self.runs = {}
        self.merged = []

    def tearDown(self):
        self.temp.cleanup()

    def dispatch(self, run_id, created, jobs, branch="task", status="completed"):
        conclusions = [conclusion for conclusion in jobs.values() if conclusion]
        conclusion = ("" if status != "completed" else "cancelled" if "cancelled" in conclusions
                      else "failure" if "failure" in conclusions else "success")
        self.runs.setdefault("ci.yml", []).append({
            "databaseId": run_id, "headBranch": branch, "headSha": "b" * 40,
            "createdAt": created, "status": status, "conclusion": conclusion,
            "url": f"https://example.invalid/runs/{run_id}"})
        (self.data / f"jobs-{run_id}.json").write_text(json.dumps({"jobs": [
            {"name": name, "conclusion": conclusion, "databaseId": run_id * 100 + index,
             "url": f"https://example.invalid/runs/{run_id}/{name}"}
            for index, (name, conclusion) in enumerate(jobs.items())]}))

    def post(self, *args, event=None, expected=0):
        (self.data / "prs.json").write_text(json.dumps(self.prs))
        (self.data / "runs.json").write_text(json.dumps(self.runs))
        (self.data / "merged.json").write_text(json.dumps(self.merged))
        (self.data / "posted.jsonl").unlink(missing_ok=True)
        env = {**os.environ, "PATH": self.path, "SYQ_TEST_DATA": str(self.data),
               "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_EVENT_PATH": ""}
        if event is not None:
            (self.data / "event.json").write_text(json.dumps(event))
            env["GITHUB_EVENT_PATH"] = str(self.data / "event.json")
        result = subprocess.run([str(STATUS), *args], env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, expected, result.stdout)
        posted = self.data / "posted.jsonl"
        return [json.loads(line) for line in posted.read_text().splitlines()] if posted.exists() else []

    def test_failure_fails_until_a_later_run_of_that_check_passes(self):
        self.dispatch(11, "2026-02-01T00:00:00Z", {"s3": "failure", "real-ssh (core, default)":
                                                   "cancelled"})
        self.dispatch(12, "2026-02-02T00:00:00Z", {"rust (native:all)": "success"})
        [posted] = self.post("7")
        self.assertEqual(posted["endpoint"], f"repos/{REPOSITORY}/statuses/{'a' * 40}")
        self.assertEqual(posted["context"], "dispatched-checks")
        self.assertEqual(posted["state"], "failure")
        self.assertEqual(posted["description"], "1 failed: ci.yml s3")
        self.assertEqual(posted["target_url"], "https://example.invalid/runs/11/s3")
        self.dispatch(13, "2026-02-03T00:00:00Z", {"s3": "success"})
        self.dispatch(14, "2026-02-04T00:00:00Z", {"s3": None}, status="in_progress")
        [posted] = self.post("7")
        self.assertEqual(posted["state"], "success")
        self.assertEqual(posted["description"], "No failed dispatched checks; 1 run in progress")
        self.assertNotIn("target_url", posted)

    def test_label_overrides_a_failure(self):
        self.dispatch(21, "2026-02-01T00:00:00Z", {"s3": "failure"})
        self.prs[0]["labels"] = [{"name": "merge-despite-failures"}]
        [posted] = self.post("7")
        self.assertEqual(posted["state"], "success")
        self.assertEqual(posted["description"],
                         "Overridden by merge-despite-failures: 1 failed: ci.yml s3")

    def test_forks_and_runs_before_an_earlier_merge_do_not_count(self):
        self.dispatch(31, "2026-02-01T00:00:00Z", {"s3": "failure"})
        self.merged = [{"number": 5, "headRefName": "task", "mergedAt": "2026-02-02T00:00:00Z",
                        "isCrossRepository": False}]
        self.assertEqual(self.post("7")[0]["state"], "success")
        self.merged = []
        self.prs[0]["isCrossRepository"] = True
        self.assertEqual(self.post("7")[0]["state"], "success")

    def test_events_select_pull_requests(self):
        self.prs.append({"number": 8, "headRefName": "other", "headRefOid": "c" * 40,
                         "isCrossRepository": False, "labels": [], "state": "OPEN"})
        self.dispatch(41, "2026-02-01T00:00:00Z", {"s3": "failure"})
        posted = self.post(event={"pull_request": {"number": 8}})
        self.assertEqual([(entry["endpoint"][-40:], entry["state"]) for entry in posted],
                         [("c" * 40, "success")])
        run = {"event": "workflow_dispatch", "head_branch": "task",
               "head_repository": {"full_name": REPOSITORY}}
        posted = self.post(event={"workflow_run": run})
        self.assertEqual([(entry["endpoint"][-40:], entry["state"]) for entry in posted],
                         [("a" * 40, "failure")])
        # Runs from other events or repositories do not affect pull requests.
        self.assertEqual(self.post(event={"workflow_run": dict(run, event="push")}), [])
        self.assertEqual(self.post(event={"workflow_run": dict(
            run, head_repository={"full_name": "someone/fork"})}), [])
        # Without an event or numbers, every open pull request is evaluated.
        self.assertEqual(len(self.post()), 2)

    def test_one_pull_request_error_does_not_stop_the_others(self):
        self.prs.insert(0, {"number": 6, "headRefName": "broken", "headRefOid": "d" * 40,
                            "isCrossRepository": False, "labels": [], "state": "OPEN"})
        self.dispatch(61, "2026-02-01T00:00:00Z", {"s3": "failure"}, branch="broken")
        (self.data / "jobs-61.json").unlink()
        posted = self.post(expected=1)
        self.assertEqual([entry["endpoint"][-40:] for entry in posted], ["a" * 40])

    def test_long_descriptions_fit_github(self):
        self.dispatch(51, "2026-02-01T00:00:00Z", {f"check {index}": "failure"
                                                   for index in range(20)})
        [posted] = self.post("7")
        self.assertEqual(len(posted["description"]), 140)

    def test_closed_pull_requests_are_skipped(self):
        self.prs[0]["state"] = "MERGED"
        self.assertEqual(self.post("7"), [])

    def test_resolve_and_new_failures(self):
        self.dispatch(80, "2026-02-01T00:00:00Z", {"btrfs": "failure"})
        replacement = "https://example.invalid/runs/81"
        reason = "Runner cannot create loop devices; replacement passed"
        resolution, gate = self.post("7", "--resolve-job", "8000", "--reason", reason,
                                     "--replacement", replacement)
        self.assertEqual(resolution, {
            "endpoint": f"repos/{REPOSITORY}/statuses/{'b' * 40}",
            "context": "dispatched-resolution/7/8000", "state": "success",
            "description": reason, "target_url": replacement})
        self.assertEqual(gate["state"], "success")
        self.assertIn("1 resolved", gate["description"])
        # Later gate evaluations retain the resolution without changing the job.
        self.assertEqual(self.post("7")[0]["state"], "success")
        self.assertEqual(json.loads((self.data / "jobs-80.json").read_text())["jobs"][0]
                         ["conclusion"], "failure")
        # Other failures remain blocking.
        self.dispatch(81, "2026-02-02T00:00:00Z", {"rust": "failure"})
        self.assertEqual(self.post("7")[0]["description"], "1 failed: ci.yml rust")
        # A rerun gets a new job ID even on the same SHA and with the same name.
        self.dispatch(82, "2026-02-03T00:00:00Z", {"btrfs": "failure", "rust": "success"})
        self.assertEqual(self.post("7")[0]["description"], "1 failed: ci.yml btrfs")

    def test_resolution_without_replacement_is_scoped_to_pr_and_paginated(self):
        self.dispatch(83, "2026-02-01T00:00:00Z", {"btrfs": "failure"})
        _, gate = self.post("7", "--resolve-job", "8300", "--reason", "Mistaken fixture removed")
        self.assertEqual(gate["state"], "success")
        self.prs[0]["number"] = 8
        self.assertEqual(self.post("8")[0]["state"], "failure")
        self.prs[0]["number"] = 7
        path = self.data / f"statuses-{'b' * 40}.json"
        statuses = json.loads(path.read_text())
        noise = [{"context": f"unrelated/{i}", "state": "success"} for i in range(101)]
        path.write_text(json.dumps(noise + statuses))
        self.assertEqual(self.post("7")[0]["state"], "success")

    def test_resolution_requires_reason_and_current_failed_job_of_open_pr(self):
        self.dispatch(84, "2026-02-01T00:00:00Z", {"btrfs": "failure", "rust": "success"})
        for options in (["--resolve-job", "8400"],
                        ["--resolve-job", "8400", "--reason", " "],
                        ["--resolve-job", "8400", "--reason", "x" * 141],
                        ["--resolve-job", "8400", "--reason", "two\nlines"],
                        ["--reason", "not an action"],
                        ["--resolve-job", "-1", "--reason", "invalid id"]):
            with self.subTest(options=options):
                self.assertEqual(self.post("7", *options, expected=2), [])
        for job in ("8401", "9999"):
            self.assertEqual(self.post("7", "--resolve-job", job, "--reason", "not failed",
                                       expected=1), [])
        self.prs[0]["isCrossRepository"] = True
        self.assertEqual(self.post("7", "--resolve-job", "8400", "--reason", "fork",
                                   expected=1), [])
        self.prs[0]["state"] = "MERGED"
        self.assertEqual(self.post("7", "--resolve-job", "8400", "--reason", "closed",
                                   expected=2), [])

    def test_unreadable_resolutions_replace_old_success_with_failure(self):
        [initial] = self.post("7")
        self.assertEqual(initial["state"], "success")
        self.dispatch(85, "2026-02-01T00:00:00Z", {"btrfs": "failure"})
        (self.data / "fail-status-read").touch()
        [posted] = self.post("7", expected=1)
        self.assertEqual(posted["endpoint"], initial["endpoint"])
        self.assertEqual(posted["context"], "dispatched-checks")
        self.assertEqual(posted["state"], "failure")
        self.assertEqual(posted["target_url"], "https://example.invalid/runs/85/btrfs")
        statuses = json.loads((self.data / f"statuses-{'a' * 40}.json").read_text())
        self.assertEqual([entry["state"] for entry in statuses], ["failure", "success"])

    def test_unreadable_resolutions_still_honor_the_explicit_override(self):
        self.dispatch(86, "2026-02-01T00:00:00Z", {"btrfs": "failure"})
        self.prs[0]["labels"] = [{"name": "merge-despite-failures"}]
        (self.data / "fail-status-read").touch()
        [posted] = self.post("7", expected=1)
        self.assertEqual(posted["state"], "success")
        self.assertTrue(posted["description"].startswith("Overridden by merge-despite-failures:"))


if __name__ == "__main__":
    unittest.main()
