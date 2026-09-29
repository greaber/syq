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
    print("{}")
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
            {"name": name, "conclusion": conclusion,
             "url": f"https://example.invalid/runs/{run_id}/{name}"}
            for name, conclusion in jobs.items()]}))

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


if __name__ == "__main__":
    unittest.main()
