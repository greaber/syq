"""Results of manually dispatched test runs on task branches.

A check is one job name in one workflow, and its result is that of its latest
run that passed or failed. A failed check therefore stays failed until a
later dispatched run of the same job on the branch passes, so running more
checks or pushing commits does not hide it. Runs still in progress do not
count as failures. Used by scripts/branch-status.py, scripts/pr-checks.py,
and the dispatched-checks commit status on pull requests.
"""
from concurrent.futures import ThreadPoolExecutor

from tooling import ToolError, json_output

# Workflows whose manually dispatched runs test task branches. Focused jobs
# carry their test or script in the job name so reruns of one check match.
BRANCH_WORKFLOWS = ("ci.yml", "macos.yml", "rsync-compat.yml", "focused-check.yml")
FAILED = ("failure", "timed_out")
DECISIVE = FAILED + ("success",)
# How far back to look for merged branches: dispatched runs per workflow and
# merged pull requests. A single branch's runs are queried directly.
DISPATCHED_RUNS = 100
MERGED_PULL_REQUESTS = 30


def in_parallel(calls):
    """The results of independent GitHub lookups, in order."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        return [future.result() for future in [pool.submit(call) for call in calls]]


def dispatched_runs(repository, workflow, branch=None):
    """Recent manually dispatched runs of a branch workflow, on one or any branch."""
    return [dict(run, workflow=workflow) for run in json_output(
        "gh", "run", "list", "--repo", repository, "--workflow", workflow, "--event",
        "workflow_dispatch", *(["--branch", branch] if branch else []), "--limit",
        str(DISPATCHED_RUNS), "--json",
        "databaseId,headBranch,headSha,createdAt,status,conclusion,url", status=2)]


def merged_pull_requests(repository):
    try:
        return [pr for pr in json_output(
            "gh", "pr", "list", "--repo", repository, "--state", "merged", "--limit",
            str(MERGED_PULL_REQUESTS), "--json", "number,url,headRefName,mergedAt,isCrossRepository",
            status=2) if not pr.get("isCrossRepository")]
    except ToolError:
        raise ToolError("could not list merged pull requests", 2) from None


def merged_from_branch(repository, branch):
    """Merged pull requests from one branch name, however long ago."""
    return [pr for pr in json_output(
        "gh", "pr", "list", "--repo", repository, "--state", "merged", "--head", branch,
        "--limit", "100", "--json", "number,url,headRefName,mergedAt,isCrossRepository",
        status=2) if not pr.get("isCrossRepository")]


def run_jobs(repository, run):
    return json_output("gh", "run", "view", str(run.get("databaseId")), "--repo", repository,
                       "--json", "jobs", status=2).get("jobs") or []


def undecided(runs):
    """A branch's runs from the first unsuccessful or unfinished one on, oldest
    first; only these can hold a failure that no later run passed. GitHub marks
    a run cancelled when any job was cancelled, even if another job failed."""
    runs = sorted(runs, key=lambda run: run.get("createdAt") or "")
    first = next((index for index, run in enumerate(runs) if run.get("status") != "completed"
                  or run.get("conclusion") != "success"), len(runs))
    return runs[first:]


def branch_runs(runs, branch, merged, until=None):
    """A branch's runs since an earlier pull request from the same branch name
    merged, and up to `until` (a merge time) when given."""
    since = max((pr.get("mergedAt") or "" for pr in merged if pr.get("headRefName") == branch
                 and (until is None or (pr.get("mergedAt") or "") < until)), default="")
    return [run for run in runs if run.get("headBranch") == branch
            and since < (run.get("createdAt") or "") and (until is None or run["createdAt"] <= until)]


def fetch_jobs(repository, runs):
    """The jobs of the given runs, by run ID."""
    runs = {run.get("databaseId"): run for run in runs}
    return dict(zip(runs, in_parallel(
        [lambda run=run: run_jobs(repository, run) for run in runs.values()])))


def check_results(runs, jobs):
    """Each check's latest result among the given runs whose jobs were fetched,
    in order of first appearance. A cancelled job does not replace an earlier
    pass or failure; unfinished and skipped jobs are left out."""
    latest = {}
    for run in sorted(runs, key=lambda run: run.get("createdAt") or ""):
        for job in jobs.get(run.get("databaseId"), []):
            conclusion = job.get("conclusion")
            key = run["workflow"], job.get("name")
            if conclusion in DECISIVE or (conclusion not in (None, "", "skipped") and (
                    latest.get(key, ({}, {}))[0].get("conclusion") not in DECISIVE)):
                latest[key] = job, run
    return [{"workflow": workflow, "job": name, "conclusion": job.get("conclusion"),
             "head": run.get("headSha") or "", "url": job.get("url") or run.get("url")}
            for (workflow, name), (job, run) in latest.items()]


def failed_checks(runs, jobs):
    """Failed checks that no later run passed. Only undecided runs need their
    jobs fetched: every check in an earlier run passed."""
    return [entry for entry in check_results(undecided(runs), jobs)
            if entry["conclusion"] in FAILED]


def running(runs):
    return sorted((run for run in runs if run.get("status") != "completed"),
                  key=lambda run: run.get("createdAt") or "")


def result_lines(results, active):
    """Report lines for check results and unfinished runs, failures first."""
    labels = {"success": "passed", "failure": "failed", "timed_out": "timed out",
              "in_progress": "running"}
    ordered = sorted(results, key=lambda entry: entry["conclusion"] not in FAILED)
    lines = [f"  {labels.get(entry['conclusion'], entry['conclusion']):<8} {entry['workflow']} "
             f"{entry['job']} at {entry['head'][:7]}  {entry['url']}" for entry in ordered]
    lines += [f"  {labels.get(run.get('status'), run.get('status') or 'unknown'):<8} "
              f"{run['workflow']} at {(run.get('headSha') or '')[:7]}  {run.get('url')}"
              for run in active]
    return lines or ["  none"]
