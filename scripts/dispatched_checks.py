"""Failed checks in manually dispatched test runs on task branches.

A check is one job name in one workflow. A failed check stays failed until a
later dispatched run of the same job on the branch passes, so running more
checks or pushing commits does not hide it. Runs still in progress do not
count as failures. Used by scripts/branch-status.py and by the
dispatched-checks commit status on pull requests.
"""
from concurrent.futures import ThreadPoolExecutor

from tooling import ToolError, json_output

# Workflows whose manually dispatched runs test task branches. Focused jobs
# carry their test or script in the job name so reruns of one check match.
BRANCH_WORKFLOWS = ("ci.yml", "macos.yml", "rsync-compat.yml", "focused-check.yml")
FAILED = ("failure", "timed_out")
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


def fetch_jobs(repository, run_lists):
    """The jobs of every undecided run in the given run lists, by run ID."""
    runs = {run.get("databaseId"): run for runs in run_lists for run in undecided(runs)}
    return dict(zip(runs, in_parallel(
        [lambda run=run: run_jobs(repository, run) for run in runs.values()])))


def failed_checks(runs, jobs):
    """Failed checks that no later run passed, given each undecided run's jobs."""
    latest = {}
    for run in undecided(runs):
        for job in jobs[run.get("databaseId")]:
            if job.get("conclusion") in FAILED + ("success",):
                latest[run["workflow"], job.get("name")] = job, run
    return [{"workflow": workflow, "job": name, "conclusion": job.get("conclusion"),
             "head": run.get("headSha") or "", "url": job.get("url") or run.get("url")}
            for (workflow, name), (job, run) in latest.items()
            if job.get("conclusion") in FAILED]


def running(runs):
    return sorted((run for run in runs if run.get("status") != "completed"),
                  key=lambda run: run.get("createdAt") or "")
