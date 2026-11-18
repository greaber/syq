"""Results of manually dispatched test runs on task branches.

A check is one job name in one workflow, and its result is that of its latest
run that passed or failed. A failed check therefore stays failed until a
later dispatched run of the same job on the branch passes, so running more
checks or pushing commits does not hide it. Runs still in progress do not
count as failures. An explicit resolution excuses only one PR's exact failed
job; its original conclusion remains visible. Used by scripts/branch-status.py,
scripts/pr-checks.py, and the dispatched-checks commit status on pull requests.
"""
from concurrent.futures import ThreadPoolExecutor

from tooling import ToolError, json_output, output

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


def fetch_branch_runs(repository, branch):
    """The merged pull requests from a branch name and every recent dispatched
    run on that branch, before any merge filtering."""
    found = in_parallel([lambda: merged_from_branch(repository, branch)] + [
        lambda workflow=workflow: dispatched_runs(repository, workflow, branch)
        for workflow in BRANCH_WORKFLOWS])
    return found[0], [run for workflow_runs in found[1:] for run in workflow_runs]


def branch_dispatched_runs(repository, branch, until=None):
    """A branch's dispatched runs since an earlier pull request from the same
    branch name merged, and up to `until` (a merge time) when given. Branch
    names get reused, so earlier merges are looked up by name."""
    merged, runs = fetch_branch_runs(repository, branch)
    return branch_runs(runs, branch, merged, until)


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
             "job_id": job.get("databaseId"),
             "head": run.get("headSha") or "", "url": job.get("url") or run.get("url")}
            for (workflow, name), (job, run) in latest.items()]


def failed_checks(runs, jobs):
    """Failed checks that no later run passed. Only undecided runs need their
    jobs fetched: every check in an earlier run passed."""
    return [entry for entry in check_results(undecided(runs), jobs)
            if entry["conclusion"] in FAILED]


def unresolved(entry):
    return entry["conclusion"] in FAILED and not entry.get("resolution")


def resolution_context(number, job_id):
    return f"dispatched-resolution/{number}/{job_id}"


def fetch_resolutions(repository, results):
    """Read each failed commit's statuses once, in parallel across PRs."""
    return fetch_commit_statuses(repository, {entry["head"] for entry in results
                                             if unresolved(entry) and entry.get("job_id")})


def fetch_commit_statuses(repository, heads):
    """Latest status per context for each commit, including paginated history."""
    heads = sorted(set(heads))

    def statuses(head):
        pages = json_output("gh", "api", f"repos/{repository}/commits/{head}/statuses?per_page=100",
                            "--paginate", "--slurp", status=2)
        latest = {}
        # GitHub returns newest first, including across pages.
        for page in pages:
            for entry in page:
                latest.setdefault(entry["context"], entry)
        return latest

    return dict(zip(heads, in_parallel([lambda head=head: statuses(head) for head in heads])))


def acknowledgement_reason(parser, reason, link, link_option, link_required):
    """The validated reason for an acknowledgement status; exits through
    `parser.error` when the reason or its HTTPS link is unusable."""
    reason = (reason or "").strip()
    if not 1 <= len(reason) <= 140 or any(c in reason for c in "\r\n"):
        parser.error("--reason must be one line of 1–140 characters")
    if (link or link_required) and (
            not link or not link.startswith("https://") or any(c.isspace() for c in link)):
        parser.error(f"{link_option} requires an HTTPS URL")
    return reason


def post_acknowledgement(repository, head, context, reason, link=None):
    """Record an acknowledgement as a successful commit status: the reason is
    its description and the optional link its target URL."""
    output("gh", "api", "--method", "POST", f"repos/{repository}/statuses/{head}",
           "-f", "state=success", "-f", f"context={context}", "-f", f"description={reason}",
           *(["-f", f"target_url={link}"] if link else []), status=2)


def read_acknowledgement(by_head, head, context, link_key, link_required=False):
    """The acknowledgement recorded by the latest status of `context` on
    `head`, with its link under `link_key`, or None. Only a successful status
    with a reason (and a link when required) counts."""
    status = by_head.get(head, {}).get(context, {})
    reason = (status.get("description") or "").strip()
    if status.get("state") != "success" or not reason or (link_required
                                                          and not status.get("target_url")):
        return None
    return {"reason": reason, link_key: status.get("target_url"),
            "actor": (status.get("creator") or {}).get("login"),
            "created_at": status.get("created_at"), "url": status.get("url")}


def apply_resolutions(number, results, by_head):
    """Attach resolutions without changing test conclusions. Commit statuses
    preserve the reason, author, time, and optional replacement link. Only the
    latest successful status with a reason resolves that PR's exact failed job.
    Old tooling ignores these separate contexts and keeps reporting failures.
    """
    annotated = []
    for entry in results:
        resolution = read_acknowledgement(by_head, entry["head"],
                                          resolution_context(number, entry.get("job_id")),
                                          "replacement")
        if unresolved(entry) and resolution:
            entry = dict(entry, resolution=resolution)
        annotated.append(entry)
    return annotated


def running(runs):
    return sorted((run for run in runs if run.get("status") != "completed"),
                  key=lambda run: run.get("createdAt") or "")


def result_lines(results, active):
    """Report lines for check results and unfinished runs, failures first."""
    labels = {"success": "passed", "failure": "failed", "timed_out": "timed out",
              "in_progress": "running"}
    ordered = sorted(results, key=lambda entry: not unresolved(entry))
    lines = []
    for entry in ordered:
        resolution = entry.get("resolution")
        label = "resolved" if resolution else labels.get(entry["conclusion"], entry["conclusion"])
        lines.append(f"  {label:<8} {entry['workflow']} {entry['job']} at {entry['head'][:7]}  "
                     f"{entry['url']}")
        if resolution:
            lines.append(f"    {entry['conclusion']}; resolved by {resolution['actor']} at "
                         f"{resolution['created_at']}: {resolution['reason']}")
            if resolution.get("replacement"):
                lines.append(f"    replacement: {resolution['replacement']}")
    lines += [f"  {labels.get(run.get('status'), run.get('status') or 'unknown'):<8} "
              f"{run['workflow']} at {(run.get('headSha') or '')[:7]}  {run.get('url')}"
              for run in active]
    return lines or ["  none"]
