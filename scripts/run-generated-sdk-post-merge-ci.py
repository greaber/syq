#!/usr/bin/env python3
"""Dispatch and await Python SDK validation on one generated SDK commit.

Usage: scripts/run-generated-sdk-post-merge-ci.py OWNER/REPOSITORY BRANCH MERGE_SHA
"""
import json
import os
import re
import shutil
import subprocess
import sys

from tooling import ToolError, json_output, output, report_errors


def watch(run_id, repository):
    sys.stdout.flush()
    return subprocess.run(["gh", "run", "watch", str(run_id), "--repo", repository,
                           "--exit-status"]).returncode


def dispatch_run(repository, branch, merge_sha):
    """Dispatch ci.yml for the merge commit and return the run GitHub created."""
    reference = json_output("gh", "api", f"repos/{repository}/git/ref/heads/{branch}")
    reference_sha = (reference.get("object") or {}).get("sha")
    if reference_sha != merge_sha:
        raise ToolError(f"generated branch {branch} does not point to expected merge commit "
                        f"{merge_sha} (found {reference_sha})")
    dispatch = json_output("gh", "api", "--method", "POST", "-H",
                           "X-GitHub-Api-Version: 2026-03-10",
                           f"repos/{repository}/actions/workflows/ci.yml/dispatches",
                           "-f", f"ref={branch}", "-f", f"inputs[scope_commit]={merge_sha}")
    run_id = dispatch.get("workflow_run_id") if isinstance(dispatch, dict) else None
    if type(run_id) is not int or run_id <= 0:
        raise ToolError(f"ci.yml dispatch returned no workflow run ID: {json.dumps(dispatch)}")
    run_text = output("gh", "api", f"repos/{repository}/actions/runs/{run_id}")
    try:
        run = json.loads(run_text)
        expected = (run["id"] == run_id and run["event"] == "workflow_dispatch"
                    and run["head_repository"]["full_name"] == repository
                    and run["head_branch"] == branch
                    and re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]))
    except (ValueError, KeyError, TypeError):
        expected = False
    if not expected:
        raise ToolError(f"ci.yml dispatch returned an unexpected workflow run: {run_text.strip()}")
    return run_id, run["head_sha"]


def main():
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} OWNER/REPOSITORY BRANCH MERGE_SHA", file=sys.stderr)
        return 2
    repository, branch, merge_sha = sys.argv[1:]
    trusted_repository = os.environ.get("SYQ_TRUSTED_REPOSITORY") or "greaber/syq"
    if repository != trusted_repository:
        raise ToolError(f"refusing generated-SDK CI dispatch for {repository}; expected "
                        f"{trusted_repository}")
    if not re.fullmatch(r"automation/python-sdk-v[0-9]+\.[0-9]+\.[0-9]+", branch):
        raise ToolError(f"unsafe generated branch: {branch}", 2)
    if not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        raise ToolError(f"invalid merge commit: {merge_sha}", 2)
    if not shutil.which("gh"):
        raise ToolError("post-merge CI dispatch needs gh")

    # Updating the Git ref and resolving it in Actions can briefly disagree. Track
    # the run returned by this dispatch, never an older run found by listing runs.
    # Retry only a stale SHA; a failure on the requested commit is a real failure.
    for attempt in (1, 2, 3):
        run_id, run_sha = dispatch_run(repository, branch, merge_sha)
        if run_sha == merge_sha:
            print(f"Dispatched ci.yml run {run_id} for {merge_sha}")
            status = watch(run_id, repository)
            if status:
                return status
            break
        print(f"ci.yml dispatch attempt {attempt}/3 started run {run_id} at stale commit "
              f"{run_sha}; expected {merge_sha}", file=sys.stderr)
        # The scope guard rejects this run. Let it finish before creating another;
        # watch's failure is expected, but an API/monitor failure cannot prove it ended.
        watch(run_id, repository)
        run = json_output("gh", "api", f"repos/{repository}/actions/runs/{run_id}")
        if run.get("status") != "completed":
            raise ToolError(f"stale ci.yml run {run_id} is not completed; refusing another dispatch")
        if attempt == 3:
            raise ToolError(f"ci.yml dispatch still selected {run_sha} instead of {merge_sha} "
                            f"after 3 attempts (last run {run_id})")
        print(f"Stale run {run_id} finished; retrying dispatch in 5 seconds", file=sys.stderr)
        # An external sleep keeps the retry delay replaceable in tests.
        output("sleep", "5")

    jobs = json_output("gh", "api", f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100")
    sdk_jobs = [job for job in jobs.get("jobs") or [] if job.get("name") == "sdks"]
    if len(sdk_jobs) == 1:
        sdk_status = sdk_jobs[0].get("status")
        sdk_conclusion = sdk_jobs[0].get("conclusion") or "pending"
    else:
        sdk_status, sdk_conclusion = "ambiguous", "missing"
    if sdk_status != "completed" or sdk_conclusion != "success":
        raise ToolError(f"ci.yml run {run_id} sdks job is {sdk_status}/{sdk_conclusion} "
                        f"(count {len(sdk_jobs)})")
    print(f"Post-merge Python SDK validation passed for {merge_sha}")
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
