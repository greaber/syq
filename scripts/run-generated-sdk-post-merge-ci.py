#!/usr/bin/env python3
"""Dispatch and await Python SDK validation on one generated SDK commit.

Usage: scripts/run-generated-sdk-post-merge-ci.py OWNER/REPOSITORY BRANCH MERGE_SHA
"""
import os
import re
import shutil
import subprocess
import sys

from tooling import (JqError, alt, captured, command, dumps, exit_on_failure, get, is_number,
                     iterate, loads, require, test)


def fail(message):
    print(message, file=sys.stderr)
    return 1


def gh(*args):
    return command("gh", *args)


def watch(run_id, repository):
    sys.stdout.flush()
    return subprocess.run(["gh", "run", "watch", run_id, "--repo", repository, "--exit-status"])


def main():
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} OWNER/REPOSITORY BRANCH MERGE_SHA", file=sys.stderr)
        return 2
    repository, branch, merge_sha = sys.argv[1:]
    trusted_repository = os.environ.get("SYQ_TRUSTED_REPOSITORY") or "greaber/syq"
    if repository != trusted_repository:
        return fail(f"refusing generated-SDK CI dispatch for {repository}; expected "
                    f"{trusted_repository}")
    if not re.fullmatch(r"automation/python-sdk-v[0-9]+\.[0-9]+\.[0-9]+", branch):
        print(f"unsafe generated branch: {branch}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        print(f"invalid merge commit: {merge_sha}", file=sys.stderr)
        return 2
    if not shutil.which("gh"):
        return fail("post-merge CI dispatch needs gh")

    # Updating the Git ref and resolving it in Actions can briefly disagree. Track
    # the run returned by this dispatch, never an older run found by listing runs.
    # Retry only a stale SHA; a failure on the requested commit is a real failure.
    for attempt in (1, 2, 3):
        reference = loads(gh("api", f"repos/{repository}/git/ref/heads/{branch}"))
        reference_sha = captured(require(get(reference, "object", "sha")))
        if reference_sha != merge_sha:
            return fail(f"generated branch {branch} does not point to expected merge commit "
                        f"{merge_sha} (found {reference_sha})")
        dispatch = loads(gh("api", "--method", "POST", "-H", "X-GitHub-Api-Version: 2026-03-10",
                            f"repos/{repository}/actions/workflows/ci.yml/dispatches",
                            "-f", f"ref={branch}", "-f", f"inputs[scope_commit]={merge_sha}"))
        run_id_value = get(dispatch, "workflow_run_id")
        if not (is_number(run_id_value) and run_id_value > 0
                and run_id_value == int(run_id_value)):
            raise JqError(4, "dispatch returned no workflow run ID")
        ci_run_id = captured(run_id_value)
        run_text = gh("api", f"repos/{repository}/actions/runs/{ci_run_id}")
        try:
            run = loads(run_text)
            expected = (get(run, "id") == run_id_value
                        and get(run, "event") == "workflow_dispatch"
                        and get(run, "head_repository", "full_name") == repository
                        and get(run, "head_branch") == branch)
        except JqError:
            expected = False
        if not expected:
            return fail(f"ci.yml dispatch returned an unexpected workflow run: "
                        f"{run_text.rstrip(chr(10))}")
        head_sha = get(run, "head_sha")
        if not test(head_sha, r"^[0-9a-f]{40}$"):
            raise JqError(4, "the dispatched run has no commit")
        run_sha = captured(head_sha)
        if run_sha == merge_sha:
            print(f"Dispatched ci.yml run {ci_run_id} for {merge_sha}")
            watched = watch(ci_run_id, repository)
            if watched.returncode:
                return watched.returncode
            break

        print(f"ci.yml dispatch attempt {attempt}/3 started run {ci_run_id} at stale commit "
              f"{run_sha}; expected {merge_sha}", file=sys.stderr)
        # The scope guard rejects this run. Let it finish before creating another;
        # watch's failure is expected, but an API/monitor failure cannot prove it ended.
        watch(ci_run_id, repository)
        run = loads(gh("api", f"repos/{repository}/actions/runs/{ci_run_id}"))
        if captured(require(get(run, "status"))) != "completed":
            return fail(f"stale ci.yml run {ci_run_id} is not completed; refusing another dispatch")
        if attempt >= 3:
            return fail(f"ci.yml dispatch still selected {run_sha} instead of {merge_sha} after "
                        f"3 attempts (last run {ci_run_id})")
        print(f"Stale run {ci_run_id} finished; retrying dispatch in 5 seconds", file=sys.stderr)
        # An external sleep keeps the retry delay replaceable in tests.
        command("sleep", "5")

    jobs = loads(gh("api", f"repos/{repository}/actions/runs/{ci_run_id}/jobs?per_page=100"))
    sdk_jobs = [job for job in iterate(get(jobs, "jobs")) if get(job, "name") == "sdks"]
    if len(sdk_jobs) == 1:
        sdk_count = 1
        sdk_status = get(sdk_jobs[0], "status")
        sdk_conclusion = alt(get(sdk_jobs[0], "conclusion"), "pending")
    else:
        sdk_count, sdk_status, sdk_conclusion = len(sdk_jobs), "ambiguous", "missing"
    sdk_status = captured(require(sdk_status))
    sdk_conclusion = captured(require(sdk_conclusion))
    if sdk_count != 1 or sdk_status != "completed" or sdk_conclusion != "success":
        return fail(f"ci.yml run {ci_run_id} sdks job is {sdk_status}/{sdk_conclusion} "
                    f"(count {dumps(sdk_count)})")

    print(f"Post-merge Python SDK validation passed for {merge_sha}")
    return 0


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
