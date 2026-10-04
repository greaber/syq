#!/usr/bin/env python3
"""List the checks dispatched on a pull request's branch.

Usage: scripts/pr-checks.py [--json] PULL_REQUEST

Prints the latest result of each check (a job name in a workflow) dispatched
on the pull request's branch, with the commit it ran at and its log, then
the runs still unfinished. Works from any checkout and for merged pull
requests, whose checks can finish after the merge. GitHub is asked each
time, so the list is current; pull request descriptions do not track CI.

A merged pull request's list covers runs dispatched before it merged; later
runs belong to work that reuses the branch name. Pull requests from forks
have no dispatched checks here.

Resolved failures keep their original conclusion, reason, and replacement link.
Exit status: 0 when no unresolved check failed; 1 when a check's latest result
is an unresolved failure, which also fails the pull request's `dispatched-checks`
status while it is open; 2 on usage or GitHub errors.
"""
import json
import shutil
import sys

from dispatched_checks import (BRANCH_WORKFLOWS, apply_resolutions, branch_runs, check_results,
                               dispatched_runs, fetch_jobs, fetch_resolutions, in_parallel,
                               merged_from_branch, result_lines, running, unresolved)
from tooling import ToolError, json_output, report_errors

REPOSITORY = "greaber/syq"
USAGE = "usage: pr-checks.py [--json] PULL_REQUEST"


def report(number, json_report):
    pr = json_output("gh", "pr", "view", number, "--repo", REPOSITORY, "--json",
                     "number,url,state,headRefName,headRefOid,mergedAt,isCrossRepository",
                     status=2)
    branch = pr.get("headRefName") or ""
    results, active = [], []
    if not pr.get("isCrossRepository"):
        found = in_parallel([lambda: merged_from_branch(REPOSITORY, branch)] + [
            lambda workflow=workflow: dispatched_runs(REPOSITORY, workflow, branch)
            for workflow in BRANCH_WORKFLOWS])
        runs = branch_runs([run for workflow_runs in found[1:] for run in workflow_runs],
                           branch, found[0], pr.get("mergedAt") or None)
        results = check_results(runs, fetch_jobs(REPOSITORY, runs))
        results = apply_resolutions(pr["number"], results, fetch_resolutions(REPOSITORY, results))
        active = running(runs)
    exit_status = 1 if any(unresolved(entry) for entry in results) else 0

    if json_report:
        print(json.dumps({"pull_request": pr, "results": results, "running": active,
                          "exit_status": exit_status}, indent=2, ensure_ascii=False))
        return exit_status
    print(f"Pull request #{pr.get('number')} {pr.get('url')} ({(pr.get('state') or '').lower()})")
    print(f"  branch {branch}, GitHub head {(pr.get('headRefOid') or '')[:7]}")
    print("Dispatched checks (latest result of each, then unfinished runs):")
    print("\n".join(result_lines(results, active)))
    return exit_status


def main():
    arguments = sys.argv[1:]
    json_report = "--json" in arguments
    numbers = [argument for argument in arguments if argument != "--json"]
    if len(numbers) != 1 or not numbers[0].isdigit():
        raise ToolError(USAGE, 2)
    if not shutil.which("gh"):
        raise ToolError("pr-checks needs gh", 2)
    try:
        return report(numbers[0], json_report)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ToolError(f"unexpected GitHub response ({error!r})", 2) from None


if __name__ == "__main__":
    sys.exit(report_errors(main))
