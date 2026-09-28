#!/usr/bin/env python3
"""Set the `dispatched-checks` commit status on open pull requests.

Usage: scripts/dispatched-checks-status.py [PULL_REQUEST...]

The status fails while a check dispatched on the pull request's branch has
failed and no later run of that check passed (see scripts/dispatched_checks.py).
Checks still running do not fail it. The `merge-despite-failures` label turns
a failing status into a success that says it was overridden. Pull requests
from forks have no dispatched checks here and always succeed.

Evaluates the pull requests named on the command line. Otherwise
GITHUB_EVENT_PATH selects them: the pull request of a pull_request_target
event, or the open pull requests from the branch of a completed workflow_run.
Without either, it evaluates every open pull request. GITHUB_REPOSITORY names
the repository.

Only reads GitHub state and writes commit statuses; it never checks out or
runs pull-request code.
"""
import json
import os
import sys

from dispatched_checks import (BRANCH_WORKFLOWS, branch_runs, dispatched_runs, failed_checks,
                               fetch_jobs, in_parallel, merged_pull_requests, running)
from tooling import ToolError, json_output, output, report_errors

CONTEXT = "dispatched-checks"
OVERRIDE_LABEL = "merge-despite-failures"
PULL_REQUEST_FIELDS = "number,headRefName,headRefOid,isCrossRepository,labels"


def open_pull_requests(repository, branch=None):
    return json_output("gh", "pr", "list", "--repo", repository, "--state", "open",
                       *(["--head", branch] if branch else []), "--limit", "200", "--json",
                       PULL_REQUEST_FIELDS, status=2)


def selected_pull_requests(repository, numbers):
    if numbers:
        prs = [json_output("gh", "pr", "view", number, "--repo", repository, "--json",
                           PULL_REQUEST_FIELDS + ",state", status=2) for number in numbers]
        return [pr for pr in prs if pr.get("state") == "OPEN"]
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    event = {}
    if event_path and os.path.isfile(event_path):
        with open(event_path, encoding="utf-8") as source:
            event = json.load(source)
    if "pull_request" in event:
        return selected_pull_requests(repository, [str(event["pull_request"]["number"])])
    if "workflow_run" in event:
        run = event["workflow_run"]
        if (run.get("event") != "workflow_dispatch"
                or (run.get("head_repository") or {}).get("full_name") != repository):
            return []
        return open_pull_requests(repository, run.get("head_branch"))
    return open_pull_requests(repository)


def status(pr, failed, active):
    """The state, description, and link for one pull request's status."""
    overridden = any(label.get("name") == OVERRIDE_LABEL for label in pr.get("labels") or [])
    if failed:
        names = ", ".join(f"{entry['workflow']} {entry['job']}" for entry in failed)
        prefix = f"Overridden by {OVERRIDE_LABEL}: " if overridden else ""
        description = f"{prefix}{len(failed)} failed: {names}"
        return ("success" if overridden else "failure"), description, failed[0]["url"]
    description = "No failed dispatched checks"
    if active:
        description += f"; {len(active)} run{'s' if len(active) > 1 else ''} in progress"
    return "success", description, ""


def main():
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository:
        raise ToolError("GITHUB_REPOSITORY must name the repository", 2)
    prs = selected_pull_requests(repository, sys.argv[1:])
    merged = merged_pull_requests(repository) if prs else []
    for pr in prs:
        failed, active = [], []
        if not pr.get("isCrossRepository"):
            branch = pr.get("headRefName")
            runs = [run for runs in in_parallel(
                [lambda workflow=workflow: dispatched_runs(repository, workflow, branch)
                 for workflow in BRANCH_WORKFLOWS]) for run in runs]
            runs = branch_runs(runs, branch, merged)
            failed = failed_checks(runs, fetch_jobs(repository, [runs]))
            active = running(runs)
        state, description, url = status(pr, failed, active)
        # GitHub limits a status description to 140 characters.
        if len(description) > 140:
            description = description[:139] + "…"
        output("gh", "api", "--method", "POST",
               f"repos/{repository}/statuses/{pr.get('headRefOid')}", "-f", f"state={state}",
               "-f", f"context={CONTEXT}", "-f", f"description={description}",
               *(["-f", f"target_url={url}"] if url else []), status=2)
        print(f"#{pr.get('number')} {pr.get('headRefOid', '')[:7]}: {state}: {description}")
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
