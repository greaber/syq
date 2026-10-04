#!/usr/bin/env python3
"""Set the `dispatched-checks` commit status on open pull requests.

Usage: scripts/dispatched-checks-status.py [PULL_REQUEST...]
       scripts/dispatched-checks-status.py PR --resolve-job JOB_ID --reason TEXT [--replacement URL]
       scripts/dispatched-checks-status.py PR --reopen-job JOB_ID --reason TEXT

The status fails while a check dispatched on the pull request's branch has
failed, no later run of that check passed, and the failed job has no explicit
resolution (see scripts/dispatched_checks.py). Resolutions are separate commit statuses
on the failed job's SHA, scoped to its PR and job ID. They require status-write
access, preserve the original failure, and never excuse a later failed job.
The command records the resolution/reopening and refreshes the PR gate.
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
import argparse
import json
import os
import sys

from dispatched_checks import (BRANCH_WORKFLOWS, apply_resolutions, branch_runs, dispatched_runs,
                               failed_checks, fetch_jobs, in_parallel, merged_from_branch,
                               resolution_context, result_lines, running, undecided, unresolved)
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


def status(pr, failed, active, resolved=()):
    """The state, description, and link for one pull request's status."""
    overridden = any(label.get("name") == OVERRIDE_LABEL for label in pr.get("labels") or [])
    if failed:
        names = ", ".join(f"{entry['workflow']} {entry['job']}" for entry in failed)
        prefix = f"Overridden by {OVERRIDE_LABEL}: " if overridden else ""
        description = f"{prefix}{len(failed)} failed: {names}"
        return ("success" if overridden else "failure"), description, failed[0]["url"]
    description = "No failed dispatched checks"
    if resolved:
        description = f"No unresolved dispatched failures; {len(resolved)} resolved"
    if active:
        description += f"; {len(active)} run{'s' if len(active) > 1 else ''} in progress"
    return "success", description, ""


def post(repository, pr, *, job_id=None, reason=None, replacement=None, reopen=False):
    failed, active = [], []
    if not pr.get("isCrossRepository"):
        branch = pr.get("headRefName")
        # Branch names get reused; only runs since this name's latest merge count.
        runs = in_parallel([lambda: merged_from_branch(repository, branch)] + [
            lambda workflow=workflow: dispatched_runs(repository, workflow, branch)
            for workflow in BRANCH_WORKFLOWS])
        runs = branch_runs([run for workflow_runs in runs[1:] for run in workflow_runs],
                           branch, runs[0])
        failed = failed_checks(runs, fetch_jobs(repository, undecided(runs)))
        active = running(runs)
    if job_id is not None:
        entry = next((entry for entry in failed if entry.get("job_id") == job_id), None)
        if entry is None:
            raise ToolError(f"job {job_id} is not a current failed dispatched check of PR "
                            f"#{pr['number']}", 2)
        output("gh", "api", "--method", "POST", f"repos/{repository}/statuses/{entry['head']}",
               "-f", f"state={'failure' if reopen else 'success'}", "-f",
               f"context={resolution_context(pr['number'], job_id)}", "-f", f"description={reason}",
               *(["-f", f"target_url={replacement}"] if replacement else []), status=2)
        print(f"{'Reopened' if reopen else 'Resolved'} job {job_id} at {entry['head'][:7]}: {reason}")
    results = apply_resolutions(repository, pr["number"], failed)
    failed = [entry for entry in results if unresolved(entry)]
    resolved = [entry for entry in results if entry.get("resolution")]
    state, description, url = status(pr, failed, active, resolved)
    # GitHub limits a status description to 140 characters.
    if len(description) > 140:
        description = description[:139] + "…"
    output("gh", "api", "--method", "POST",
           f"repos/{repository}/statuses/{pr.get('headRefOid')}", "-f", f"state={state}",
           "-f", f"context={CONTEXT}", "-f", f"description={description}",
           *(["-f", f"target_url={url}"] if url else []), status=2)
    print(f"#{pr.get('number')} {pr.get('headRefOid', '')[:7]}: {state}: {description}")
    if resolved:
        print("\n".join(result_lines(resolved, [])))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pull_requests", nargs="*")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--resolve-job", type=int, help="Resolve this exact failed job ID")
    action.add_argument("--reopen-job", type=int, help="Revoke this failed job's resolution")
    parser.add_argument("--reason", help="Required resolution/reopening reason (1–140 characters)")
    parser.add_argument("--replacement", help="Optional HTTPS URL of replacement evidence")
    args = parser.parse_args()
    job_id = args.resolve_job if args.resolve_job is not None else args.reopen_job
    if any(not number.isdigit() or int(number) <= 0 for number in args.pull_requests):
        parser.error("pull request numbers must be positive integers")
    if job_id is not None:
        if len(args.pull_requests) != 1 or job_id <= 0:
            parser.error("resolving or reopening requires one pull request and a positive job ID")
        args.reason = (args.reason or "").strip()
        if not 1 <= len(args.reason) <= 140 or any(c in args.reason for c in "\r\n"):
            parser.error("--reason must be one line of 1–140 characters")
        if args.replacement and (args.reopen_job is not None or
                                 not args.replacement.startswith("https://") or
                                 any(c.isspace() for c in args.replacement)):
            parser.error("--replacement requires --resolve-job and an HTTPS URL")
    elif args.reason is not None or args.replacement is not None:
        parser.error("--reason and --replacement require --resolve-job or --reopen-job")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository:
        raise ToolError("GITHUB_REPOSITORY must name the repository", 2)
    # One pull request's failure must not leave the others without a status.
    failures = []
    prs = selected_pull_requests(repository, args.pull_requests)
    if job_id is not None and not prs:
        raise ToolError("resolving or reopening requires an open pull request", 2)
    for pr in prs:
        try:
            post(repository, pr, job_id=job_id, reason=args.reason, replacement=args.replacement,
                 reopen=args.reopen_job is not None)
        except ToolError as error:
            print(f"error: #{pr.get('number')}: {error}", file=sys.stderr)
            failures.append(pr.get("number"))
    if failures:
        raise ToolError(f"no status set for {', '.join(f'#{number}' for number in failures)}")
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
