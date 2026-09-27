#!/usr/bin/env python3
"""Require full CI certification for this commit or unchanged release test inputs.

Usage: scripts/verify-release-ci.py [--json] OWNER/REPOSITORY COMMIT

Exit 0 when ci.yml, rsync-compat.yml, and macos.yml all certify the commit or
a first-parent ancestor with the same test inputs, 1 when any is missing,
pending, or failed, and 2 on usage or inspection errors.
"""
import json
import re
import shutil
import subprocess
import sys

from release_test_inputs import candidates as equivalent_commits
from tooling import ToolError, json_output, report_errors

WORKFLOWS = ("ci.yml", "rsync-compat.yml", "macos.yml")
DOCUMENTATION_STEPS = ("Test executable mapping documentation", "Test every native target")


def pages(endpoint, key):
    """Every item under `key` in each page of a paginated GitHub API response."""
    response = json_output("gh", "api", "--paginate", "--slurp", endpoint, status=2)
    try:
        return [item for page in response for item in (page or {}).get(key) or []]
    except (AttributeError, TypeError):
        raise ToolError(f"unexpected GitHub response from {endpoint}", 2) from None


def completed_successfully(item):
    return item.get("status") == "completed" and item.get("conclusion") == "success"


def trusted_runs(repository, workflow, commit):
    """Push, schedule, and manual runs of the workflow on master for exactly this
    commit in this repository, newest first."""
    runs = [run for run in pages(f"repos/{repository}/actions/workflows/{workflow}/runs"
                                 f"?head_sha={commit}&per_page=100", "workflow_runs")
            if run.get("head_sha") == commit and run.get("head_branch") == "master"
            and (run.get("head_repository") or {}).get("full_name") == repository
            and run.get("event") in ("workflow_dispatch", "push", "schedule")]
    runs.sort(key=lambda run: (run.get("run_number") or 0, run.get("run_attempt") or 0))
    return runs[::-1]


def attempt_jobs(repository, run):
    return pages(f"repos/{repository}/actions/runs/{run.get('id')}"
                 f"/attempts/{run.get('run_attempt')}/jobs?per_page=100", "jobs")


def unchanged_nightly(repository, run):
    """Whether a run is a successful nightly that skipped unchanged test inputs."""
    if run.get("event") != "schedule" or not completed_successfully(run):
        return False
    markers = [job for job in attempt_jobs(repository, run)
               if job.get("name") == "nightly-unchanged" and completed_successfully(job)]
    return len(markers) == 1


def certify(repository, workflow, evidence_commits, documentation_commits):
    """The certification state of one workflow."""
    documentation_commit = ""
    for evidence_commit in evidence_commits:
        candidates = trusted_runs(repository, workflow, evidence_commit)
        # Only explicit successful unchanged-nightly markers allow walking past
        # a newer run. Failures, pending runs, and ordinary uncertified runs retain
        # their existing meaning; never inspect an older attempt of the same run.
        while candidates and unchanged_nightly(repository, candidates[0]):
            candidates = candidates[1:]
        latest = candidates[0] if candidates else None
        run_id = latest.get("id") if latest else None
        attempt = latest.get("run_attempt") if latest else None
        url = (latest.get("html_url") or "") if latest else ""
        state = "dispatch"
        message = (f"full release CI workflow {workflow} has no push, schedule, or "
                   f"workflow_dispatch run on master on {evidence_commit}")
        if latest:
            status = latest.get("status") or "unknown"
            conclusion = latest.get("conclusion") or "pending"
            message = (f"latest full release CI workflow {workflow} is {status}/{conclusion} "
                       f"on {evidence_commit}")
            if status != "completed":
                state = "wait"
            elif conclusion != "success":
                state = "repair"
            else:
                # Never borrow the certificate from a previous run attempt.
                jobs = attempt_jobs(repository, latest)
                # Documentation examples have separate focused validation. Only use
                # an executed test step on a commit with the candidate's example inputs.
                if (workflow == "ci.yml" and not documentation_commit
                        and evidence_commit in documentation_commits
                        and any(step.get("name") in DOCUMENTATION_STEPS
                                and completed_successfully(step)
                                for job in jobs for step in job.get("steps") or [])):
                    documentation_commit = evidence_commit
                certificates = [job for job in jobs if job.get("name") == "release-certification"]
                if len(certificates) == 1 and completed_successfully(certificates[0]):
                    state = "ready"
                    if evidence_commit in documentation_commits:
                        documentation_commit = evidence_commit
                    message = f"Full release CI: {workflow} run {run_id} succeeded on {evidence_commit}."
                else:
                    message = (f"workflow {workflow} run {run_id} attempt {attempt} lacks "
                               f"successful full-suite release-certification on "
                               f"{evidence_commit}; dispatch this workflow on master")
        if state != "dispatch":
            break
    else:
        # No equivalent commit has a run, so none is the evidence.
        evidence_commit = ""

    focused_docs = False
    if workflow == "ci.yml" and state == "ready":
        if not documentation_commit:
            state = "dispatch"
            focused_docs = True
            message = (f"native CI is certified at {evidence_commit}, but changed documentation "
                       f"examples need focused tests")
        elif documentation_commit != evidence_commit:
            message += f" Executable documentation tests succeeded on {documentation_commit}."
    action = {
        "ready": "",
        "dispatch": f"gh workflow run {workflow} --repo {repository} --ref master"
                    + (" -f documentation_only=true" if focused_docs else ""),
        "wait": f"gh run watch {run_id} --repo {repository} --exit-status",
        "repair": f"gh run view {run_id} --repo {repository} --log-failed",
    }[state]
    return {"workflow": workflow, "state": state, "run_id": run_id, "attempt": attempt,
            "url": url, "message": message, "next_action": action,
            "evidence_commit": evidence_commit, "documentation_commit": documentation_commit}


def main():
    arguments = sys.argv[1:]
    json_report = arguments[:1] == ["--json"]
    if json_report:
        arguments = arguments[1:]
    if len(arguments) != 2:
        print(f"usage: {sys.argv[0]} [--json] OWNER/REPOSITORY COMMIT", file=sys.stderr)
        return 2
    repository, commit = arguments
    if "/" not in repository:
        raise ToolError(f"invalid GitHub repository: {repository}", 2)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ToolError(f"invalid release commit: {commit}", 2)
    if not shutil.which("gh"):
        raise ToolError("release CI verification needs gh")

    evidence_commits = documentation_commits = [commit]
    if subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"],
                      stderr=subprocess.DEVNULL).returncode == 0:
        try:
            evidence_commits = list(equivalent_commits(commit, native=True))
            documentation_commits = list(equivalent_commits(commit))
        except subprocess.CalledProcessError as error:
            raise ToolError(f"cannot compare release test inputs: {error}", 2) from None

    report = []
    for workflow in WORKFLOWS:
        try:
            result = certify(repository, workflow, evidence_commits, documentation_commits)
        except (AttributeError, KeyError, TypeError) as error:
            raise ToolError(f"unexpected GitHub response for {workflow} ({error!r})", 2) from None
        report.append(result)
        if json_report:
            continue
        if result["state"] == "ready":
            print(result["message"], flush=True)
        else:
            print(f"error: {result['message']}\nNext: {result['next_action']}", file=sys.stderr,
                  flush=True)
    ready = all(result["state"] == "ready" for result in report)
    if json_report:
        print(json.dumps({"commit": commit, "ready": ready, "workflows": report}, indent=2))
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(report_errors(main))
