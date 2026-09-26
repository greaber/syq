#!/usr/bin/env python3
"""Require full CI certification for this commit or unchanged release test inputs.

Usage: scripts/verify-release-ci.py [--json] OWNER/REPOSITORY COMMIT

Exit 0 when ci.yml, rsync-compat.yml, and macos.yml all certify the commit or
a first-parent ancestor with the same test inputs, 1 when any is missing,
pending, or failed, and 2 on usage or inspection errors.
"""
import re
import shutil
import subprocess
import sys

from release_test_inputs import candidates as equivalent_commits
from tooling import (JqError, alt, captured, dumps, exit_on_failure, get, items, iterate,
                     json_text, loads, order)

WORKFLOWS = ("ci.yml", "rsync-compat.yml", "macos.yml")


def die(message):
    print(f"error: {message}", file=sys.stderr)
    return 1


def gh_pages(endpoint):
    """The text of `gh api --paginate --slurp`; a failed request exits 2."""
    completed = subprocess.run(["gh", "api", "--paginate", "--slurp", endpoint],
                               stdout=subprocess.PIPE, text=True)
    if completed.returncode:
        raise JqError(2)
    return completed.stdout


def succeeds(predicate):
    """A jq -e condition: false when jq would report an error."""
    try:
        return bool(predicate())
    except JqError:
        return False


def pages_of(pages, key):
    """jq's `.[].KEY[]?`."""
    return [item for page in iterate(pages) for item in items(get(page, key))]


def trusted_runs(runs, commit, repository):
    selected = [run for run in pages_of(runs, "workflow_runs")
                if get(run, "head_sha") == commit and get(run, "head_branch") == "master"
                and get(run, "head_repository", "full_name") == repository
                and get(run, "event") in ("workflow_dispatch", "push", "schedule")]
    ordered = sorted(selected, key=lambda run: order(
        [alt(get(run, "run_number"), 0), alt(get(run, "run_attempt"), 0)]))
    return ordered[::-1]


def completed_successfully(job):
    return get(job, "status") == "completed" and get(job, "conclusion") == "success"


def main():
    arguments = sys.argv[1:]
    json_output = False
    if arguments[:1] == ["--json"]:
        json_output = True
        arguments = arguments[1:]
    if len(arguments) != 2:
        print(f"usage: {sys.argv[0]} [--json] OWNER/REPOSITORY COMMIT", file=sys.stderr)
        return 2
    repository, commit = arguments
    if "/" not in repository:
        print(f"invalid GitHub repository: {repository}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        print(f"invalid release commit: {commit}", file=sys.stderr)
        return 2
    if not shutil.which("gh"):
        return die("release CI verification needs gh")

    evidence_commits = [commit]
    documentation_commits = [commit]
    if subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"],
                      stderr=subprocess.DEVNULL).returncode == 0:
        try:
            evidence_commits = list(equivalent_commits(commit, native=True)) or [""]
            documentation_commits = list(equivalent_commits(commit)) or [""]
        except (subprocess.CalledProcessError, OSError, ValueError) as error:
            print(f"cannot compare release test inputs: {error}", file=sys.stderr)
            return 2

    report = []
    ready = True
    for workflow in WORKFLOWS:
        documentation_commit = ""
        focused_docs = False
        for evidence_commit in evidence_commits:
            runs = gh_pages(f"repos/{repository}/actions/workflows/{workflow}/runs"
                            f"?head_sha={evidence_commit}&per_page=100")
            try:
                candidates = trusted_runs(loads(runs), evidence_commit, repository)
            except JqError:
                return 2
            # Only explicit successful unchanged-nightly markers allow walking past
            # a newer run. Failures, pending runs, and ordinary uncertified runs retain
            # their existing meaning; never inspect an older attempt of the same run.
            while True:
                latest = candidates[0] if candidates else None
                if not succeeds(lambda: get(latest, "event") == "schedule"
                                and completed_successfully(latest)):
                    break
                skipped = gh_pages(f"repos/{repository}/actions/runs/{json_text(get(latest, 'id'))}"
                                   f"/attempts/{json_text(get(latest, 'run_attempt'))}/jobs?per_page=100")
                if not succeeds(lambda: len([job for job in pages_of(loads(skipped), "jobs")
                                             if get(job, "name") == "nightly-unchanged"
                                             and completed_successfully(job)]) == 1):
                    break
                candidates = candidates[1:]
            run_id = alt(get(latest, "id"), None)
            attempt = alt(get(latest, "run_attempt"), None)
            url = captured(alt(get(latest, "html_url"), ""))
            state = "dispatch"
            message = (f"full release CI workflow {workflow} has no push, schedule, or "
                       f"workflow_dispatch run on master on {evidence_commit}")
            if latest is not None:
                status = captured(alt(get(latest, "status"), "unknown"))
                conclusion = captured(alt(get(latest, "conclusion"), "pending"))
                message = (f"latest full release CI workflow {workflow} is {status}/{conclusion} "
                           f"on {evidence_commit}")
                if status != "completed":
                    state = "wait"
                elif conclusion != "success":
                    state = "repair"
                else:
                    # Never borrow the certificate from a previous run attempt.
                    jobs_text = gh_pages(f"repos/{repository}/actions/runs/{json_text(run_id)}"
                                         f"/attempts/{json_text(attempt)}/jobs?per_page=100")
                    try:
                        jobs = loads(jobs_text)
                    except JqError:
                        jobs = None  # Unreadable jobs satisfy neither condition below.
                    # Documentation examples have separate focused validation. Only use
                    # an executed test step on a commit with the candidate's example inputs.
                    if (workflow == "ci.yml" and not documentation_commit
                            and evidence_commit in documentation_commits
                            and succeeds(lambda: any(
                                get(step, "name") in ("Test executable mapping documentation",
                                                      "Test every native target")
                                and completed_successfully(step)
                                for job in pages_of(jobs, "jobs")
                                for step in items(get(job, "steps"))))):
                        documentation_commit = evidence_commit

                    def certified():
                        certificates = [job for job in pages_of(jobs, "jobs")
                                        if get(job, "name") == "release-certification"]
                        return len(certificates) == 1 and all(
                            completed_successfully(job) for job in certificates)

                    if succeeds(certified):
                        state = "ready"
                        if evidence_commit in documentation_commits:
                            documentation_commit = evidence_commit
                        message = (f"Full release CI: {workflow} run {json_text(run_id)} "
                                   f"succeeded on {evidence_commit}.")
                    else:
                        message = (f"workflow {workflow} run {json_text(run_id)} attempt "
                                   f"{json_text(attempt)} lacks successful full-suite "
                                   f"release-certification on {evidence_commit}; dispatch "
                                   f"this workflow on master")
            if state != "dispatch":
                break
        else:
            # Like the shell loop this replaces, a search that finds no run on
            # any equivalent commit reports no evidence commit.
            evidence_commit = ""
        if workflow == "ci.yml" and state == "ready" and not documentation_commit:
            state = "dispatch"
            focused_docs = True
            message = (f"native CI is certified at {evidence_commit}, but changed documentation "
                       f"examples need focused tests")
        if workflow == "ci.yml" and state == "ready" and documentation_commit != evidence_commit:
            message += f" Executable documentation tests succeeded on {documentation_commit}."
        if state == "ready":
            action = ""
        elif state == "dispatch":
            action = f"gh workflow run {workflow} --repo {repository} --ref master"
            if focused_docs:
                action += " -f documentation_only=true"
        elif state == "wait":
            action = f"gh run watch {json_text(run_id)} --repo {repository} --exit-status"
        else:
            action = f"gh run view {json_text(run_id)} --repo {repository} --log-failed"
        report.append({"workflow": workflow, "state": state, "run_id": run_id,
                       "attempt": attempt, "url": url, "message": message,
                       "next_action": action, "evidence_commit": evidence_commit,
                       "documentation_commit": documentation_commit})
        if state != "ready":
            ready = False
        if not json_output:
            if state == "ready":
                print(message, flush=True)
            else:
                print(f"error: {message}\nNext: {action}", file=sys.stderr, flush=True)
    if json_output:
        print(dumps({"commit": commit, "ready": ready, "workflows": report}, indent=2))
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
