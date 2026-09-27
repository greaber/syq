#!/usr/bin/env python3
"""Report the state of the current task branch.

Usage: scripts/branch-status.py [--json] [--check]

Reports the worktree, the branch's pull request, the latest post-merge and
nightly CI runs on master, and failed checks in test runs dispatched on this
branch or on recently merged branches. Its output is what a status report or
review request should state.

Fetches origin's master, since a local master branch is updated only by
manual pulls and says nothing about current master. Otherwise only reads git
and GitHub state. With --check it also runs the fixed Rust baseline (fmt,
clippy, unit tests) in this worktree.

A job that failed in a run dispatched on this branch stays a failure until a
later dispatched run of the same job on the branch passes; merge past one only
when the user explicitly says so. Runs still in progress at a merge keep
running, so a failure left on a merged branch is reported until the next
successful full-suite run of that workflow on master.

Exit status: 0 when nothing needs attention; 1 when master's latest
post-merge or nightly run failed, a dispatched check on this branch or a
recently merged branch failed, the GitHub head is stale or unrelated, or a
--check step failed or changed worktree status; 2 on usage/tooling errors or
HEAD moving during checks (stderr diagnostic, no report, even with --json).
The pull request's check rollup is informational.
"""
import json
import shutil
import subprocess
import sys

from tooling import ToolError, json_output, output, report_errors

REPOSITORY = "greaber/syq"
WORKFLOWS = ("ci.yml", "rsync-compat.yml", "macos.yml")
MASTER_REF = "refs/remotes/origin/master"
BASELINE = [
    ("fmt", ["cargo", "fmt", "--all", "--", "--check"]),
    ("clippy", ["cargo", "clippy", "--locked", "--all-targets", "--all-features", "--", "-D",
                "warnings"]),
    ("unit-tests", ["cargo", "test", "--locked", "--bin", "syq"]),
]
CHANGE_CODES = {"M", "A", "D", "R", "C", "T"}
UNFINISHED = ("queued", "in_progress", "pending", "waiting", "requested")
# Workflows whose manually dispatched runs test task branches. A check is one job
# name in one workflow; focused jobs carry their test or script in the name.
BRANCH_WORKFLOWS = ("ci.yml", "macos.yml", "rsync-compat.yml", "focused-check.yml")
# The full-suite master workflows whose next success covers a merged failure.
# Focused scripts can run anything, so they wait for both native suites.
CLEARED_BY = {"ci.yml": ("ci.yml",), "macos.yml": ("macos.yml",),
              "rsync-compat.yml": ("rsync-compat.yml",),
              "focused-check.yml": ("ci.yml", "macos.yml")}
FAILED = ("failure", "timed_out")
# How far back to look: dispatched runs per workflow and merged pull requests.
DISPATCHED_RUNS = 100
MERGED_PULL_REQUESTS = 30


def git(*args):
    return output("git", *args, status=2).strip()


def succeeds(*args):
    return subprocess.run(list(args), stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def worktree_state():
    """(HEAD, short HEAD, porcelain status, staged, unstaged, untracked counts)."""
    # Porcelain lines begin with a significant space, so keep leading whitespace.
    status = output("git", "status", "--porcelain", "--untracked-files=all", status=2).rstrip("\n")
    lines = status.splitlines()
    return (git("rev-parse", "HEAD"), git("rev-parse", "--short", "HEAD"), status,
            sum(1 for line in lines if line[:1] in CHANGE_CODES),
            sum(1 for line in lines if line[1:2] in CHANGE_CODES),
            sum(1 for line in lines if line.startswith("??")))


def ahead_behind(range_):
    ahead, behind = git("rev-list", "--left-right", "--count", range_).split()
    return int(ahead), int(behind)


def latest_run(workflow, event, kind, warn):
    """The latest run of a workflow on master for one trigger, and its state."""
    runs = json_output("gh", "run", "list", "--repo", REPOSITORY, "--workflow", workflow,
                       "--branch", "master", "--event", event, "--limit", "1", "--json",
                       "headSha,status,conclusion,url,createdAt,databaseId", status=2)
    run = runs[0] if runs else None
    state = "missing"
    if run:
        if run.get("status") == "completed":
            state = run.get("conclusion") or ""
        else:
            state = run.get("status") or "unknown"
    if state == "missing":
        warn(f"{workflow} has no {kind} run on master")
    elif state != "success" and state not in UNFINISHED:
        warn(f"master is red: {workflow} {kind} {state} at {(run.get('headSha') or '')[:7]} "
             f"{run.get('url')}")
    return run, state


def dispatched_runs():
    """Recent manually dispatched runs of the branch workflows, on any branch."""
    runs = []
    for workflow in BRANCH_WORKFLOWS:
        for run in json_output("gh", "run", "list", "--repo", REPOSITORY, "--workflow", workflow,
                               "--event", "workflow_dispatch", "--limit", str(DISPATCHED_RUNS),
                               "--json", "databaseId,headBranch,headSha,createdAt,status,"
                               "conclusion,url", status=2):
            runs.append(dict(run, workflow=workflow))
    return runs


def run_jobs(run):
    return json_output("gh", "run", "view", str(run.get("databaseId")), "--repo", REPOSITORY,
                       "--json", "jobs", status=2).get("jobs") or []


def branch_runs(runs, branch, merged, until=None):
    """A branch's runs since an earlier pull request from the same branch name
    merged, and up to `until` (a merge time) when given."""
    since = max((pr.get("mergedAt") or "" for pr in merged if pr.get("headRefName") == branch
                 and (until is None or (pr.get("mergedAt") or "") < until)), default="")
    return [run for run in runs if run.get("headBranch") == branch
            and since < (run.get("createdAt") or "") and (until is None or run["createdAt"] <= until)]


def branch_checks(runs):
    """Failed checks that no later run passed, and the runs still in progress."""
    runs = sorted(runs, key=lambda run: run.get("createdAt") or "")
    running = [run for run in runs if run.get("status") != "completed"]
    # Only runs from the first failed or unfinished one on can hold a failure.
    first = next((index for index, run in enumerate(runs) if run.get("status") != "completed"
                  or run.get("conclusion") in FAILED), len(runs))
    latest = {}
    for run in runs[first:]:
        for job in run_jobs(run):
            if job.get("conclusion") in FAILED + ("success",):
                latest[run["workflow"], job.get("name")] = job, run
    failed = [{"workflow": workflow, "job": name, "conclusion": job.get("conclusion"),
               "head": run.get("headSha") or "", "url": job.get("url") or run.get("url")}
              for (workflow, name), (job, run) in latest.items()
              if job.get("conclusion") in FAILED]
    return failed, running


def latest_full_run(workflow):
    """When the latest successful full-suite run of a workflow on master started."""
    runs = json_output("gh", "run", "list", "--repo", REPOSITORY, "--workflow", workflow,
                       "--branch", "master", "--limit", "20", "--json",
                       "databaseId,event,createdAt,status,conclusion", status=2)
    for run in sorted(runs, key=lambda run: run.get("createdAt") or "", reverse=True):
        if run.get("event") in ("schedule", "workflow_dispatch") and run.get("conclusion") == "success":
            passed = {job.get("name") for job in run_jobs(run) if job.get("conclusion") == "success"}
            if "release-certification" in passed and "nightly-unchanged" not in passed:
                return run.get("createdAt") or ""
    return ""


def pull_request_checks(pr):
    """The rollup's check runs and status contexts as name, outcome, and pending."""
    checks = []
    for entry in pr.get("statusCheckRollup") or []:
        outcome = (entry.get("conclusion") or entry.get("state") or "").upper()
        checks.append({"name": entry.get("name") or entry.get("context") or "unnamed",
                       "outcome": outcome, "pending": outcome in ("", "PENDING", "EXPECTED")})
    return checks


def report(json_report, check):
    warnings = []
    warn = warnings.append

    toplevel = git("rev-parse", "--show-toplevel")
    head_sha, short_sha, status_lines, staged, unstaged, untracked = worktree_state()
    initial_head_sha, initial_status_lines = head_sha, status_lines
    symbolic = subprocess.run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
                              stdout=subprocess.PIPE, text=True)
    branch = symbolic.stdout.strip() if symbolic.returncode == 0 else "HEAD"
    upstream_lookup = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    upstream = upstream_lookup.stdout.strip() if upstream_lookup.returncode == 0 else None
    upstream_ahead = upstream_behind = None
    if upstream:
        upstream_ahead, upstream_behind = ahead_behind(f"HEAD...{upstream}")

    if not succeeds("git", "fetch", "--quiet", "origin", f"+refs/heads/master:{MASTER_REF}"):
        raise ToolError("could not fetch master from origin", 2)
    master_sha = git("rev-parse", MASTER_REF)
    master_short = git("rev-parse", "--short", MASTER_REF)
    ahead_of_master, behind_master = ahead_behind(f"HEAD...{MASTER_REF}")

    # Post-merge runs select checks from the changed paths, so a later success
    # need not rerun an earlier failure. The nightly run covers the full suite
    # whenever test inputs changed since its last success.
    master_runs = []
    for workflow in WORKFLOWS:
        push_run, push_state = latest_run(workflow, "push", "post-merge", warn)
        nightly_run, nightly_state = latest_run(workflow, "schedule", "nightly", warn)
        master_runs.append({"workflow": workflow, "state": push_state, "run": push_run,
                            "nightly": {"state": nightly_state, "run": nightly_run}})

    # The pull request for this branch, if any.
    # An empty list means no open pull request; a failed command is an error.
    pr = None
    pr_head_relation = "none"
    if branch != "HEAD":
        try:
            prs = json_output("gh", "pr", "list", "--repo", REPOSITORY, "--head", branch, "--state",
                              "open", "--limit", "1", "--json",
                              "number,url,state,isDraft,baseRefName,headRefOid,reviewDecision,"
                              "mergeStateStatus,statusCheckRollup", status=2)
        except ToolError:
            raise ToolError(f"could not look up the pull request for {branch}", 2) from None
        pr = prs[0] if prs else None
    if pr:
        pr_head, number = pr.get("headRefOid") or "", pr.get("number")
        if pr_head == head_sha:
            pr_head_relation = "matches"
        elif succeeds("git", "merge-base", "--is-ancestor", pr_head, "HEAD"):
            pr_head_relation = "github-behind"
            warn(f"PR #{number} head {pr_head[:7]} is behind local {short_sha}; push before reporting")
        elif succeeds("git", "merge-base", "--is-ancestor", head_sha, pr_head):
            pr_head_relation = "local-behind"
            warn(f"local {short_sha} is behind PR #{number} head {pr_head[:7]}")
        else:
            pr_head_relation = "unrelated"
            warn(f"PR #{number} head {pr_head[:7]} is not related to local {short_sha}")

    # Failed dispatched checks on this branch, and those merged branches left behind.
    try:
        merged = [pr for pr in json_output(
            "gh", "pr", "list", "--repo", REPOSITORY, "--state", "merged", "--limit",
            str(MERGED_PULL_REQUESTS), "--json", "number,url,headRefName,mergedAt,isCrossRepository",
            status=2) if not pr.get("isCrossRepository")]
    except ToolError:
        raise ToolError("could not list merged pull requests", 2) from None
    runs = dispatched_runs()
    branch_failed, branch_running = [], []
    if branch != "HEAD":
        branch_failed, branch_running = branch_checks(branch_runs(runs, branch, merged))
    for entry in branch_failed:
        warn(f"{entry['workflow']} {entry['job']} {entry['conclusion']} at {entry['head'][:7]} on "
             f"this branch, and no later run passed it; merge only if the user says to "
             f"{entry['url']}")
    merged_failed = []
    full_runs = {}
    for merged_pr in merged:
        merged_at = merged_pr.get("mergedAt") or ""
        failed, _ = branch_checks(branch_runs(runs, merged_pr.get("headRefName"), merged, merged_at))
        for entry in failed:
            clearing = CLEARED_BY[entry["workflow"]]
            for workflow in clearing:
                if workflow not in full_runs:
                    full_runs[workflow] = latest_full_run(workflow)
            if all(full_runs[workflow] > merged_at for workflow in clearing):
                continue
            merged_failed.append(dict(entry, number=merged_pr.get("number"),
                                      pull_request=merged_pr.get("url")))
            warn(f"#{merged_pr.get('number')} merged with {entry['workflow']} {entry['job']} "
                 f"{entry['conclusion']} at {entry['head'][:7]}, and no full run of "
                 f"{' and '.join(clearing)} on master has passed since {entry['url']}")

    checks = []
    if check:
        for name, arguments in BASELINE:
            # Keep stdout for the report, so --json stays a single document.
            sys.stdout.flush()
            try:
                passed = subprocess.run(arguments, cwd=toplevel, stdout=sys.stderr).returncode == 0
            except OSError as error:
                print(f"{arguments[0]}: {error.strerror}", file=sys.stderr)
                passed = False
            if not passed:
                warn(f"{name} failed")
            checks.append({"name": name, "command": " ".join(arguments),
                           "result": "pass" if passed else "fail"})
        # Checks can modify files or overlap an edit. Report the state after checking,
        # and never attribute checks to a commit that moved while they ran.
        head_sha, short_sha, status_lines, staged, unstaged, untracked = worktree_state()
        if head_sha != initial_head_sha:
            raise ToolError(f"HEAD changed during baseline checks: {initial_head_sha} -> "
                            f"{head_sha}; rerun branch-status", 2)
        if status_lines != initial_status_lines:
            warn("worktree status changed during baseline checks; inspect changes and rerun "
                 "affected checks")

    clean = not status_lines
    if not clean:
        warn(f"worktree is dirty: {staged} staged, {unstaged} unstaged, {untracked} untracked")
    # A dirty worktree is worth stating but is not by itself a problem.
    exit_status = 0 if not warnings or (len(warnings) == 1 and
                                        warnings[0].startswith("worktree is dirty")) else 1

    if json_report:
        print(json.dumps({
            "worktree": {
                "path": toplevel, "branch": branch, "head": head_sha, "short": short_sha,
                "clean": clean, "staged": staged, "unstaged": unstaged, "untracked": untracked,
                "upstream": upstream, "ahead_of_upstream": upstream_ahead,
                "behind_upstream": upstream_behind, "master_ref": MASTER_REF,
                "master": master_sha, "ahead_of_master": ahead_of_master,
                "behind_master": behind_master,
            },
            "master_ci": master_runs, "pull_request": pr, "pull_request_head": pr_head_relation,
            "dispatched": {"failed": branch_failed, "running": branch_running},
            "merged_failures": merged_failed, "checks": checks, "warnings": warnings, "exit_status": exit_status,
        }, indent=2, ensure_ascii=False))
        return exit_status

    dirty = f"dirty: {staged} staged, {unstaged} unstaged, {untracked} untracked"
    lines = [f"Worktree: {toplevel}",
             f"Branch:   {branch} at {short_sha} ({'clean' if clean else dirty})",
             f"Upstream: {upstream} (ahead {upstream_ahead}, behind {upstream_behind})"
             if upstream else "Upstream: none",
             f"Master:   {master_short} from {MASTER_REF} (branch is ahead {ahead_of_master}, "
             f"behind {behind_master})",
             "",
             "Master CI (latest post-merge run per workflow, then its latest nightly full suite):"]

    def run_line(label, state, run):
        if run is None:
            return f"  {label:<16} {state:<12} (no run)"
        return f"  {label:<16} {state:<12} {(run.get('headSha') or '')[:7]}  {run.get('url')}"

    for entry in master_runs:
        lines.append(run_line(entry["workflow"], entry["state"], entry["run"]))
        lines.append(run_line("  nightly", entry["nightly"]["state"], entry["nightly"]["run"]))
    lines.append("")
    if pr is None:
        lines.append(f"Pull request: none for {branch}")
    else:
        pr_state = "draft" if pr.get("isDraft") else (pr.get("state") or "").lower()
        review = (pr.get("reviewDecision") or "none").lower()
        merge_state = (pr.get("mergeStateStatus") or "unknown").lower()
        lines.append(f"Pull request: #{pr.get('number')} {pr.get('url')}")
        lines.append(f"  base {pr.get('baseRefName')}, {pr_state}, review {review}, "
                     f"merge state {merge_state}")
        lines.append(f"  GitHub head {(pr.get('headRefOid') or '')[:7]}: {pr_head_relation} "
                     f"local {short_sha}")
        pr_checks = pull_request_checks(pr)
        failed = [f"{entry['name']} {entry['outcome'].lower()}" for entry in pr_checks
                  if not entry["pending"]
                  and entry["outcome"] not in ("SUCCESS", "SKIPPED", "NEUTRAL")]
        pending = [str(entry["name"]) for entry in pr_checks if entry["pending"]]
        if not pr_checks:
            lines.append("  checks: none registered yet")
        elif failed:
            lines.append(f"  failed checks: {', '.join(failed)}")
        elif pending:
            lines.append(f"  pending checks: {', '.join(pending)}")
        else:
            lines.append("  checks: all completed successfully")
    if branch != "HEAD":
        lines += ["", f"Dispatched test runs on {branch}:"]
        lines += [f"  failed   {entry['workflow']} {entry['job']} at {entry['head'][:7]}  "
                  f"{entry['url']}" for entry in branch_failed]
        lines += [f"  running  {run['workflow']} at {(run.get('headSha') or '')[:7]}  {run.get('url')}"
                  for run in branch_running]
        if not branch_failed and not branch_running:
            lines.append("  no failed or running checks")
    if merged_failed:
        lines += ["", "Failures left by merged pull requests (until a full run on master passes):"]
        lines += [f"  #{entry['number']} {entry['workflow']} {entry['job']} at {entry['head'][:7]}  "
                  f"{entry['url']}" for entry in merged_failed]
    if check:
        lines += ["", f"Baseline checks (started at {initial_head_sha[:7]}; worktree state is "
                      "reported above):"]
        lines += [f"  {entry['name']}: {entry['result']}  ({entry['command']})" for entry in checks]
    if warnings:
        lines.append("")
        lines += [f"WARNING: {warning}" for warning in warnings]
    print("\n".join(lines))
    return exit_status


def main():
    json_report = check = False
    for argument in sys.argv[1:]:
        if argument == "--json":
            json_report = True
        elif argument == "--check":
            check = True
        else:
            raise ToolError(f"usage: {sys.argv[0]} [--json] [--check]", 2)
    for tool in ("git", "gh"):
        if not shutil.which(tool):
            raise ToolError(f"branch status needs {tool}", 2)
    try:
        return report(json_report, check)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ToolError(f"unexpected GitHub response ({error!r})", 2) from None


if __name__ == "__main__":
    sys.exit(report_errors(main))
