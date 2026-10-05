#!/usr/bin/env python3
"""Report the state of the current task branch.

Usage: scripts/branch-status.py [--json] [--check]
       scripts/branch-status.py --address-master-run RUN --reason TEXT --fix URL

Reports the worktree, the branch's pull request, the latest post-merge and
nightly CI runs on master, the latest result of each check dispatched on this
branch, and failed checks left by recently merged branches. Its output is what
a status report or review request should state. scripts/pr-checks.py lists
the dispatched checks of any pull request.

Fetches origin's master, since a local master branch is updated only by
manual pulls and says nothing about current master. Otherwise only reads git
and GitHub state, except --address-master-run, which records a separate commit
status for a failed master run and its attempt. Addressed runs keep their failed
conclusion but no longer produce a reminder. A new run or rerun is independent;
addressing a failure never supplies passing tests or release certification.
With --check it also runs the fixed Rust baseline (fmt, clippy, unit tests)
in this worktree.

A job that failed in a run dispatched on this branch stays a failure until a
later dispatched run of the same job on the branch passes or that exact failed
job is explicitly resolved. Resolutions remain visible in the report. Runs in
progress at a merge keep running, so a failure left on a merged branch is
reported until the next successful full-suite run of that workflow on master.

Red master runs and failures left by merged branches are reported as notes:
they are separate problems and do not make this branch's status fail.

Exit status: 0 when nothing needs attention; 1 when a dispatched check on this
branch failed, the GitHub head is stale or unrelated, or a --check step failed
or changed worktree status; 2 on usage/tooling errors or HEAD moving during
checks (stderr diagnostic, no report, even with --json). The pull request's
check rollup is reported as is; its required `dispatched-checks` status
reflects the same dispatched failures this script reports.
"""
import argparse
import json
import shutil
import subprocess
import sys

from dispatched_checks import (BRANCH_WORKFLOWS, apply_resolutions, branch_runs, check_results,
                               dispatched_runs, failed_checks, fetch_commit_statuses, fetch_jobs,
                               fetch_resolutions, in_parallel, merged_from_branch,
                               merged_pull_requests, result_lines,
                               run_jobs, running, undecided, unresolved)
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
# The full-suite master workflows whose next success covers a merged failure.
# Focused scripts can run anything, so they wait for both native suites.
CLEARED_BY = {"ci.yml": ("ci.yml",), "macos.yml": ("macos.yml",),
              "rsync-compat.yml": ("rsync-compat.yml",),
              "focused-check.yml": ("ci.yml", "macos.yml")}


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


def master_run(workflow, event):
    """The latest run of a workflow on master for one trigger."""
    runs = json_output("gh", "run", "list", "--repo", REPOSITORY, "--workflow", workflow,
                       "--branch", "master", "--event", event, "--limit", "1", "--json",
                       "headSha,status,conclusion,url,createdAt,databaseId,attempt", status=2)
    return runs[0] if runs else None


def run_state(workflow, run, kind, note):
    """A master run's state, noting when it is missing or red."""
    state = "missing"
    if run:
        if run.get("status") == "completed":
            state = run.get("conclusion") or ""
        else:
            state = run.get("status") or "unknown"
    if state == "missing":
        note(f"{workflow} has no {kind} run on master")
    elif state != "success" and state not in UNFINISHED and not run.get("resolution"):
        note(f"master is red: {workflow} {kind} {state} at {(run.get('headSha') or '')[:7]} "
             f"{run.get('url')}")
    return state


def master_resolution_context(run):
    return f"master-ci-addressed/{run['databaseId']}/{run['attempt']}"


def failed_master_run(run):
    return (run and run.get("status") == "completed"
            and run.get("conclusion") not in ("success", "neutral", "skipped"))


def annotate_master_runs(runs):
    """Keep the original results and attach acknowledgments of exact attempts."""
    statuses = fetch_commit_statuses(REPOSITORY, {run["headSha"] for run in runs
                                                if failed_master_run(run)})
    for run in runs:
        if not failed_master_run(run):
            continue
        resolution = statuses.get(run["headSha"], {}).get(master_resolution_context(run), {})
        if (resolution.get("state") == "success" and (resolution.get("description") or "").strip()
                and resolution.get("target_url")):
            run["resolution"] = {
                "reason": resolution["description"], "fix": resolution["target_url"],
                "actor": (resolution.get("creator") or {}).get("login"),
                "created_at": resolution.get("created_at"), "url": resolution.get("url")}


def address_master_run(run_id, reason, fix):
    """Acknowledge only a currently reported failed master run's exact attempt."""
    runs = in_parallel([lambda workflow=workflow, event=event: master_run(workflow, event)
                        for workflow in WORKFLOWS for event in ("push", "schedule")])
    run = next((run for run in runs if run and run.get("databaseId") == run_id), None)
    if not failed_master_run(run):
        raise ToolError(f"run {run_id} is not a current failed post-merge or nightly master run", 2)
    output("gh", "api", "--method", "POST", f"repos/{REPOSITORY}/statuses/{run['headSha']}",
           "-f", "state=success", "-f", f"context={master_resolution_context(run)}",
           "-f", f"description={reason}", "-f", f"target_url={fix}", status=2)
    print(f"Addressed master run {run_id}, attempt {run['attempt']}, at {run['headSha'][:7]}: "
          f"{reason} {fix}")
    print("The original result is unchanged; this is not passing test or release evidence.")
    return 0


def open_pull_request(branch):
    """The branch's open pull request; an empty list means none, a failure is an error."""
    try:
        prs = json_output("gh", "pr", "list", "--repo", REPOSITORY, "--head", branch, "--state",
                          "open", "--limit", "1", "--json",
                          "number,url,state,isDraft,baseRefName,headRefOid,reviewDecision,"
                          "mergeStateStatus,statusCheckRollup", status=2)
    except ToolError:
        raise ToolError(f"could not look up the pull request for {branch}", 2) from None
    return prs[0] if prs else None


def latest_full_run(workflow):
    """When the latest successful full-suite run of a workflow on master started.
    Only nightly and manual runs can be full, so busy days of pushes don't
    crowd them out."""
    runs = [run for event in ("schedule", "workflow_dispatch") for run in json_output(
        "gh", "run", "list", "--repo", REPOSITORY, "--workflow", workflow, "--branch", "master",
        "--event", event, "--limit", "20", "--json", "databaseId,createdAt,status,conclusion",
        status=2)]
    for run in sorted(runs, key=lambda run: run.get("createdAt") or "", reverse=True):
        if run.get("conclusion") == "success":
            passed = {job.get("name") for job in run_jobs(REPOSITORY, run)
                      if job.get("conclusion") == "success"}
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
    # Problems elsewhere in the repository, reported without failing this branch.
    notes = []
    note = notes.append

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
    # Branch names get reused, so this branch's own earlier merges are looked up
    # directly rather than from the recent merges shared with other branches.
    lookups = [lambda: open_pull_request(branch) if branch != "HEAD" else None,
               lambda: merged_pull_requests(REPOSITORY),
               lambda: merged_from_branch(REPOSITORY, branch) if branch != "HEAD" else []]
    lookups += [lambda workflow=workflow, event=event: master_run(workflow, event)
                for workflow in WORKFLOWS for event in ("push", "schedule")]
    lookups += [lambda workflow=workflow: dispatched_runs(REPOSITORY, workflow)
                for workflow in BRANCH_WORKFLOWS]
    # The recent runs on every branch can crowd out this branch's older ones.
    lookups += [lambda workflow=workflow: dispatched_runs(REPOSITORY, workflow, branch)
                if branch != "HEAD" else [] for workflow in BRANCH_WORKFLOWS]
    results = in_parallel(lookups)
    pr, merged, own_merged = results[:3]
    latest_runs = results[3:3 + 2 * len(WORKFLOWS)]
    annotate_master_runs(latest_runs)
    latest = iter(latest_runs)
    runs = {run.get("databaseId"): run for workflow_runs in results[3 + 2 * len(WORKFLOWS):]
            for run in workflow_runs}
    runs = list(runs.values())
    master_runs = []
    for workflow in WORKFLOWS:
        push_run, nightly_run = next(latest), next(latest)
        master_runs.append({
            "workflow": workflow, "state": run_state(workflow, push_run, "post-merge", note),
            "run": push_run, "nightly": {
                "state": run_state(workflow, nightly_run, "nightly", note), "run": nightly_run}})

    pr_head_relation = "none"
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
    # A merged branch needs its jobs read only while its failing workflows have
    # had no full run on master since the merge.
    own_runs = branch_runs(runs, branch, own_merged) if branch != "HEAD" else []
    merged_runs = [(merged_pr, branch_runs(runs, merged_pr.get("headRefName"), merged,
                                           merged_pr.get("mergedAt") or ""))
                   for merged_pr in merged]
    clearing = sorted({workflow for _, pr_runs in merged_runs for run in undecided(pr_runs)
                       for workflow in CLEARED_BY[run["workflow"]]})
    full_runs = dict(zip(clearing, in_parallel(
        [lambda workflow=workflow: latest_full_run(workflow) for workflow in clearing])))

    def cleared(workflow, merged_at):
        return all(full_runs.get(name, "") > merged_at for name in CLEARED_BY[workflow])

    merged_runs = [(merged_pr, [run for run in pr_runs if not cleared(
        run["workflow"], merged_pr.get("mergedAt") or "")]) for merged_pr, pr_runs in merged_runs]
    # Every run on this branch is listed; merged branches only need their failures.
    jobs = fetch_jobs(REPOSITORY, own_runs + [run for _, pr_runs in merged_runs
                                              for run in undecided(pr_runs)])
    branch_results = check_results(own_runs, jobs)
    merged_results = [(merged_pr, failed_checks(pr_runs, jobs)) for merged_pr, pr_runs in merged_runs]
    resolutions = fetch_resolutions(REPOSITORY, (branch_results if pr else []) +
                                   [entry for _, results in merged_results for entry in results])
    branch_results = apply_resolutions(pr["number"] if pr else None, branch_results, resolutions)
    branch_failed = [entry for entry in branch_results if unresolved(entry)]
    branch_running = running(own_runs)
    for entry in branch_failed:
        warn(f"{entry['workflow']} {entry['job']} {entry['conclusion']} at {entry['head'][:7]} on "
             f"this branch, and no later run passed it {entry['url']}")
    merged_failed = []
    for merged_pr, results in merged_results:
        for entry in apply_resolutions(merged_pr["number"], results, resolutions):
            if not unresolved(entry):
                continue
            merged_failed.append(dict(entry, number=merged_pr.get("number"),
                                      pull_request=merged_pr.get("url")))
            note(f"#{merged_pr.get('number')} merged with {entry['workflow']} {entry['job']} "
                 f"{entry['conclusion']} at {entry['head'][:7]}, and no full run of "
                 f"{' and '.join(CLEARED_BY[entry['workflow']])} on master has passed since "
                 f"{entry['url']}")

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
            "dispatched": {"results": branch_results, "failed": branch_failed,
                           "running": branch_running},
            "merged_failures": merged_failed, "checks": checks, "notes": notes,
            "warnings": warnings, "exit_status": exit_status,
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
        if resolution := run.get("resolution"):
            return (f"  {label:<16} {'addressed':<12} {(run.get('headSha') or '')[:7]}  "
                    f"{run.get('url')}\n    original result: {state}; {resolution['reason']} "
                    f"{resolution['fix']}")
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
        lines += ["", f"Dispatched checks on {branch} (latest result of each, then unfinished runs):"]
        lines += result_lines(branch_results, branch_running)
    if merged_failed:
        lines += ["", "Failures left by merged pull requests (until a full run on master passes):"]
        lines += [f"  #{entry['number']} {entry['workflow']} {entry['job']} at {entry['head'][:7]}  "
                  f"{entry['url']}" for entry in merged_failed]
    if check:
        lines += ["", f"Baseline checks (started at {initial_head_sha[:7]}; worktree state is "
                      "reported above):"]
        lines += [f"  {entry['name']}: {entry['result']}  ({entry['command']})" for entry in checks]
    if notes or warnings:
        lines.append("")
        lines += [f"NOTE: {entry}" for entry in notes]
        lines += [f"WARNING: {warning}" for warning in warnings]
    print("\n".join(lines))
    return exit_status


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="Print a JSON report")
    parser.add_argument("--check", action="store_true", help="Run the Rust baseline")
    parser.add_argument("--address-master-run", type=int, metavar="RUN",
                        help="Stop reminders for this exact failed master run attempt")
    parser.add_argument("--reason", help="One-line reason (1–140 characters)")
    parser.add_argument("--fix", help="HTTPS link to the merged repair or replacement evidence")
    args = parser.parse_args()
    if args.address_master_run is not None:
        if args.address_master_run <= 0 or args.json or args.check:
            parser.error("--address-master-run requires a positive run ID and no report options")
        args.reason = (args.reason or "").strip()
        if not 1 <= len(args.reason) <= 140 or any(c in args.reason for c in "\r\n"):
            parser.error("--reason must be one line of 1–140 characters")
        if not args.fix or not args.fix.startswith("https://") or any(c.isspace() for c in args.fix):
            parser.error("--fix requires an HTTPS URL")
    elif args.reason is not None or args.fix is not None:
        parser.error("--reason and --fix require --address-master-run")
    for tool in ("git", "gh"):
        if not shutil.which(tool):
            raise ToolError(f"branch status needs {tool}", 2)
    try:
        if args.address_master_run is not None:
            return address_master_run(args.address_master_run, args.reason, args.fix)
        return report(args.json, args.check)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ToolError(f"unexpected GitHub response ({error!r})", 2) from None


if __name__ == "__main__":
    sys.exit(report_errors(main))
