#!/usr/bin/env python3
"""Report the state of the current task branch.

Usage: scripts/branch-status.py [--json] [--check]

Reports the worktree, the branch's pull request, and the latest post-merge and
nightly CI runs on master. Its output is what a status report or review
request should state.

Fetches origin's master, since a local master branch is updated only by
manual pulls and says nothing about current master. Otherwise only reads git
and GitHub state. With --check it also runs the fixed Rust baseline (fmt,
clippy, unit tests) in this worktree.

Exit status: 0 when nothing needs attention; 1 when master's latest
post-merge or nightly run failed, the GitHub head is stale or unrelated, or a
--check step failed or changed worktree status; 2 on usage/tooling errors or
HEAD moving during checks (stderr diagnostic, no report, even with --json).
Pull-request checks are reported but do not gate handoff or merging.
"""
import re
import shutil
import subprocess
import sys

from tooling import (JqError, alt, captured, command, dumps, exit_on_failure, get, items, join,
                     loads, truthy)

REPOSITORY = "greaber/syq"
WORKFLOWS = ("ci.yml", "rsync-compat.yml", "macos.yml")
MASTER_REF = "refs/remotes/origin/master"
BASELINE = [
    ("fmt", ["cargo", "fmt", "--all", "--", "--check"]),
    ("clippy", ["cargo", "clippy", "--locked", "--all-targets", "--all-features", "--", "-D",
                "warnings"]),
    ("unit-tests", ["cargo", "test", "--locked", "--bin", "syq"]),
]


class Stop(Exception):
    """A tooling failure: report it on stderr and exit 2 without a report."""


def git(*args):
    return command("git", *args).rstrip("\n")


def quiet(*args):
    return subprocess.run(list(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def counts(status_lines):
    lines = status_lines.split("\n")
    return (sum(1 for line in lines if re.match(r"[MADRCT]", line)),
            sum(1 for line in lines if re.match(r".[MADRCT]", line)),
            sum(1 for line in lines if line.startswith("??")))


def left_right(range_):
    completed = subprocess.run(["git", "rev-list", "--left-right", "--count", range_],
                               stdout=subprocess.PIPE, text=True)
    fields = completed.stdout.split() if completed.returncode == 0 else []
    fields += ["", ""]
    return [int(field) if field.isdigit() else field for field in fields[:2]]


def ascii_case(value, upper):
    if not isinstance(value, str):
        raise JqError(5, "ascii case conversion needs a string")
    if upper:
        return "".join(chr(ord(c) - 32) if "a" <= c <= "z" else c for c in value)
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in value)


def prefix(value, length=7):
    """jq's `.[0:7]` of a string, or null."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise JqError(5, "cannot slice a non-string")
    return value[:length]


def first(value):
    """jq's `first // null` over an array."""
    if not isinstance(value, list):
        raise JqError(5, "expected an array")
    return alt(value[0] if value else None, None)


def concat(*parts):
    if not all(isinstance(part, str) for part in parts):
        raise JqError(5, "cannot add a string and a non-string")
    return "".join(parts)


def main():
    json_output = check = False
    for argument in sys.argv[1:]:
        if argument == "--json":
            json_output = True
        elif argument == "--check":
            check = True
        else:
            print(f"usage: {sys.argv[0]} [--json] [--check]", file=sys.stderr)
            return 2
    for tool in ("git", "gh"):
        if not shutil.which(tool):
            print(f"branch status needs {tool}", file=sys.stderr)
            return 2
    try:
        return report(json_output, check)
    except Stop as error:
        print(error, file=sys.stderr)
        return 2


def latest_run(workflow, event, kind, warn):
    """The latest run of a workflow on master for one trigger, and its state."""
    completed = subprocess.run([
        "gh", "run", "list", "--repo", REPOSITORY, "--workflow", workflow, "--branch", "master",
        "--event", event, "--limit", "1", "--json",
        "headSha,status,conclusion,url,createdAt,databaseId"], stdout=subprocess.PIPE, text=True)
    if completed.returncode:
        raise Stop(f"could not list {workflow} {kind} runs on master")
    run = first(loads(completed.stdout))
    state = "missing"
    if run is not None:
        status = captured(get(run, "status"))
        conclusion = captured(alt(get(run, "conclusion"), ""))
        state = conclusion if status == "completed" else status
    if state == "missing":
        warn(f"{workflow} has no {kind} run on master")
    elif state not in ("success", "queued", "in_progress", "pending", "waiting", "requested"):
        warn(f"master is red: {workflow} {kind} {state} at {captured(prefix(get(run, 'headSha')))} "
             f"{captured(get(run, 'url'))}")
    return run, state


def report(json_output, check):
    warnings = []
    warn = warnings.append

    # Worktree and branch.
    toplevel = git("rev-parse", "--show-toplevel")
    head_sha = git("rev-parse", "HEAD")
    short_sha = git("rev-parse", "--short", "HEAD")
    symbolic = subprocess.run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
                              stdout=subprocess.PIPE, text=True)
    branch = symbolic.stdout.rstrip("\n") if symbolic.returncode == 0 else "HEAD"
    status_lines = git("status", "--porcelain", "--untracked-files=all")
    initial_status_lines = status_lines
    initial_head_sha = head_sha
    staged, unstaged, untracked = counts(status_lines)
    clean = not status_lines

    upstream_lookup = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    upstream = upstream_lookup.stdout.rstrip("\n") if upstream_lookup.returncode == 0 else ""
    upstream_ahead = upstream_behind = None
    if upstream:
        upstream_ahead, upstream_behind = left_right(f"HEAD...{upstream}")

    if subprocess.run(["git", "fetch", "--quiet", "origin",
                       f"+refs/heads/master:{MASTER_REF}"]).returncode:
        raise Stop("could not fetch master from origin")
    master_sha = git("rev-parse", MASTER_REF)
    master_short = git("rev-parse", "--short", MASTER_REF)
    ahead_of_master, behind_master = left_right(f"HEAD...{MASTER_REF}")

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
    if branch != "HEAD":
        completed = subprocess.run([
            "gh", "pr", "list", "--repo", REPOSITORY, "--head", branch, "--state", "open",
            "--limit", "1", "--json", "number,url,state,isDraft,baseRefName,headRefOid,"
            "reviewDecision,mergeStateStatus,statusCheckRollup"], stdout=subprocess.PIPE, text=True)
        if completed.returncode:
            raise Stop(f"could not look up the pull request for {branch}")
        pr = first(loads(completed.stdout))
    pr_head_relation = "none"
    if pr is not None:
        pr_head = captured(get(pr, "headRefOid"))
        pr_number = captured(get(pr, "number"))
        if pr_head == head_sha:
            pr_head_relation = "matches"
        elif quiet("git", "merge-base", "--is-ancestor", pr_head, "HEAD").returncode == 0:
            pr_head_relation = "github-behind"
            warn(f"PR #{pr_number} head {pr_head[:7]} is behind local {short_sha}; "
                 "push before reporting")
        elif quiet("git", "merge-base", "--is-ancestor", head_sha, pr_head).returncode == 0:
            pr_head_relation = "local-behind"
            warn(f"local {short_sha} is behind PR #{pr_number} head {pr_head[:7]}")
        else:
            pr_head_relation = "unrelated"
            warn(f"PR #{pr_number} head {pr_head[:7]} is not related to local {short_sha}")
        # The rollup mixes check runs (name, status, conclusion) and commit status
        # contexts (context, state); normalize both to a name, an outcome, and
        # whether the check is still pending.
        pr_checks = []
        for entry in items(get(pr, "statusCheckRollup")):
            outcome = ascii_case(alt(alt(get(entry, "conclusion"), get(entry, "state")), ""), True)
            pr_checks.append({"name": alt(alt(get(entry, "name"), get(entry, "context")), "unnamed"),
                              "outcome": outcome,
                              "pending": outcome in ("", "PENDING", "EXPECTED")})
        check_count = len(pr_checks)
        failed_checks = ", ".join(
            concat(entry["name"], " ", ascii_case(entry["outcome"], False)) for entry in pr_checks
            if not entry["pending"] and entry["outcome"] not in ("SUCCESS", "SKIPPED", "NEUTRAL"))
        pending_checks = join([entry["name"] for entry in pr_checks if entry["pending"]], ", ")

    # Optional fixed Rust baseline.
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
        head_sha = git("rev-parse", "HEAD")
        short_sha = git("rev-parse", "--short", "HEAD")
        status_lines = git("status", "--porcelain", "--untracked-files=all")
        staged, unstaged, untracked = counts(status_lines)
        clean = not status_lines
        if head_sha != initial_head_sha:
            raise Stop(f"HEAD changed during baseline checks: {initial_head_sha} -> {head_sha}; "
                       "rerun branch-status")
        if status_lines != initial_status_lines:
            warn("worktree status changed during baseline checks; inspect changes and rerun "
                 "affected checks")

    if not clean:
        warn(f"worktree is dirty: {staged} staged, {unstaged} unstaged, {untracked} untracked")

    exit_status = 1 if warnings else 0
    # A dirty worktree is worth stating but is not by itself a problem.
    if len(warnings) == 1 and warnings[0].startswith("worktree is dirty"):
        exit_status = 0

    if json_output:
        if "" in (upstream_ahead, upstream_behind, ahead_of_master, behind_master):
            raise JqError(2, "invalid JSON text passed to --argjson")
        print(dumps({
            "worktree": {
                "path": toplevel, "branch": branch, "head": head_sha, "short": short_sha,
                "clean": clean, "staged": staged, "unstaged": unstaged, "untracked": untracked,
                "upstream": upstream or None, "ahead_of_upstream": upstream_ahead,
                "behind_upstream": upstream_behind, "master_ref": MASTER_REF,
                "master": master_sha, "ahead_of_master": ahead_of_master,
                "behind_master": behind_master,
            },
            "master_ci": master_runs, "pull_request": pr, "pull_request_head": pr_head_relation,
            "checks": checks, "warnings": warnings, "exit_status": exit_status,
        }, indent=2))
        return exit_status

    lines = [f"Worktree: {toplevel}"]
    if clean:
        lines.append(f"Branch:   {branch} at {short_sha} (clean)")
    else:
        lines.append(f"Branch:   {branch} at {short_sha} (dirty: {staged} staged, {unstaged} "
                     f"unstaged, {untracked} untracked)")
    if upstream:
        lines.append(f"Upstream: {upstream} (ahead {upstream_ahead}, behind {upstream_behind})")
    else:
        lines.append("Upstream: none")
    lines.append(f"Master:   {master_short} from {MASTER_REF} (branch is ahead {ahead_of_master}, "
                 f"behind {behind_master})")
    lines.append("")
    lines.append("Master CI (latest post-merge run per workflow, then its latest nightly full suite):")

    def run_line(label, state, run):
        if run is None:
            return f"  {label:<16} {state:<12} (no run)"
        return (f"  {label:<16} {state:<12} {captured(prefix(get(run, 'headSha')))}  "
                f"{captured(get(run, 'url'))}")

    for entry in master_runs:
        lines.append(run_line(entry["workflow"], entry["state"], entry["run"]))
        lines.append(run_line("  nightly", entry["nightly"]["state"], entry["nightly"]["run"]))
    lines.append("")
    if pr is None:
        lines.append(f"Pull request: none for {branch}")
    else:
        lines.append(f"Pull request: #{captured(get(pr, 'number'))} {captured(get(pr, 'url'))}")
        pr_state = "draft" if truthy(get(pr, "isDraft")) else ascii_case(get(pr, "state"), False)
        review = alt(get(pr, "reviewDecision"), "")
        review = "none" if review == "" else ascii_case(review, False)
        merge_state = ascii_case(alt(get(pr, "mergeStateStatus"), "unknown"), False)
        lines.append(f"  base {captured(get(pr, 'baseRefName'))}, {captured(pr_state)}, "
                     f"review {captured(review)}, merge state {captured(merge_state)}")
        lines.append(f"  GitHub head {captured(prefix(get(pr, 'headRefOid')))}: "
                     f"{pr_head_relation} local {short_sha}")
        if check_count == 0:
            lines.append("  checks: none registered yet")
        elif failed_checks:
            lines.append(f"  failed checks: {failed_checks}")
        elif pending_checks:
            lines.append(f"  pending checks: {pending_checks}")
        else:
            lines.append("  checks: all completed successfully")
    if check:
        lines.append("")
        lines.append(f"Baseline checks (started at {initial_head_sha[:7]}; worktree state is "
                     "reported above):")
        for entry in checks:
            lines.append(f"  {entry['name']}: {entry['result']}  ({entry['command']})")
    if warnings:
        lines.append("")
        lines.extend(f"WARNING: {warning}" for warning in warnings)
    print("\n".join(lines))
    return exit_status


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
