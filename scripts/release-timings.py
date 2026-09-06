#!/usr/bin/env python3
"""Report the observable GitHub Actions phases of a syq release."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY = "greaber/syq"
WORKFLOWS = (
    ("syq certification", "ci.yml"),
    ("syq certification", "rsync-compat.yml"),
    ("syq certification", "macos.yml"),
    ("syq publication", "release.yml"),
    ("Python preparation", "prepare-python-sdk.yml"),
)


def gh_api(endpoint: str, *fields: str) -> Any:
    command = ["gh", "api", "-X", "GET", endpoint]
    for field in fields:
        command.extend(("-f", field))
    return json.loads(subprocess.check_output(command, text=True))


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def duration(start: str | None, end: str | None) -> int | None:
    parsed_start, parsed_end = parse_time(start), parse_time(end)
    if parsed_start is None or parsed_end is None:
        return None
    return max(0, round((parsed_end - parsed_start).total_seconds()))


def resolve_tag(tag: str) -> str | None:
    refs = gh_api(f"repos/{REPOSITORY}/git/matching-refs/tags/{tag}")
    exact = next((item for item in refs if item.get("ref") == f"refs/tags/{tag}"), None)
    if exact is None:
        return None
    target = exact["object"]
    while target["type"] == "tag":
        target = gh_api(f"repos/{REPOSITORY}/git/tags/{target['sha']}")["object"]
    return target["sha"] if target["type"] == "commit" else None


def matching_runs(workflow: str, commit: str, branch: str | None = None) -> list[dict[str, Any]]:
    response = gh_api(
        f"repos/{REPOSITORY}/actions/workflows/{workflow}/runs",
        f"head_sha={commit}",
        "per_page=100",
    )
    runs = [run for run in response.get("workflow_runs", []) if run.get("head_sha") == commit]
    if branch is not None:
        runs = [run for run in runs if run.get("head_branch") == branch]
    return sorted(runs, key=lambda run: run.get("created_at", ""))


def selected_run(workflow: str, runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not runs:
        return None
    successful = [run for run in runs if run.get("conclusion") == "success"]
    if workflow in {"ci.yml", "rsync-compat.yml", "macos.yml"} and successful:
        return successful[-1]
    return runs[-1]


def describe_run(phase: str, workflow: str, run: dict[str, Any]) -> dict[str, Any]:
    attempt = run.get("run_attempt", 1)
    response = gh_api(
        f"repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/{attempt}/jobs",
        "per_page=100",
    )
    jobs = []
    for job in response.get("jobs", []):
        steps = [
            {
                "name": step["name"],
                "status": step.get("status"),
                "conclusion": step.get("conclusion"),
                "started_at": step.get("started_at"),
                "completed_at": step.get("completed_at"),
                "duration_seconds": duration(step.get("started_at"), step.get("completed_at")),
            }
            for step in job.get("steps", [])
        ]
        jobs.append(
            {
                "name": job["name"],
                "status": job.get("status"),
                "conclusion": job.get("conclusion"),
                "started_at": job.get("started_at"),
                "completed_at": job.get("completed_at"),
                "duration_seconds": duration(job.get("started_at"), job.get("completed_at")),
                "steps": steps,
            }
        )
    return {
        "phase": phase,
        "workflow": workflow,
        "run_id": run["id"],
        "attempt": attempt,
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "duration_seconds": duration(run.get("created_at"), run.get("updated_at")),
        "url": run.get("html_url"),
        "jobs": jobs,
    }


def format_duration(seconds: int | None) -> str:
    if seconds is None:
        return "in progress"
    minutes, remainder = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {remainder}s"
    if minutes:
        return f"{minutes}m {remainder}s"
    return f"{remainder}s"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="syq release tag, for example v0.4.0")
    parser.add_argument("--json", action="store_true", help="emit machine-readable details")
    args = parser.parse_args()
    if not __import__("re").fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        parser.error("tag must have the form vMAJOR.MINOR.PATCH")

    commit = resolve_tag(args.tag)
    if commit is None:
        print(f"release tag does not exist: {args.tag}", file=sys.stderr)
        return 1

    entries = []
    for phase, workflow in WORKFLOWS:
        branch = args.tag if workflow == "release.yml" else None
        run = selected_run(workflow, matching_runs(workflow, commit, branch))
        if run is not None:
            entries.append(describe_run(phase, workflow, run))

    sdk_tag = f"sdk-python-{args.tag}"
    sdk_commit = resolve_tag(sdk_tag)
    if sdk_commit is not None:
        for workflow in ("ci.yml", "rsync-compat.yml", "macos.yml"):
            run = selected_run(workflow, matching_runs(workflow, sdk_commit))
            if run is not None:
                entries.append(describe_run("Python certification", workflow, run))
        runs = matching_runs("publish-sdks.yml", sdk_commit, sdk_tag)
        run = selected_run("publish-sdks.yml", runs)
        if run is not None:
            entries.append(describe_run("Python publication", "publish-sdks.yml", run))

    starts = [parse_time(entry["created_at"]) for entry in entries]
    ends = [parse_time(entry["updated_at"]) for entry in entries]
    starts = [value for value in starts if value is not None]
    ends = [value for value in ends if value is not None]
    observed = round((max(ends) - min(starts)).total_seconds()) if starts and ends else None
    result = {
        "repository": REPOSITORY,
        "tag": args.tag,
        "tag_commit": commit,
        "python_tag": sdk_tag if sdk_commit else None,
        "python_tag_commit": sdk_commit,
        "observable_window_seconds": observed,
        "runs": entries,
    }
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
        return 0

    print(f"Release timing for {args.tag} at {commit}")
    print(f"  observable GitHub window: {format_duration(observed)}")
    for entry in entries:
        state = entry["conclusion"] or entry["status"]
        print(f"  {entry['phase']}: {entry['workflow']} run {entry['run_id']} — "
              f"{format_duration(entry['duration_seconds'])} ({state})")
        for job in sorted(entry["jobs"], key=lambda item: item["duration_seconds"] or -1, reverse=True):
            print(f"    {format_duration(job['duration_seconds']):>10}  {job['name']}")
    print("  Runs and jobs can overlap; their durations are not additive.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
