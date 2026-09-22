#!/usr/bin/env python3
"""Select successful manual release binaries for this exact master commit."""

import json
import subprocess
import sys

ASSETS = {"syq-linux-x86_64", "syq-linux-aarch64", "syq-macos-arm64", "syq-macos-x86_64"}
WORKFLOW = ".github/workflows/reproducible-builds.yml"


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def eligible(run, repository, commit):
    return (run["head_sha"] == commit and run["event"] == "workflow_dispatch"
            and run["head_branch"] == "master" and run["path"] == WORKFLOW
            and run["head_repository"]["full_name"] == repository)


def complete_artifacts(artifacts):
    names = [item["name"] for item in artifacts if not item["expired"]]
    return all(names.count(name) == 1 for name in ASSETS)


def main():
    repository, commit = sys.argv[1:]
    prefix = f"repos/{repository}/actions"
    runs = api(f"{prefix}/workflows/reproducible-builds.yml/runs?head_sha={commit}&event=workflow_dispatch&per_page=100")["workflow_runs"]
    runs = sorted((run for run in runs if eligible(run, repository, commit)),
                  key=lambda run: run["id"], reverse=True)
    if not runs:
        return
    run = runs[0]
    run_id = run["id"]
    if run["status"] != "completed":
        # A candidate build may outlast validation. Wait rather than build twice.
        subprocess.run(["gh", "run", "watch", str(run_id), "--repo", repository,
                        "--exit-status", "--interval", "30"], check=True,
                       timeout=75 * 60, stdout=sys.stderr)
        run = api(f"{prefix}/runs/{run_id}")
    if not eligible(run, repository, commit) or run["conclusion"] != "success":
        return
    artifacts = api(f"{prefix}/runs/{run_id}/artifacts?per_page=100")["artifacts"]
    if complete_artifacts(artifacts):
        print(f"run-id={run_id}")
        print(f"Reusing release binaries from run {run_id} at {commit}", file=sys.stderr)


if __name__ == "__main__":
    main()
