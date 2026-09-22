#!/usr/bin/env python3
"""Select successful manual native or Python artifacts for an exact release commit."""

import argparse
import json
import subprocess
import sys

ASSETS = {"syq-linux-x86_64", "syq-linux-aarch64", "syq-macos-arm64", "syq-macos-x86_64",
          "source-crate"}
WORKFLOW = ".github/workflows/reproducible-builds.yml"


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def eligible(run, repository, commit, workflow=WORKFLOW, branches=("master",)):
    return (run["head_sha"] == commit and run["event"] == "workflow_dispatch"
            and run["head_branch"] in branches and run["path"] == workflow
            and run["head_repository"]["full_name"] == repository)


def complete_artifacts(artifacts, assets=ASSETS):
    names = [item["name"] for item in artifacts if not item["expired"]]
    return all(names.count(name) == 1 for name in assets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository")
    parser.add_argument("commit")
    parser.add_argument("--python-version")
    args = parser.parse_args()
    repository, commit = args.repository, args.commit
    workflow, assets, branches = WORKFLOW, ASSETS, ("master",)
    if args.python_version:
        workflow = ".github/workflows/publish-sdks.yml"
        assets = {f"python-sdk-{target}" for target in (
            "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin", "aarch64-apple-darwin")}
        branches = ("master", f"automation/python-sdk-v{args.python_version}")
    prefix = f"repos/{repository}/actions"
    runs = api(f"{prefix}/workflows/{workflow.rsplit('/', 1)[-1]}/runs?head_sha={commit}&event=workflow_dispatch&per_page=100")["workflow_runs"]
    runs = sorted((run for run in runs if eligible(run, repository, commit, workflow, branches)),
                  key=lambda run: run["id"], reverse=True)
    if not runs:
        return
    run = runs[0]
    run_id = run["id"]
    if run["status"] != "completed":
        # A candidate build may outlast validation. Wait rather than build twice.
        subprocess.run(["gh", "run", "watch", str(run_id), "--repo", repository,
                        "--exit-status", "--interval", "30"], check=False,
                       timeout=75 * 60, stdout=sys.stderr)
        run = api(f"{prefix}/runs/{run_id}")
        if run["status"] != "completed":
            raise RuntimeError("Candidate build wait ended before completion")
    if not eligible(run, repository, commit, workflow, branches) or run["conclusion"] != "success":
        return
    artifacts = api(f"{prefix}/runs/{run_id}/artifacts?per_page=100")["artifacts"]
    if complete_artifacts(artifacts, assets):
        print(f"run-id={run_id}")
        print(f"Reusing release artifacts from run {run_id} at {commit}", file=sys.stderr)


if __name__ == "__main__":
    main()
