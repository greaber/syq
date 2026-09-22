#!/usr/bin/env python3
"""Run a command or local Bash script on a CI runner and watch that exact run."""

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
from urllib.parse import quote


def output(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", choices=("linux", "macos", "macos-intel"), required=True)
    parser.add_argument("--provider", choices=("namespace", "github"), default="namespace")
    parser.add_argument("--ref", help="Pushed branch/tag; defaults to the current branch")
    parser.add_argument("--script", type=Path, help="Local Bash file, including any setup")
    parser.add_argument("--cargo-cache", action="store_true")
    parser.add_argument("--timeout", type=int, default=15, help="Runner timeout in minutes (1–90)")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command after --")
    args = parser.parse_args()
    if args.runner == "macos-intel" and args.provider != "github":
        parser.error("macos-intel requires --provider github")
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if bool(command) == bool(args.script):
        parser.error("provide either a command after -- or --script FILE")
    if not 1 <= args.timeout <= 90:
        parser.error("--timeout must be between 1 and 90 minutes")
    script = args.script.read_text() if args.script else shlex.join(command)
    if not script.strip():
        parser.error("the script must not be empty")

    repo = output("gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner")
    ref = args.ref or output("git", "symbolic-ref", "--quiet", "--short", "HEAD")
    revision = output("gh", "api", f"repos/{repo}/commits/{quote(ref, safe='')}", "--jq", ".sha")
    if not args.ref:
        if output("git", "status", "--porcelain"):
            parser.error("commit and push your changes first; only remote commits are tested")
        if revision != output("git", "rev-parse", "HEAD"):
            parser.error("remote branch differs from HEAD; push first or select --ref explicitly")
    payload = {
        "ref": ref,
        "inputs": {
            "runner": args.runner,
            "provider": args.provider,
            "revision": revision,
            "script": script,
            "cargo_cache": str(args.cargo_cache).lower(),
            "timeout": str(args.timeout),
        },
    }
    print(f"Checking {repo}@{revision} on {args.provider}/{args.runner}", flush=True)
    response = json.loads(output(
        "gh", "api", f"repos/{repo}/actions/workflows/focused-check.yml/dispatches",
        "-H", "X-GitHub-Api-Version: 2026-03-10", "--input", "-",
        input=json.dumps(payload),
    ))
    run_id = response.get("workflow_run_id")
    if type(run_id) is not int or run_id <= 0:
        raise ValueError(f"dispatch did not return a run ID: {response}")
    print(f"https://github.com/{repo}/actions/runs/{run_id}", flush=True)
    print(f"To cancel: gh run cancel {run_id} --repo {repo}", flush=True)
    return subprocess.call(["gh", "run", "watch", str(run_id), "--repo", repo, "--exit-status"])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
