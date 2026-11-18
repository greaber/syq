#!/usr/bin/env python3
"""Report missing release preparation and CI; record reusable local SSH validation.

Exit 0: ready for preflight (or the requested SSH check passed).
Exit 1: preparation/validation is incomplete. Exit 2: inspection/tooling failed.
No tags, publications, PRs, or CI runs are created. Until macos.yml certifies the
candidate, this lints its macOS build locally. --check-ssh runs the local lab.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

from release_checks import ReleaseCheck, clean_candidate, inputs_receipt_path, ssh_evidence
from tooling import ToolError

SCRIPTS = Path(__file__).resolve().parent


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def check_ssh():
    commit, tree = clean_candidate()
    # Invalidate an earlier success before a deliberate rerun, including on failure.
    path = inputs_receipt_path(commit)
    path.parent.mkdir(parents=True, exist_ok=True)
    # A failed deliberate rerun must also supersede old equivalent-tree evidence.
    path.write_text(json.dumps({"schema": 2, "commit": commit, "tree": tree,
                                "profile": "default", "result": "pending"}))
    receipt = {
        "schema": 2, "commit": commit, "tree": tree, "profile": "default",
        "host": platform.platform(), "docker": run("docker", "--version"),
        "compose": run("docker", "compose", "version"),
    }
    subprocess.run([str(SCRIPTS / "test-real-ssh.py")], check=True, stdout=sys.stderr)
    if clean_candidate() != (commit, tree):
        raise ValueError("checkout changed during real-SSH validation; no evidence recorded")
    receipt.update(result="success", completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    os.replace(output.name, path)
    print(f"Real-SSH evidence recorded for {commit} (default profile, tree {tree}).", file=sys.stderr)


def macos_lint(certification):
    """Lint the macOS build until the macOS suite certifies these inputs. A failure
    would stop that suite at its first step, so it shows here in about a minute,
    before any validation runs on a candidate the repair must replace."""
    if all(workflow["state"] == "ready" for workflow in certification["workflows"]
           if workflow["workflow"] == "macos.yml"):
        return "skipped"
    status = subprocess.run([str(SCRIPTS / "check-macos-lint.py")], stdout=sys.stderr).returncode
    return {0: "passed", 1: "failed"}.get(status, "unavailable")


def readiness(tag):
    check = ReleaseCheck(tag)
    lint = None
    def macos_lint_issue(certification):
        # Before the SSH lab and CI: a repair replaces the candidate they would test.
        nonlocal lint
        lint = macos_lint(certification)
        if lint == "failed":
            yield {"message": "the macOS lint failed, which fails the full ci.yml run's macos-lint "
                              "job and blocks certification; errors in syq's code would also "
                              "fail the macOS suite",
                   "next_action": "If scripts/check-macos-lint.py reports errors in syq's code, "
                                  "repair them through a PR and use the repaired commit as the "
                                  "candidate, starting no validation for this one. Errors outside "
                                  "syq's code, such as a dependency build script that needs a "
                                  "real C compiler, need a repair to scripts/check-macos-lint.py."}
    issues = list(check.issues(after_ci=macos_lint_issue))
    # A lint that cannot run only warns in ci.yml, so here it never comes first.
    if lint == "unavailable":
        issues.append({"message": "the macOS lint could not run; macOS CI still validates the "
                                  "candidate",
                       "next_action": "Optionally run scripts/check-macos-lint.py and fix what "
                                      "stops it."})
    return {"schema": 1, "tag": tag, "commit": check.commit, "remote_master": check.remote_master,
            "ready": not issues, "ssh": check.ssh, "ci": check.certification, "macos_lint": lint,
            "missing": issues,
            "next_action": issues[0]["next_action"] if issues else f"scripts/release-preflight.py {tag}"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("--json", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check-ssh", action="store_true", help="run the default local lab and record successful clean-tree evidence")
    group.add_argument("--verify-ssh", action="store_true", help="only verify local SSH evidence")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag):
        parser.error("tag must be vMAJOR.MINOR.PATCH")
    try:
        os.chdir(run("git", "rev-parse", "--show-toplevel"))
        if args.check_ssh:
            check_ssh()
            return 0
        if args.verify_ssh:
            if not ssh_evidence():
                print(f"error: real-SSH evidence is missing; run scripts/release-readiness.py {args.tag} --check-ssh", file=sys.stderr)
                return 1
            return 0
        report = readiness(args.tag)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"Release {args.tag} at {report['commit']}: " + ("ready for preflight" if report["ready"] else "not ready"))
            for item in report["missing"]:
                print(f"  {item['message']}\n    Next: {item['next_action']}")
            if report["ready"]:
                print("Next: " + report["next_action"])
        return 0 if report["ready"] else 1
    except (OSError, ValueError, subprocess.CalledProcessError, IndexError, AttributeError,
            ToolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
