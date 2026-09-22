#!/usr/bin/env python3
"""Report missing release preparation and CI; record reusable local SSH validation.

Exit 0: ready for preflight (or the requested SSH check passed).
Exit 1: preparation/validation is incomplete. Exit 2: inspection/tooling failed.
No tags, publications, PRs, or CI runs are created. --check-ssh runs the local lab.
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

from release_test_inputs import candidates, fingerprint

SCRIPTS = Path(__file__).resolve().parent
REPOSITORY = "greaber/syq"


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def clean_candidate():
    if run("git", "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("working tree is not clean; commit preparation before recording SSH evidence")
    return run("git", "rev-parse", "HEAD"), run("git", "rev-parse", "HEAD^{tree}")


def receipt_path(tree):
    common = Path(run("git", "rev-parse", "--git-common-dir")).resolve()
    return common / "syq-release" / "real-ssh" / f"{tree}.json"


def inputs_receipt_path(commit):
    common = Path(run("git", "rev-parse", "--git-common-dir")).resolve()
    return common / "syq-release" / "real-ssh-inputs" / f"{fingerprint(commit, native=True)}.json"


def ssh_evidence():
    commit, tree = clean_candidate()
    path = inputs_receipt_path(commit)
    if not path.is_file():
        # Existing full-tree receipts remain usable if their tested inputs match.
        for ancestor in candidates(commit, native=True):
            path = receipt_path(run("git", "rev-parse", ancestor + "^{tree}"))
            if path.is_file():
                break
        else:
            return None
    receipt = json.loads(path.read_text())
    checked = receipt.get("commit", "")
    if (receipt.get("schema") not in (1, 2) or receipt.get("profile") != "default"
            or not re.fullmatch(r"[0-9a-f]{40}", checked)
            or run("git", "rev-parse", checked + "^{tree}") != receipt.get("tree")
            or fingerprint(checked, native=True) != fingerprint(commit, native=True)):
        raise ValueError(f"invalid real-SSH evidence: {path}")
    if receipt.get("result") != "success":
        return None
    return {**receipt, "candidate": commit, "path": str(path)}


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
    subprocess.run([str(SCRIPTS / "test-real-ssh.sh")], check=True, stdout=sys.stderr)
    if clean_candidate() != (commit, tree):
        raise ValueError("checkout changed during real-SSH validation; no evidence recorded")
    receipt.update(result="success", completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    os.replace(output.name, path)
    print(f"Real-SSH evidence recorded for {commit} (default profile, tree {tree}).", file=sys.stderr)


def readiness(tag):
    commit = run("git", "rev-parse", "HEAD")
    issues = []
    def missing(message, action):
        issues.append({"message": message, "next_action": action})

    remote = run("git", "config", "--get", "remote.origin.url").removesuffix(".git")
    if remote not in (f"git@github.com:{REPOSITORY}", f"ssh://git@github.com/{REPOSITORY}",
                       f"https://github.com/{REPOSITORY}"):
        raise ValueError("origin is not the canonical greaber/syq repository")
    local_tag = subprocess.run(["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"])
    remote_tag = run("git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}")
    if local_tag.returncode == 0 or remote_tag:
        missing("the requested tag already exists; inspect or resume it, do not choose another version",
                f"scripts/release-status.sh {tag}")
        return {"schema": 1, "tag": tag, "commit": commit, "remote_master": None,
                "ready": False, "ssh": None, "ci": None, "missing": issues,
                "next_action": issues[0]["next_action"]}
    master = run("git", "ls-remote", "origin", "refs/heads/master").split()[0]
    tracking = subprocess.run(["git", "rev-parse", "--verify", "refs/remotes/origin/master"],
                              capture_output=True, text=True)
    if tracking.returncode or tracking.stdout.strip() != master:
        missing("origin/master is stale or missing", "git fetch origin master")
    elif subprocess.run(["git", "merge-base", "--is-ancestor", commit, master]).returncode:
        missing(f"candidate is not merged into remote master {master}",
                "Merge preparation through a PR, then use a clean checkout of the chosen release commit.")
    if run("git", "status", "--porcelain", "--untracked-files=all"):
        missing("working tree is dirty", "Commit the release preparation on its task branch.")
    version = re.search(r'^version = "([^"]+)"', Path("Cargo.toml").read_text(), re.M).group(1)
    lock = re.search(r'\[\[package\]\]\nname = "syq"\nversion = "([^"]+)"', Path("Cargo.lock").read_text())
    if tag != f"v{version}" or not lock or lock.group(1) != version:
        missing("Cargo version/lockfile does not match the requested tag", "Update Cargo metadata and refresh the lockfile without upgrading dependencies.")
    notes = Path(f".github/release-notes/{tag}.md")
    if not notes.is_file() or not notes.read_text().strip():
        missing("curated release notes are missing", f"Write {notes} and merge them with the version change.")
    api = subprocess.run([sys.executable, str(SCRIPTS / "check-python-api-sync.py")],
                         capture_output=True, text=True)
    if api.returncode:
        missing("Python native API synchronization failed: " + (api.stderr or api.stdout).strip(),
                "Resolve native API follow-ups before release.")
    try:
        evidence = ssh_evidence()
    except ValueError as error:
        evidence = None
        missing(str(error), "Commit preparation, then rerun readiness.")
    if not evidence:
        missing("default real-SSH validation is missing for these test inputs",
                f"scripts/release-readiness.py {tag} --check-ssh")
    ci = subprocess.run([str(SCRIPTS / "verify-release-ci.sh"), "--json", REPOSITORY, commit],
                        capture_output=True, text=True)
    if ci.returncode not in (0, 1):
        raise ValueError("CI inspection failed: " + ci.stderr.strip())
    certification = json.loads(ci.stdout)
    for workflow in certification["workflows"]:
        if workflow["state"] != "ready":
            action = workflow["next_action"]
            if commit != master and workflow["state"] == "dispatch":
                action = ("This candidate lacks full-suite evidence; dispatching on current master would "
                          "validate a different commit. Inspect existing candidate runs or deliberately "
                          "select a newer merged candidate before dispatching.")
            missing(workflow["message"], action)
    return {"schema": 1, "tag": tag, "commit": commit, "remote_master": master,
            "ready": not issues, "ssh": evidence, "ci": certification, "missing": issues,
            "next_action": issues[0]["next_action"] if issues else f"scripts/release-preflight.sh {tag}"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("--json", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check-ssh", action="store_true", help="run the default local lab and record successful clean-tree evidence")
    group.add_argument("--verify-ssh", action="store_true", help="only verify local SSH evidence (used by preflight)")
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
    except (OSError, ValueError, subprocess.CalledProcessError, IndexError, AttributeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
