"""Release preconditions shared by release-readiness.py, release-preflight.py,
and verify-release-tag.py.

Readiness reports every unmet precondition; preflight stops at the first one
and then adds its GitHub-only checks. Both run the same list in the same order.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from release_test_inputs import candidates, fingerprint
from tooling import ToolError, cargo_version, check_conclusion, json_output, output

SCRIPTS = Path(os.path.abspath(__file__)).parent
REPOSITORY = "greaber/syq"
# The check runs a native release requires beyond the full-suite certificates.
# release.yml passes the same list to verify-release-tag.py.
REQUIRED_CHECKS = ("rust", "sdks", "macos", "linux-arm64", "conformance")


def run(*args):
    return output(*args).strip()


def succeeds(*args):
    return subprocess.run(list(args), stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def release_ci(repository, commit):
    """The `verify-release-ci.py --json` report for a commit; its `ready` says
    whether every full-suite workflow certifies it."""
    sys.stdout.flush()
    ci = subprocess.run([str(SCRIPTS / "verify-release-ci.py"), "--json", repository, commit],
                        stdout=subprocess.PIPE, text=True)
    if ci.returncode not in (0, 1):
        raise ToolError(f"release CI inspection failed with exit status {ci.returncode}")
    return json.loads(ci.stdout)


def failed_checks(repository, commit, checks, certification=None):
    """Yield (check, conclusion, commit) for each named check run that did not
    succeed. A check is read at the commit holding its workflow's release
    evidence (conformance from rsync-compat.yml, the rest from ci.yml), or at
    `commit` itself without a certification report."""
    evidence = {workflow["workflow"]: workflow["evidence_commit"]
                for workflow in (certification or {}).get("workflows", [])}
    check_runs = {}
    for check in checks:
        checked = evidence.get("rsync-compat.yml" if check == "conformance" else "ci.yml", commit)
        if checked not in check_runs:
            check_runs[checked] = json_output("gh", "api", f"repos/{repository}/commits/{checked}"
                                              "/check-runs?filter=latest&per_page=100")
        conclusion = check_conclusion(check_runs[checked], check)
        if conclusion != "success":
            yield check, conclusion, checked


def lock_version(path):
    """The syq version recorded in Cargo.lock."""
    try:
        with open(path, "rb") as source:
            packages = tomllib.load(source).get("package", [])
    except (OSError, ValueError) as error:
        raise ToolError(f"cannot read {path}: {error}") from None
    versions = [package.get("version") for package in packages if package.get("name") == "syq"]
    return versions[0] if versions else None


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


class ReleaseCheck:
    """The release preconditions for a tag at the current checkout's HEAD.
    `issues()` fills in what it inspected as it goes: `commit`,
    `remote_master`, `ssh`, and the CI `certification` report."""

    def __init__(self, tag):
        self.tag = tag
        self.commit = run("git", "rev-parse", "HEAD")
        self.remote_master = self.ssh = self.certification = None

    def issues(self, after_ci=None):
        """Yield {message, next_action} for every unmet precondition, in order.
        An existing tag ends the list: that release is resumed, not prepared.
        `after_ci(certification)` may yield more issues once the CI report is
        known, before the SSH and CI issues."""
        tag, commit = self.tag, self.commit
        def issue(message, action):
            return {"message": message, "next_action": action}

        remote = run("git", "config", "--get", "remote.origin.url").removesuffix(".git")
        if remote not in (f"git@github.com:{REPOSITORY}", f"ssh://git@github.com/{REPOSITORY}",
                          f"https://github.com/{REPOSITORY}"):
            raise ToolError(f"origin is not the canonical {REPOSITORY} repository")
        if os.environ.get("GH_HOST", "github.com") != "github.com":
            raise ToolError("GH_HOST must be github.com")
        resolved = subprocess.run(["gh", "repo", "view", REPOSITORY, "--json", "nameWithOwner",
                                   "--jq", ".nameWithOwner"], stdout=subprocess.PIPE, text=True)
        if resolved.stdout.strip() != REPOSITORY:
            raise ToolError("gh resolved an unexpected repository")

        remote_tag = run("git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}",
                         f"refs/tags/{tag}^{{}}")
        if succeeds("git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}") or remote_tag:
            yield issue(f"tag {tag} already exists; inspect or resume it, do not choose another "
                        "version", f"scripts/release-status.py {tag}")
            return

        listing = run("git", "ls-remote", "origin", "refs/heads/master").split()
        if not listing:
            raise ToolError("remote master is unavailable")
        master = self.remote_master = listing[0]
        tracking = subprocess.run(["git", "rev-parse", "--verify", "refs/remotes/origin/master"],
                                  capture_output=True, text=True)
        if tracking.returncode or tracking.stdout.strip() != master:
            yield issue(f"origin/master is stale or missing; remote master is {master}",
                        "git fetch origin master")
        elif not succeeds("git", "merge-base", "--is-ancestor", commit, master):
            yield issue(f"release candidate {commit} is not merged into remote master {master}",
                        "Merge preparation through a PR, then use a clean checkout of the chosen "
                        "release commit.")
        if run("git", "status", "--porcelain", "--untracked-files=all"):
            yield issue("working tree is not clean",
                        "Commit the release preparation on its task branch.")
        version = tag.removeprefix("v")
        package_version, locked_version = cargo_version("Cargo.toml"), lock_version("Cargo.lock")
        if package_version != version or locked_version != version:
            yield issue(f"Cargo.toml version {package_version} and Cargo.lock syq version "
                        f"{locked_version} do not both match tag {tag}",
                        "Update Cargo metadata and refresh the lockfile without upgrading "
                        "dependencies.")
        notes = Path(f".github/release-notes/{tag}.md")
        if not notes.is_file() or not notes.read_text().strip():
            yield issue(f"curated release notes are missing: {notes}",
                        f"Write {notes} and merge them with the version change.")
        api = subprocess.run([sys.executable, str(SCRIPTS / "check-python-api-sync.py")],
                             capture_output=True, text=True)
        if api.returncode:
            yield issue("Python native API synchronization failed: "
                        + (api.stderr or api.stdout).strip(),
                        "Resolve native API follow-ups before release.")

        certification = self.certification = release_ci(REPOSITORY, commit)
        if after_ci:
            yield from after_ci(certification)
        try:
            self.ssh = ssh_evidence()
        except ValueError as error:
            yield issue(str(error), "Commit preparation, then rerun readiness.")
        except subprocess.CalledProcessError as error:
            raise ToolError(f"cannot compare release test inputs: {error}") from None
        if not self.ssh:
            yield issue("default real-SSH evidence is missing for these test inputs",
                        f"scripts/release-readiness.py {tag} --check-ssh")
        for workflow in certification["workflows"]:
            if workflow["state"] != "ready":
                action = workflow["next_action"]
                if commit != master and workflow["state"] == "dispatch":
                    action = ("This candidate lacks full-suite evidence; dispatching on current "
                              "master would validate a different commit. Inspect existing "
                              "candidate runs or deliberately select a newer merged candidate "
                              "before dispatching.")
                yield issue(workflow["message"], action)
        if certification["ready"]:
            for check, conclusion, checked in failed_checks(REPOSITORY, commit, REQUIRED_CHECKS,
                                                            certification):
                yield issue(f"required check {check} is {conclusion} on certified commit "
                            f"{checked}",
                            f"Inspect the {check} check on {checked}; the release workflow "
                            "requires it to succeed.")
