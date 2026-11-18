#!/usr/bin/env python3
"""Read-only validation of every locally auditable prerequisite before a tag is pushed.

Usage: scripts/release-preflight.py vMAJOR.MINOR.PATCH
"""
import base64
import binascii
import glob
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from release_checks import REPOSITORY as CANONICAL_REPOSITORY, REQUIRED_CHECKS, ReleaseCheck
from tooling import ToolError, json_output, output, report_errors

SCRIPTS = Path(os.path.abspath(__file__)).parent
HOMEBREW_REPOSITORY = "greaber/homebrew-tap"
RELEASE_ENVIRONMENT = "release"
CRATES_AUTH_ACTION = "rust-lang/crates-io-auth-action@3268eb413133e2960fa4ae0e963ca76380c54cd9"


def git_config(*args):
    completed = subprocess.run(["git", "config", *args], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
    return completed.stdout.strip()


def gh_api(*args):
    return json_output("gh", "api", *args)


def require(condition, message):
    if not condition:
        raise ToolError(message)


def pinned_identity(signers):
    """The `TYPE KEY` of the syq-release principal in an allowed-signers file,
    after any options (which can contain quoted spaces)."""
    for line in Path(signers).read_text().splitlines():
        fields = line.split()
        if fields[:1] == ["syq-release"]:
            for index in range(1, len(fields) - 1):
                if fields[index].startswith("ssh-"):
                    return f"{fields[index]} {fields[index + 1]}"
    return None


def workflow_actions():
    actions = set()
    for path in glob.glob(".github/workflows/*.yml"):
        for line in Path(path).read_text().splitlines():
            match = re.match(r"\s*uses:\s*([^\s#]+)", line)
            if match:
                actions.add(match.group(1))
    return sorted(actions)


def check_release(tag):
    """Fail on the first release precondition that readiness would report."""
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True)
    require(root.returncode == 0, "run this from the syq repository")
    os.chdir(root.stdout.strip())
    check = ReleaseCheck(tag)
    for issue in check.issues():
        raise ToolError(issue["message"])
    for workflow in check.certification["workflows"]:
        print(f"Full release CI: {workflow['workflow']} certified at {workflow['evidence_commit']}",
              flush=True)
    return check.commit


def check_signing_key():
    signing_identity = " ".join(
        git_config("--get", "user.signingkey").removeprefix("key::").split()[:2])
    require(git_config("--get", "gpg.format") == "ssh",
            "gpg.format must be ssh for release tag signing")
    require(git_config("--bool", "--get", "tag.gpgsign") == "true", "tag.gpgsign must be enabled")
    require(re.fullmatch(r"ssh-\S+ \S+", signing_identity),
            "user.signingkey is not an inline SSH public key")
    fingerprint = subprocess.run(["ssh-keygen", "-lf", "/dev/stdin"], input=signing_identity + "\n",
                                 stdout=subprocess.PIPE, text=True)
    require(fingerprint.returncode == 0, "cannot fingerprint user.signingkey")
    signing_fingerprint = fingerprint.stdout.split()[1]
    require(signing_identity == pinned_identity(SCRIPTS / "release-tag-signers"),
            f"tag signing key {signing_fingerprint} is not the pinned maintainer key")
    login = output("gh", "api", "user", "--jq", ".login").strip()
    registered = gh_api(f"users/{login}/ssh_signing_keys?per_page=100")
    require(any(" ".join(str(key.get("key", "")).split(" ")[:2]) == signing_identity
                for key in registered),
            f"tag signing key {signing_fingerprint} is not registered as a GitHub SSH signing key")
    return signing_fingerprint


def check_repository_policy():
    permissions = gh_api(f"repos/{CANONICAL_REPOSITORY}/actions/permissions")
    require(permissions.get("enabled") is True and permissions.get("allowed_actions") == "selected"
            and permissions.get("sha_pinning_required") is True,
            "GitHub Actions must be enabled with selected actions and SHA pinning required")
    selected = gh_api(f"repos/{CANONICAL_REPOSITORY}/actions/permissions/selected-actions")
    require(selected.get("github_owned_allowed") is True and selected.get("verified_allowed") is False,
            "unexpected GitHub selected-actions policy")
    allowed = selected.get("patterns_allowed") or []
    for action in workflow_actions():
        if action.startswith("./"):
            continue
        require(re.fullmatch(r"[0-9a-f]{40}", action.rsplit("@", 1)[-1]),
                f"workflow action is not pinned to a full SHA: {action}")
        require(action.startswith("actions/") or action in allowed,
                f"workflow action is not selected in repository policy: {action}")
    require(CRATES_AUTH_ACTION in allowed,
            f"crates.io authentication action is not selected: {CRATES_AUTH_ACTION}")

    environment = gh_api(f"repos/{CANONICAL_REPOSITORY}/environments/{RELEASE_ENVIRONMENT}")
    require(environment.get("name") == "release"
            and any(rule.get("type") == "required_reviewers"
                    for rule in environment.get("protection_rules") or []),
            "release environment is missing its required-reviewer protection")
    policies = gh_api(f"repos/{CANONICAL_REPOSITORY}/environments/{RELEASE_ENVIRONMENT}"
                      "/deployment-branch-policies")
    require(any(policy.get("type") == "tag" and policy.get("name") == "v*"
                for policy in policies.get("branch_policies") or []),
            "release environment is not restricted to v* tags")
    secrets = {secret.get("name") for secret in json_output(
        "gh", "secret", "list", "--repo", CANONICAL_REPOSITORY, "--env", RELEASE_ENVIRONMENT,
        "--json", "name")}
    for secret in ("SYQ_RELEASE_SIGNING_KEY_PEM_B64", "HOMEBREW_TAP_DEPLOY_KEY"):
        require(secret in secrets, f"release environment secret is missing: {secret}")
    variables = {variable.get("name"): variable.get("value") for variable in json_output(
        "gh", "variable", "list", "--repo", CANONICAL_REPOSITORY, "--json", "name,value")}
    public_key = variables.get("SYQ_RELEASE_PUBLIC_KEY")
    require(public_key, "repository variable is missing: SYQ_RELEASE_PUBLIC_KEY")
    try:
        key_length = len(base64.b64decode(public_key, validate=True))
    except (binascii.Error, ValueError):
        key_length = None
    require(key_length == 32, "SYQ_RELEASE_PUBLIC_KEY is not a base64-encoded 32-byte key")
    require(public_key == Path("src/release-public-key.txt").read_text().strip(),
            "SYQ_RELEASE_PUBLIC_KEY differs from src/release-public-key.txt; update the "
            "source-build trust anchor when rotating keys")


def check_unpublished(tag):
    version = tag.removeprefix("v")
    pages = gh_api("--paginate", "--slurp", f"repos/{CANONICAL_REPOSITORY}/releases?per_page=100")
    require(not any(release.get("tag_name") == tag for page in pages for release in page),
            f"GitHub release {tag} already exists")
    crates = json_output(
        "curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
        "--proto-redir", "=https", "--user-agent",
        "syq-release-preflight (https://github.com/greaber/syq)",
        "https://crates.io/api/v1/crates/syq")
    require(not any(item.get("num") == version for item in crates.get("versions") or []),
            f"syq {version} is already published on crates.io")
    formula = gh_api(f"repos/{HOMEBREW_REPOSITORY}/contents/Formula/syq.rb")
    try:
        content = base64.b64decode(formula["content"].replace("\n", ""))
    except (KeyError, AttributeError, binascii.Error, ValueError):
        raise ToolError("cannot read the Homebrew formula") from None
    require(f"/{tag}/".encode() not in content, f"Homebrew tap already references {tag}")


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} vMAJOR.MINOR.PATCH", file=sys.stderr)
        return 2
    tag = sys.argv[1]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        print(f"invalid syq release tag: {tag}", file=sys.stderr)
        return 2
    for tool in ("git", "gh", "curl", "ssh-keygen"):
        require(shutil.which(tool), f"release preflight needs {tool}")
    try:
        head = check_release(tag)
        signing_fingerprint = check_signing_key()
        check_repository_policy()
        check_unpublished(tag)
    except (AttributeError, KeyError, TypeError) as error:
        raise ToolError(f"unexpected GitHub or registry response ({error!r})") from None
    print(f"Release preflight passed for {tag} at {head}.")
    print(f"Tag signing key: {signing_fingerprint}")
    print(f"Required checks: {','.join(REQUIRED_CHECKS)}")
    print("No existing GitHub release, crates.io version, or Homebrew formula was found.")
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
