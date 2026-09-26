#!/usr/bin/env python3
"""Read-only validation of every locally auditable prerequisite before a tag is pushed.

Usage: scripts/release-preflight.py vMAJOR.MINOR.PATCH
"""
import base64
import binascii
import glob
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

from tooling import ToolError, cargo_version, check_conclusion, json_output, output, report_errors

SCRIPTS = Path(os.path.abspath(__file__)).parent
CANONICAL_REPOSITORY = "greaber/syq"
HOMEBREW_REPOSITORY = "greaber/homebrew-tap"
RELEASE_ENVIRONMENT = "release"
REQUIRED_CHECKS = "rust,sdks,macos,linux-arm64,conformance"
CRATES_AUTH_ACTION = "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18"


def succeeds(*args):
    return subprocess.run(list(args), stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def git_config(*args):
    completed = subprocess.run(["git", "config", *args], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
    return completed.stdout.strip()


def gh_api(*args):
    return json_output("gh", "api", *args)


def require(condition, message):
    if not condition:
        raise ToolError(message)


def lock_version(path):
    """The syq version recorded in Cargo.lock."""
    try:
        with open(path, "rb") as source:
            packages = tomllib.load(source).get("package", [])
    except (OSError, ValueError) as error:
        raise ToolError(f"cannot read {path}: {error}") from None
    versions = [package.get("version") for package in packages if package.get("name") == "syq"]
    return versions[0] if versions else None


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


def check_repository(tag):
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True)
    require(root.returncode == 0, "run this from the syq repository")
    os.chdir(root.stdout.strip())
    require(not output("git", "status", "--porcelain").strip(), "working tree is not clean")
    sys.stdout.flush()
    output(sys.executable, "scripts/check-python-api-sync.py", stdout=None)

    origin_url = git_config("--get", "remote.origin.url").removesuffix(".git")
    require(origin_url in (f"git@github.com:{CANONICAL_REPOSITORY}",
                           f"ssh://git@github.com/{CANONICAL_REPOSITORY}",
                           f"https://github.com/{CANONICAL_REPOSITORY}"),
            f"origin is not the canonical {CANONICAL_REPOSITORY} repository")
    require(os.environ.get("GH_HOST", "github.com") == "github.com", "GH_HOST must be github.com")
    resolved = subprocess.run(["gh", "repo", "view", CANONICAL_REPOSITORY, "--json",
                               "nameWithOwner", "--jq", ".nameWithOwner"],
                              stdout=subprocess.PIPE, text=True)
    require(resolved.stdout.strip() == CANONICAL_REPOSITORY, "gh resolved an unexpected repository")

    head = output("git", "rev-parse", "HEAD").strip()
    tracking = subprocess.run(["git", "rev-parse", "refs/remotes/origin/master"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    require(tracking.returncode == 0, "origin/master is unavailable; fetch it first")
    listing = output("git", "ls-remote", "origin", "refs/heads/master").split()
    remote_master = listing[0] if listing else ""
    require(tracking.stdout.strip() == remote_master,
            f"origin/master is stale; fetch remote master ({remote_master})")
    require(succeeds("git", "merge-base", "--is-ancestor", head, remote_master),
            f"release candidate {head} is not merged into remote master ({remote_master})")

    notes = Path(f".github/release-notes/{tag}.md")
    require(notes.is_file() and notes.stat().st_size > 0, f"release notes are missing: {notes}")
    output(str(SCRIPTS / "release-readiness.py"), tag, "--verify-ssh", stdout=None)

    version = tag.removeprefix("v")
    package_version = cargo_version("Cargo.toml")
    require(package_version == version, f"tag {tag} does not match Cargo.toml version {package_version}")
    locked_version = lock_version("Cargo.lock")
    require(locked_version == version,
            f"Cargo.lock syq version {locked_version} does not match {version}")

    require(not succeeds("git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"),
            f"local tag {tag} already exists")
    remote_tags = subprocess.run(["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}",
                                  f"refs/tags/{tag}^{{}}"], stdout=subprocess.PIPE, text=True)
    require(remote_tags.returncode == 0, f"cannot inspect remote tag {tag}")
    require(not remote_tags.stdout.strip(), f"remote tag {tag} already exists")
    return head


def check_ci(head):
    ci = subprocess.run([str(SCRIPTS / "verify-release-ci.py"), "--json", CANONICAL_REPOSITORY,
                         head], stdout=subprocess.PIPE, text=True)
    if ci.returncode:
        print(ci.stdout.strip(), file=sys.stderr)
        raise ToolError("full release CI is not ready")
    evidence = {}
    for workflow in json.loads(ci.stdout)["workflows"]:
        print(f"Full release CI: {workflow['workflow']} certified at {workflow['evidence_commit']}",
              flush=True)
        evidence[workflow["workflow"]] = workflow["evidence_commit"]
    for check_name in REQUIRED_CHECKS.split(","):
        checked_commit = evidence["rsync-compat.yml" if check_name == "conformance" else "ci.yml"]
        checks = gh_api(f"repos/{CANONICAL_REPOSITORY}/commits/{checked_commit}"
                        "/check-runs?filter=latest&per_page=100")
        conclusion = check_conclusion(checks, check_name)
        require(conclusion == "success",
                f"required check {check_name} is {conclusion} on {checked_commit}")


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
    head = check_repository(tag)
    try:
        check_ci(head)
        signing_fingerprint = check_signing_key()
        check_repository_policy()
        check_unpublished(tag)
    except (AttributeError, KeyError, TypeError) as error:
        raise ToolError(f"unexpected GitHub or registry response ({error!r})") from None
    print(f"Release preflight passed for {tag} at {head}.")
    print(f"Tag signing key: {signing_fingerprint}")
    print(f"Required checks: {REQUIRED_CHECKS}")
    print("No existing GitHub release, crates.io version, or Homebrew formula was found.")
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
