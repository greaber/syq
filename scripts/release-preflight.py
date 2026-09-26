#!/usr/bin/env python3
"""Read-only validation of every locally auditable prerequisite before a tag is pushed.

Usage: scripts/release-preflight.py vMAJOR.MINOR.PATCH
"""
import base64
import binascii
from fnmatch import fnmatchcase
import glob
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from tooling import (JqError, awk_fields, captured, cargo_version, check_conclusion, comma_fields,
                     command, exit_on_failure, get, items, iterate, loads, require, text, truthy)

SCRIPTS = Path(os.path.abspath(__file__)).parent
CANONICAL_REPOSITORY = "greaber/syq"
HOMEBREW_REPOSITORY = "greaber/homebrew-tap"
RELEASE_ENVIRONMENT = "release"
REQUIRED_CHECKS = "rust,sdks,macos,linux-arm64,conformance"
CRATES_AUTH_ACTION = "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18"


class Die(Exception):
    pass


def die(message):
    raise Die(message)


def holds(predicate):
    """A `jq -e` condition: false when jq would fail."""
    try:
        return truthy(predicate())
    except JqError:
        return False


def quiet(*args):
    return subprocess.run(list(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def config(*args):
    completed = subprocess.run(["git", "config", *args], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
    return completed.stdout.rstrip("\n")


def pinned_identity(signers):
    """The key following each `syq-release` principal in an allowed-signers file."""
    lines = []
    for line in Path(signers).read_text().split("\n"):
        fields = re.split(r"[ \t]+", line.strip(" \t")) if line.strip(" \t") else []
        if fields and fields[0] == "syq-release":
            for index in range(1, len(fields) - 1):
                if fields[index].startswith("ssh-"):
                    lines.append(f"{fields[index]} {fields[index + 1]}")
                    break
    return "\n".join(lines)


def lock_version(path):
    """The syq package version in Cargo.lock, as the awk program extracted it."""
    name = ""
    for line in Path(path).read_text().split("\n"):
        if line == "[[package]]":
            name = ""
        if line == 'name = "syq"':
            name = "syq"
        if name == "syq" and line.startswith("version = "):
            if line.startswith('version = "'):
                line = line[len('version = "'):]
            return line[:-1] if line.endswith('"') else line
    return ""


def workflow_actions():
    actions = set()
    for path in glob.glob(".github/workflows/*.yml"):
        for line in Path(path).read_text().split("\n"):
            match = re.match(r'[ \t\n\r\f\v]*uses:[ \t\n\r\f\v]*([^ #]*).*', line)
            if match:
                actions.update(word for word in re.split(r"[ \t\n]+", match.group(1)) if word)
    return sorted(actions)


def listed(patterns, action):
    """jq's `.patterns_allowed | index($action) != null`."""
    if isinstance(patterns, list):
        return action in patterns
    if isinstance(patterns, str):
        return action in patterns
    if patterns is None:
        return False
    raise JqError(5, "cannot search this value")


def gh_api(*args):
    """The text of a GitHub API response; a failed request exits with its status."""
    return command("gh", "api", *args)


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} vMAJOR.MINOR.PATCH", file=sys.stderr)
        return 2
    tag = sys.argv[1]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        print(f"invalid syq release tag: {tag}", file=sys.stderr)
        return 2
    version = tag[1:]
    try:
        return preflight(tag, version)
    except Die as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def preflight(tag, version):
    for tool in ("git", "gh", "curl", "ssh-keygen"):
        if not shutil.which(tool):
            die(f"release preflight needs {tool}")

    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True)
    if root.returncode:
        die("run this from the syq repository")
    os.chdir(root.stdout.rstrip("\n"))
    if command("git", "status", "--porcelain").rstrip("\n"):
        die("working tree is not clean")
    sys.stdout.flush()
    command(sys.executable, "scripts/check-python-api-sync.py", stdout=None)

    origin_url = config("--get", "remote.origin.url").removesuffix(".git")
    if origin_url not in (f"git@github.com:{CANONICAL_REPOSITORY}",
                          f"ssh://git@github.com/{CANONICAL_REPOSITORY}",
                          f"https://github.com/{CANONICAL_REPOSITORY}"):
        die(f"origin is not the canonical {CANONICAL_REPOSITORY} repository")
    if (os.environ.get("GH_HOST") or "github.com") != "github.com":
        die("GH_HOST must be github.com")
    resolved = subprocess.run(["gh", "repo", "view", CANONICAL_REPOSITORY, "--json",
                               "nameWithOwner", "--jq", ".nameWithOwner"],
                              stdout=subprocess.PIPE, text=True)
    if resolved.stdout.rstrip("\n") != CANONICAL_REPOSITORY:
        die("gh resolved an unexpected repository")

    head = command("git", "rev-parse", "HEAD").rstrip("\n")
    tracking = subprocess.run(["git", "rev-parse", "refs/remotes/origin/master"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if tracking.returncode:
        die("origin/master is unavailable; fetch it first")
    tracking_master = tracking.stdout.rstrip("\n")
    listing = command("git", "ls-remote", "origin", "refs/heads/master")
    remote_master = awk_fields(listing.split("\n")[0], 1)
    if tracking_master != remote_master:
        die(f"origin/master is stale; fetch remote master ({remote_master})")
    if quiet("git", "merge-base", "--is-ancestor", head, remote_master).returncode:
        die(f"release candidate {head} is not merged into remote master ({remote_master})")

    notes = f".github/release-notes/{tag}.md"
    if not (os.path.exists(notes) and os.stat(notes).st_size > 0):
        die(f"release notes are missing: .github/release-notes/{tag}.md")
    command(str(SCRIPTS / "release-readiness.py"), tag, "--verify-ssh", stdout=None)

    package_version = cargo_version("Cargo.toml")
    if package_version != version:
        die(f"tag {tag} does not match Cargo.toml version {package_version}")
    locked_version = lock_version("Cargo.lock")
    if locked_version != version:
        die(f"Cargo.lock syq version {locked_version} does not match {version}")

    if quiet("git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}").returncode == 0:
        die(f"local tag {tag} already exists")
    remote_tags = subprocess.run(["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}",
                                  f"refs/tags/{tag}^{{}}"], stdout=subprocess.PIPE, text=True)
    if remote_tags.returncode:
        die(f"cannot inspect remote tag {tag}")
    if remote_tags.stdout.rstrip("\n"):
        die(f"remote tag {tag} already exists")

    ci = subprocess.run([str(SCRIPTS / "verify-release-ci.py"), "--json", CANONICAL_REPOSITORY,
                         head], stdout=subprocess.PIPE, text=True)
    if ci.returncode:
        print(ci.stdout.rstrip("\n"), file=sys.stderr)
        die("full release CI is not ready")
    certification = loads(ci.stdout)
    for workflow in iterate(get(certification, "workflows")):
        print(f"Full release CI: {text(get(workflow, 'workflow'))} certified at "
              f"{text(get(workflow, 'evidence_commit'))}", flush=True)
    for check_name in comma_fields(REQUIRED_CHECKS):
        workflow = "rsync-compat.yml" if check_name == "conformance" else "ci.yml"
        evidence = [get(item, "evidence_commit") for item in iterate(get(certification, "workflows"))
                    if get(item, "workflow") == workflow]
        if not evidence:
            raise JqError(4, f"no certification for {workflow}")
        checked_commit = captured("\n".join(text(value) for value in evidence))
        require(evidence[-1])
        checks = loads(gh_api(f"repos/{CANONICAL_REPOSITORY}/commits/{checked_commit}"
                        "/check-runs?filter=latest&per_page=100"))
        conclusion = check_conclusion(checks, check_name)
        if conclusion != "success":
            die(f"required check {check_name} is {conclusion} on {checked_commit}")

    signing_key = config("--get", "user.signingkey").removeprefix("key::")
    signing_identity = awk_fields(signing_key, 1, 2)
    if config("--get", "gpg.format") != "ssh":
        die("gpg.format must be ssh for release tag signing")
    if config("--bool", "--get", "tag.gpgsign") != "true":
        die("tag.gpgsign must be enabled")
    if not fnmatchcase(signing_identity, "ssh-* *"):
        die("user.signingkey is not an inline SSH public key")
    fingerprint = subprocess.run(["ssh-keygen", "-lf", "/dev/stdin"], input=signing_identity + "\n",
                                 stdout=subprocess.PIPE, text=True)
    if fingerprint.returncode:
        die("cannot fingerprint user.signingkey")
    signing_fingerprint = awk_fields(fingerprint.stdout.rstrip("\n"), 2)
    if signing_identity != pinned_identity(SCRIPTS / "release-tag-signers"):
        die(f"tag signing key {signing_fingerprint} is not the pinned maintainer key")
    github_login = command("gh", "api", "user", "--jq", ".login").rstrip("\n")
    github_signing_keys = gh_api(f"users/{github_login}/ssh_signing_keys?per_page=100")

    def registered():
        for key in iterate(loads(github_signing_keys)):
            value = get(key, "key")
            if not isinstance(value, str):
                raise JqError(5, "cannot split a non-string key")
            if " ".join(value.split(" ")[0:2]) == signing_identity:
                return True
        return False

    if not holds(registered):
        die(f"tag signing key {signing_fingerprint} is not registered as a GitHub SSH signing key")

    permissions = gh_api(f"repos/{CANONICAL_REPOSITORY}/actions/permissions")
    if not holds(lambda: get(loads(permissions), "enabled") is True
                 and get(loads(permissions), "allowed_actions") == "selected"
                 and get(loads(permissions), "sha_pinning_required") is True):
        die("GitHub Actions must be enabled with selected actions and SHA pinning required")
    selected_actions = gh_api(f"repos/{CANONICAL_REPOSITORY}/actions/permissions/selected-actions")
    if not holds(lambda: get(loads(selected_actions), "github_owned_allowed") is True
                 and get(loads(selected_actions), "verified_allowed") is False):
        die("unexpected GitHub selected-actions policy")
    for action in workflow_actions():
        if action.startswith("./"):
            continue
        reference = action.rsplit("@", 1)[-1]
        if not re.fullmatch(r"[0-9a-f]{40}", reference):
            die(f"workflow action is not pinned to a full SHA: {action}")
        if not action.startswith("actions/") and not holds(
                lambda: listed(get(loads(selected_actions), "patterns_allowed"), action)):
            die(f"workflow action is not selected in repository policy: {action}")
    if not holds(lambda: listed(get(loads(selected_actions), "patterns_allowed"),
                                CRATES_AUTH_ACTION)):
        die(f"crates.io authentication action is not selected: {CRATES_AUTH_ACTION}")

    environment = gh_api(f"repos/{CANONICAL_REPOSITORY}/environments/{RELEASE_ENVIRONMENT}")
    if not holds(lambda: get(loads(environment), "name") == "release" and any(
            get(rule, "type") == "required_reviewers"
            for rule in items(get(loads(environment), "protection_rules")))):
        die("release environment is missing its required-reviewer protection")
    policies = gh_api(f"repos/{CANONICAL_REPOSITORY}/environments/{RELEASE_ENVIRONMENT}"
                      "/deployment-branch-policies")
    if not holds(lambda: any(get(policy, "type") == "tag" and get(policy, "name") == "v*"
                             for policy in items(get(loads(policies), "branch_policies")))):
        die("release environment is not restricted to v* tags")
    secrets = command("gh", "secret", "list", "--repo", CANONICAL_REPOSITORY, "--env",
                           RELEASE_ENVIRONMENT, "--json", "name")
    for secret in ("SYQ_RELEASE_SIGNING_KEY_PEM_B64", "HOMEBREW_TAP_DEPLOY_KEY"):
        if not holds(lambda: any(get(item, "name") == secret for item in iterate(loads(secrets)))):
            die(f"release environment secret is missing: {secret}")
    variables = command("gh", "variable", "list", "--repo", CANONICAL_REPOSITORY,
                             "--json", "name,value")
    try:
        values = [get(item, "value") for item in iterate(loads(variables))
                  if get(item, "name") == "SYQ_RELEASE_PUBLIC_KEY"]
        if not values or not truthy(values[-1]):
            raise JqError(1)
    except JqError:
        die("repository variable is missing: SYQ_RELEASE_PUBLIC_KEY")
    public_key = captured("\n".join(text(value) for value in values))
    try:
        key_length = len(base64.b64decode(public_key, validate=True))
    except (binascii.Error, ValueError):
        key_length = -1
    if key_length != 32:
        die("SYQ_RELEASE_PUBLIC_KEY is not a base64-encoded 32-byte key")
    if public_key != Path("src/release-public-key.txt").read_text().rstrip("\n"):
        die("SYQ_RELEASE_PUBLIC_KEY differs from src/release-public-key.txt; update the "
            "source-build trust anchor when rotating keys")

    releases = gh_api("--paginate", "--slurp", f"repos/{CANONICAL_REPOSITORY}/releases?per_page=100")
    if not holds(lambda: not any(get(release, "tag_name") == tag
                                 for release in iterate(flatten(loads(releases))))):
        die(f"GitHub release {tag} already exists")
    crates = command(
        "curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
        "--proto-redir", "=https", "--user-agent",
        "syq-release-preflight (https://github.com/greaber/syq)",
        "https://crates.io/api/v1/crates/syq")
    if not holds(lambda: not any(get(item, "num") == version
                                 for item in items(get(loads(crates), "versions")))):
        die(f"syq {version} is already published on crates.io")
    formula_json = loads(gh_api(f"repos/{HOMEBREW_REPOSITORY}/contents/Formula/syq.rb"))
    content = captured(require(get(formula_json, "content")))
    try:
        formula = base64.b64decode(content.replace("\n", ""))
    except (binascii.Error, ValueError):
        print("error: the Homebrew formula is not valid base64", file=sys.stderr)
        return 1
    if f"/{tag}/".encode() in formula:
        die(f"Homebrew tap already references {tag}")

    print(f"Release preflight passed for {tag} at {head}.")
    print(f"Tag signing key: {signing_fingerprint}")
    print(f"Required checks: {REQUIRED_CHECKS}")
    print("No existing GitHub release, crates.io version, or Homebrew formula was found.")
    return 0


def flatten(value):
    """jq's `flatten`."""
    if not isinstance(value, list):
        raise JqError(5, "cannot flatten a non-array")
    result = []
    for item in value:
        result.extend(flatten(item) if isinstance(item, list) else [item])
    return result


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
