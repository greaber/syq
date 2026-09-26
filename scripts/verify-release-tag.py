#!/usr/bin/env python3
"""Verify a release tag before the release workflow publishes anything.

Usage: scripts/verify-release-tag.py OWNER/REPOSITORY TAG EXPECTED_COMMIT
       PROTECTED_BRANCH REQUIRED_CHECKS

Require a maintainer-signed, GitHub-verified annotated tag that directly names
the workflow commit, is reachable from the protected branch, and has every
named CI check concluded successfully. Native releases may reuse ancestor
evidence only for unchanged test inputs; SDK checks remain exact.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from tooling import ToolError, check_conclusion, json_output, report_errors

SCRIPTS = Path(os.path.abspath(__file__)).parent


def field(value, *path):
    """A string at `path` in a GitHub API object."""
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    if not isinstance(value, str) or not value:
        raise ToolError(f"GitHub response has no {'.'.join(path)}")
    return value


def verify_signature(tag, tag_object):
    """Check the tag's signed payload against the pinned maintainer key."""
    verification = tag_object.get("verification") or {}
    for name in ("signature", "payload"):
        if not isinstance(verification.get(name), str) or not verification[name]:
            raise ToolError(f"release tag {tag} has a missing, empty, or invalid verification {name}")
    with tempfile.TemporaryDirectory(prefix="syq-tag-verification.") as work:
        signature = Path(work, "signature")
        signature.write_text(verification["signature"])
        signed = subprocess.run(["ssh-keygen", "-Y", "verify", "-f",
                                 str(SCRIPTS / "release-tag-signers"), "-I", "syq-release",
                                 "-n", "git", "-s", str(signature)],
                                input=verification["payload"].encode())
    if signed.returncode:
        raise ToolError(f"release tag {tag} was not signed by the pinned maintainer key")


def main():
    if len(sys.argv) != 6:
        print(f"usage: {sys.argv[0]} OWNER/REPOSITORY TAG EXPECTED_COMMIT PROTECTED_BRANCH "
              "REQUIRED_CHECKS", file=sys.stderr)
        print("REQUIRED_CHECKS is a comma-separated list of check run names", file=sys.stderr)
        return 2
    repository, tag, expected_commit, protected_branch, required_checks = sys.argv[1:]
    for valid, message in [
            ("/" in repository, f"invalid GitHub repository: {repository}"),
            (re.fullmatch(r"[A-Za-z0-9._-]+", tag), f"unsafe release tag: {tag}"),
            (re.fullmatch(r"[0-9a-f]+", expected_commit), f"invalid expected commit: {expected_commit}"),
            (re.fullmatch(r"[A-Za-z0-9._/-]+", protected_branch),
             f"unsafe protected branch: {protected_branch}"),
            (re.fullmatch(r"[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*", required_checks),
             f"unsafe required check list: {required_checks}")]:
        if not valid:
            raise ToolError(message, 2)
    for tool in ("gh", "ssh-keygen"):
        if not shutil.which(tool):
            raise ToolError(f"tag verification needs {tool}")

    reference = json_output("gh", "api", f"repos/{repository}/git/ref/tags/{tag}")
    if field(reference, "object", "type") != "tag":
        raise ToolError(f"release tag {tag} is lightweight; a signed annotated tag is required")
    tag_object = json_output("gh", "api",
                             f"repos/{repository}/git/tags/{field(reference, 'object', 'sha')}")
    actual_tag = field(tag_object, "tag")
    target_type = field(tag_object, "object", "type")
    target_commit = field(tag_object, "object", "sha")
    verification = tag_object.get("verification") or {}
    if actual_tag != tag:
        raise ToolError(f"tag object names {actual_tag}, expected {tag}")
    if target_type != "commit":
        raise ToolError(f"release tag {tag} points to a {target_type}, not a commit")
    if target_commit != expected_commit:
        raise ToolError(f"release tag {tag} resolves to {target_commit}, "
                        f"not workflow commit {expected_commit}")
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise ToolError(f"GitHub did not verify the signature on release tag {tag} "
                        f"(reason: {verification.get('reason')})")
    # GitHub's verified flag establishes signature validity, not release authority.
    # Verify the signed payload against the public maintainer identity as well.
    verify_signature(tag, tag_object)

    comparison = json_output("gh", "api",
                             f"repos/{repository}/compare/{target_commit}...{protected_branch}")
    if (field(comparison, "base_commit", "sha") != target_commit
            or field(comparison, "merge_base_commit", "sha") != target_commit):
        raise ToolError(f"release commit {target_commit} is not reachable from protected branch "
                        f"{protected_branch}")

    # Native releases may reuse ancestor evidence for unchanged test inputs.
    evidence = {}
    if re.match(r"v[0-9]", tag):
        certification = subprocess.run([str(SCRIPTS / "verify-release-ci.py"), "--json",
                                         repository, target_commit],
                                        stdout=subprocess.PIPE, text=True)
        if certification.returncode:
            raise ToolError(f"full release CI does not certify {target_commit}")
        evidence = {workflow["workflow"]: workflow["evidence_commit"]
                    for workflow in json.loads(certification.stdout)["workflows"]}
    for check_name in required_checks.split(","):
        workflow = "rsync-compat.yml" if check_name == "conformance" else "ci.yml"
        checked_commit = evidence.get(workflow, target_commit)
        check_runs = json_output("gh", "api", f"repos/{repository}/commits/{checked_commit}"
                                 "/check-runs?filter=latest&per_page=100")
        conclusion = check_conclusion(check_runs, check_name)
        if conclusion != "success":
            raise ToolError(f"required check {check_name} is {conclusion} on certified commit "
                            f"{checked_commit}")

    print(f"verified signed annotated tag {tag} at {target_commit} on {protected_branch} "
          f"with checks {required_checks}")
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
