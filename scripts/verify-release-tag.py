#!/usr/bin/env python3
"""Verify a release tag before the release workflow publishes anything.

Usage: scripts/verify-release-tag.py OWNER/REPOSITORY TAG EXPECTED_COMMIT
       PROTECTED_BRANCH REQUIRED_CHECKS

Require a maintainer-signed, GitHub-verified annotated tag that directly names
the workflow commit, is reachable from the protected branch, and has every
named CI check concluded successfully. Native releases may reuse ancestor
evidence only for unchanged test inputs; SDK checks remain exact.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from tooling import (JqError, captured, check_conclusion, comma_fields, command, command_json,
                     exit_on_failure, get, iterate, loads, require, text)

SCRIPTS = Path(os.path.abspath(__file__)).parent


def fail(message):
    print(message, file=sys.stderr)
    return 1


def main():
    if len(sys.argv) != 6:
        print(f"usage: {sys.argv[0]} OWNER/REPOSITORY TAG EXPECTED_COMMIT PROTECTED_BRANCH "
              "REQUIRED_CHECKS", file=sys.stderr)
        print("REQUIRED_CHECKS is a comma-separated list of check run names", file=sys.stderr)
        return 2
    repository, tag, expected_commit, protected_branch, required_checks = sys.argv[1:]
    if "/" not in repository:
        print(f"invalid GitHub repository: {repository}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9._-]+", tag):
        print(f"unsafe release tag: {tag}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[0-9a-f]+", expected_commit):
        print(f"invalid expected commit: {expected_commit}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", protected_branch):
        print(f"unsafe protected branch: {protected_branch}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9._,-]+", required_checks):
        print(f"unsafe required check list: {required_checks}", file=sys.stderr)
        return 2
    if not shutil.which("gh"):
        return fail("tag verification needs gh")

    reference = command_json("gh", "api", f"repos/{repository}/git/ref/tags/{tag}")
    object_type = captured(require(get(reference, "object", "type")))
    tag_sha = captured(require(get(reference, "object", "sha")))
    if object_type != "tag":
        return fail(f"release tag {tag} is lightweight; a signed annotated tag is required")

    tag_object = command_json("gh", "api", f"repos/{repository}/git/tags/{tag_sha}")
    actual_tag = captured(require(get(tag_object, "tag")))
    target_type = captured(require(get(tag_object, "object", "type")))
    target_commit = captured(require(get(tag_object, "object", "sha")))
    verified = captured(get(tag_object, "verification", "verified"))
    reason = captured(get(tag_object, "verification", "reason"))
    if actual_tag != tag:
        return fail(f"tag object names {actual_tag}, expected {tag}")
    if target_type != "commit":
        return fail(f"release tag {tag} points to a {target_type}, not a commit")
    if target_commit != expected_commit:
        return fail(f"release tag {tag} resolves to {target_commit}, "
                    f"not workflow commit {expected_commit}")
    if verified != "true" or reason != "valid":
        return fail(f"GitHub did not verify the signature on release tag {tag} (reason: {reason})")

    # GitHub's verified flag establishes signature validity, not release authority.
    # Verify the signed payload against the public maintainer identity as well.
    if not shutil.which("ssh-keygen"):
        return fail("tag verification needs ssh-keygen")
    with tempfile.TemporaryDirectory(prefix="syq-tag-verification.") as verification_dir:
        verification = {}
        for field in ("signature", "payload"):
            try:
                value = get(tag_object, "verification", field)
            except JqError:
                value = None
            if not (isinstance(value, str) and value):
                return fail(f"release tag {tag} has a missing, empty, or invalid verification {field}")
            verification[field] = Path(verification_dir, field)
            try:
                verification[field].write_bytes(value.encode("utf-8"))
            except UnicodeEncodeError:
                return fail(f"release tag {tag} was not signed by the pinned maintainer key")
        with verification["payload"].open("rb") as payload:
            signed = subprocess.run(["ssh-keygen", "-Y", "verify", "-f",
                                     str(SCRIPTS / "release-tag-signers"), "-I", "syq-release",
                                     "-n", "git", "-s", str(verification["signature"])],
                                    stdin=payload)
        if signed.returncode:
            return fail(f"release tag {tag} was not signed by the pinned maintainer key")

    comparison = command_json("gh", "api",
                              f"repos/{repository}/compare/{target_commit}...{protected_branch}")
    base_commit = captured(require(get(comparison, "base_commit", "sha")))
    merge_base = captured(require(get(comparison, "merge_base_commit", "sha")))
    if base_commit != target_commit or merge_base != target_commit:
        return fail(f"release commit {target_commit} is not reachable from protected branch "
                    f"{protected_branch}")

    certification = None
    if re.match(r"v[0-9]", tag):
        certification = loads(command(str(SCRIPTS / "verify-release-ci.py"), "--json",
                                      repository, target_commit))
    for check_name in comma_fields(required_checks):
        checked_commit = target_commit
        if certification is not None:
            workflow = "rsync-compat.yml" if check_name == "conformance" else "ci.yml"
            evidence = [get(item, "evidence_commit") for item in iterate(get(certification, "workflows"))
                        if get(item, "workflow") == workflow]
            if not evidence:
                raise JqError(4, f"no certification for {workflow}")
            checked_commit = captured("\n".join(text(value) for value in evidence))
            require(evidence[-1])
        check_runs = command_json("gh", "api", f"repos/{repository}/commits/{checked_commit}"
                                  "/check-runs?filter=latest&per_page=100")
        conclusion = check_conclusion(check_runs, check_name)
        if conclusion != "success":
            return fail(f"required check {check_name} is {conclusion} on certified commit "
                        f"{checked_commit}")

    print(f"verified signed annotated tag {tag} at {target_commit} on {protected_branch} "
          f"with checks {required_checks}")
    return 0


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
