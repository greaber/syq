#!/usr/bin/env python3
"""Report release progress without changing GitHub, registries, or local refs.

Usage: scripts/release-status.py [--json] [vMAJOR.MINOR.PATCH]

Without a tag, report the version in Cargo.toml.
"""
import base64
import binascii
from fnmatch import fnmatchcase
import re
import shutil
import subprocess
import sys

from tooling import (JqError, alt, captured, cargo_version, command, dumps, exit_on_failure,
                     get, is_number, items, iterate, join, load_file, loads, require, text,
                     truthy)

REPOSITORY = "greaber/syq"
HOMEBREW_REPOSITORY = "greaber/homebrew-tap"


def succeeds(*args):
    """stdout of a command whose failure is an ordinary result, else None."""
    completed = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True)
    return None if completed.returncode else completed.stdout


def holds(predicate):
    try:
        return truthy(predicate())
    except JqError:
        return False


def first(values):
    """jq's `first // null` over an array."""
    return alt(values[0] if values else None, None)


def flatten(value):
    if not isinstance(value, list):
        raise JqError(5, "cannot flatten a non-array")
    result = []
    for item in value:
        result.extend(flatten(item) if isinstance(item, list) else [item])
    return result


def version_of(path):
    try:
        return cargo_version(path)
    except OSError as error:
        print(f"sed: can't read {path}: {error.strerror}", file=sys.stderr)
        raise JqError(2) from None


def argjson(value_text):
    """A value printed by `jq -r` and read back by `jq --argjson`."""
    try:
        return loads(value_text)
    except JqError:
        raise JqError(2, f"invalid JSON text passed to --argjson: {value_text}") from None


def tag_status(tag):
    references = loads(command("gh", "api", f"repos/{REPOSITORY}/git/matching-refs/tags/{tag}"))
    reference = first([item for item in iterate(references)
                       if get(item, "ref") == f"refs/tags/{tag}"])
    if reference is None:
        return "", "missing"
    object_type = captured(require(get(reference, "object", "type")))
    object_sha = captured(require(get(reference, "object", "sha")))
    if object_type == "tag":
        tag_object = loads(command("gh", "api", f"repos/{REPOSITORY}/git/tags/{object_sha}"))
        actual_tag = captured(require(get(tag_object, "tag")))
        target_type = captured(require(get(tag_object, "object", "type")))
        target_sha = captured(require(get(tag_object, "object", "sha")))
        verified = (get(tag_object, "verification", "verified") is True
                    and get(tag_object, "verification", "reason") == "valid")
        if actual_tag != tag:
            return "", "name-mismatch"
        if target_type != "commit":
            return "", "invalid-target"
        return target_sha, "verified" if verified else "unverified"
    if object_type == "commit":
        return object_sha, "lightweight"
    return "", "invalid-target"


def interpolate(value):
    return text(value)


def concat(prefix, value):
    if not isinstance(value, str):
        raise JqError(5, f"cannot add a string and {type(value).__name__}")
    return prefix + value


def main():
    json_output = False
    tag = ""
    for argument in sys.argv[1:]:
        if argument == "--json":
            json_output = True
        elif fnmatchcase(argument, "v[0-9]*.[0-9]*.[0-9]*"):
            if tag:
                print("only one tag may be supplied", file=sys.stderr)
                return 2
            tag = argument
        else:
            print(f"usage: {sys.argv[0]} [--json] [vMAJOR.MINOR.PATCH]", file=sys.stderr)
            return 2
    if not tag:
        tag = "v" + version_of("Cargo.toml")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        print(f"invalid release tag: {tag}", file=sys.stderr)
        return 2
    version = tag[1:]
    for tool in ("gh", "curl"):
        if not shutil.which(tool):
            print(f"release status needs {tool}", file=sys.stderr)
            return 1

    tag_commit, tag_state = tag_status(tag)

    releases = loads(command("gh", "api", "--paginate", "--slurp",
                             f"repos/{REPOSITORY}/releases?per_page=100"))
    release = first([item for item in flatten(releases) if get(item, "tag_name") == tag])
    github_state = "missing"
    github_url = ""
    github_immutable = "false"
    if release is not None:
        github_url = captured(get(release, "html_url"))
        github_immutable = captured(alt(get(release, "immutable"), False))
        github_state = "draft" if captured(get(release, "draft")) == "true" else "published"

    runs = loads(command("gh", "run", "list", "--repo", REPOSITORY, "--workflow", "release.yml",
                         "--branch", tag, "--limit", "20", "--json",
                         "conclusion,databaseId,event,headSha,status,url,workflowName"))
    if tag_commit:
        runs = [run for run in iterate(runs) if get(run, "headSha") == tag_commit]
    try:
        listed_runs = iterate(runs)
    except JqError:
        listed_runs = []
    runs_with_environments = []
    for run in listed_runs:
        run_id = captured(require(get(run, "databaseId")))
        pending = succeeds("gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}/pending_deployments")
        if pending is None:
            environments = None
        else:
            environments = [get(item, "environment", "name") for item in iterate(loads(pending))]
        if not isinstance(run, dict):
            raise JqError(5, "cannot add an object to a non-object run")
        runs_with_environments.append({**run, "pending_environments": environments})

    crates_state = "unknown"
    crates = succeeds("curl", "--fail", "--silent", "--show-error", "--location", "--proto",
                      "=https", "--proto-redir", "=https", "--user-agent",
                      "syq-release-status (https://github.com/greaber/syq)",
                      "https://crates.io/api/v1/crates/syq")
    if crates is not None:
        published = holds(lambda: any(get(item, "num") == version
                                      for item in items(get(loads(crates), "versions"))))
        crates_state = "published" if published else "missing"

    pypi_state = "unknown"
    pypi_version = ""
    try:
        mapped = alt(get(load_file("sdk/python/src/syq/syq-release-manifest.json"), "tag"), None)
        mapped_tag = "" if mapped is None else captured(mapped)
    except (JqError, OSError, UnicodeDecodeError):
        mapped_tag = ""
    if mapped_tag == tag:
        pypi_version = version_of("sdk/python/pyproject.toml")
    pypi = succeeds("curl", "--fail", "--silent", "--show-error", "--location", "--proto",
                    "=https", "--proto-redir", "=https", "https://pypi.org/pypi/syq/json")
    if pypi is not None:
        if pypi_version:
            def released():
                files = get(loads(pypi), "releases", pypi_version)
                return length(files) > 0
            pypi_state = "published" if holds(released) else "missing"
        else:
            pypi_state = "unmapped"
            found = alt(get(loads(pypi), "info", "version"), None)
            pypi_version = "" if found is None else captured(found)

    homebrew_state = "unknown"
    formula_json = succeeds("gh", "api", f"repos/{HOMEBREW_REPOSITORY}/contents/Formula/syq.rb")
    if formula_json is not None:
        content = captured(require(get(loads(formula_json), "content")))
        try:
            formula = base64.b64decode(content.replace("\n", ""))
        except (binascii.Error, ValueError):
            print("error: the Homebrew formula is not valid base64", file=sys.stderr)
            return 1
        homebrew_state = "published" if f"/{tag}/".encode() in formula else "missing"

    github_immutable = argjson(github_immutable)
    result = {
        "repository": REPOSITORY, "tag": tag,
        "tag_commit": tag_commit or None,
        "tag_state": tag_state,
        "github_release": {"state": github_state, "immutable": github_immutable,
                           "url": github_url or None},
        "release_runs": runs_with_environments,
        "publications": {
            "crates_io": {"version": version, "state": crates_state},
            "pypi": {"version": pypi_version or None, "state": pypi_state},
            "homebrew": {"tag": tag, "state": homebrew_state},
        },
    }
    result["complete"] = (
        tag_state == "verified" and github_state == "published" and truthy(github_immutable)
        and any(get(run, "status") == "completed" and get(run, "conclusion") == "success"
                for run in runs_with_environments)
        and crates_state == "published" and pypi_state == "published"
        and homebrew_state == "published")

    if json_output:
        print(dumps(result, indent=2))
        return 0
    lines = [
        f"Release {tag}",
        f"  tag:       {tag_state}" + (f" at {tag_commit}" if tag_commit else ""),
        f"  GitHub:    {github_state}" + (" (immutable)" if truthy(github_immutable) else ""),
        f"  crates.io: {crates_state}",
        f"  PyPI SDK:  {pypi_state}" + (f" ({pypi_version})" if pypi_version else ""),
        f"  Homebrew:  {homebrew_state}",
        "  complete:  " + ("yes" if result["complete"] else "no"),
    ]
    if not runs_with_environments:
        lines.append("  runs:       none")
    for run in runs_with_environments:
        conclusion = get(run, "conclusion")
        environments = run["pending_environments"]
        if environments is None:
            pending = "unknown"
        else:
            pending = join(environments, ", ") or "none"
        lines.append(f"  run {interpolate(get(run, 'databaseId'))}: {interpolate(get(run, 'status'))}"
                     + (concat("/", conclusion) if truthy(conclusion) else "")
                     + f", pending environments: {pending}\n    {interpolate(get(run, 'url'))}")
    print("\n".join(lines))
    return 0


def length(value):
    """jq's `length`."""
    if value is None:
        return 0
    if isinstance(value, bool):
        raise JqError(5, "boolean has no length")
    if is_number(value):
        return abs(value)
    return len(value)


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
