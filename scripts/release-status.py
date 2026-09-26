#!/usr/bin/env python3
"""Report release progress without changing GitHub, registries, or local refs.

Usage: scripts/release-status.py [--json] [vMAJOR.MINOR.PATCH]

Without a tag, report the version in Cargo.toml.
"""
import base64
import binascii
import json
import re
import shutil
import subprocess
import sys
import tomllib

from tooling import ToolError, cargo_version, json_output, report_errors

REPOSITORY = "greaber/syq"
HOMEBREW_REPOSITORY = "greaber/homebrew-tap"


def optional_json(*args):
    """The JSON printed by a command whose failure is an ordinary result, else None."""
    completed = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True)
    if completed.returncode:
        return None
    try:
        return json.loads(completed.stdout)
    except ValueError:
        return None


def tag_status(tag):
    """(commit, state) of the remote tag."""
    references = json_output("gh", "api", f"repos/{REPOSITORY}/git/matching-refs/tags/{tag}")
    reference = next((item for item in references if item.get("ref") == f"refs/tags/{tag}"), None)
    if reference is None:
        return None, "missing"
    target = reference.get("object") or {}
    if target.get("type") == "commit":
        return target.get("sha"), "lightweight"
    if target.get("type") != "tag":
        return None, "invalid-target"
    tag_object = json_output("gh", "api", f"repos/{REPOSITORY}/git/tags/{target.get('sha')}")
    if tag_object.get("tag") != tag:
        return None, "name-mismatch"
    if (tag_object.get("object") or {}).get("type") != "commit":
        return None, "invalid-target"
    verification = tag_object.get("verification") or {}
    verified = verification.get("verified") is True and verification.get("reason") == "valid"
    return tag_object["object"].get("sha"), "verified" if verified else "unverified"


def github_release(tag):
    pages = json_output("gh", "api", "--paginate", "--slurp",
                        f"repos/{REPOSITORY}/releases?per_page=100")
    release = next((release for page in pages for release in page
                    if release.get("tag_name") == tag), None)
    if release is None:
        return {"state": "missing", "immutable": False, "url": None}
    return {"state": "draft" if release.get("draft") else "published",
            "immutable": bool(release.get("immutable")), "url": release.get("html_url")}


def release_runs(tag, tag_commit):
    runs = json_output("gh", "run", "list", "--repo", REPOSITORY, "--workflow", "release.yml",
                       "--branch", tag, "--limit", "20", "--json",
                       "conclusion,databaseId,event,headSha,status,url,workflowName")
    if tag_commit:
        runs = [run for run in runs if run.get("headSha") == tag_commit]
    for run in runs:
        pending = optional_json("gh", "api",
                                f"repos/{REPOSITORY}/actions/runs/{run['databaseId']}"
                                "/pending_deployments")
        run["pending_environments"] = (None if pending is None else
                                       [(item.get("environment") or {}).get("name")
                                        for item in pending])
    return runs


def publications(tag):
    version = tag.removeprefix("v")
    crates_state = "unknown"
    crates = optional_json("curl", "--fail", "--silent", "--show-error", "--location", "--proto",
                           "=https", "--proto-redir", "=https", "--user-agent",
                           "syq-release-status (https://github.com/greaber/syq)",
                           "https://crates.io/api/v1/crates/syq")
    if crates is not None:
        published = any(item.get("num") == version for item in crates.get("versions") or [])
        crates_state = "published" if published else "missing"

    # The SDK version that pins this syq release, when the checkout's SDK does.
    pypi_version = None
    try:
        with open("sdk/python/src/syq/syq-release-manifest.json", encoding="utf-8") as source:
            mapped = json.load(source).get("tag") == tag
    except (OSError, ValueError, AttributeError):
        mapped = False
    if mapped:
        with open("sdk/python/pyproject.toml", "rb") as source:
            pypi_version = tomllib.load(source)["project"]["version"]
    pypi_state = "unknown"
    pypi = optional_json("curl", "--fail", "--silent", "--show-error", "--location", "--proto",
                         "=https", "--proto-redir", "=https", "https://pypi.org/pypi/syq/json")
    if pypi is not None:
        if pypi_version:
            files = (pypi.get("releases") or {}).get(pypi_version)
            pypi_state = "published" if files else "missing"
        else:
            pypi_state = "unmapped"
            pypi_version = (pypi.get("info") or {}).get("version")

    homebrew_state = "unknown"
    formula = optional_json("gh", "api", f"repos/{HOMEBREW_REPOSITORY}/contents/Formula/syq.rb")
    if formula is not None:
        try:
            content = base64.b64decode(formula["content"].replace("\n", ""))
        except (KeyError, AttributeError, binascii.Error, ValueError):
            raise ToolError("cannot read the Homebrew formula") from None
        homebrew_state = "published" if f"/{tag}/".encode() in content else "missing"
    return {"crates_io": {"version": version, "state": crates_state},
            "pypi": {"version": pypi_version, "state": pypi_state},
            "homebrew": {"tag": tag, "state": homebrew_state}}


def status(tag):
    tag_commit, tag_state = tag_status(tag)
    release = github_release(tag)
    runs = release_runs(tag, tag_commit)
    published = publications(tag)
    return {
        "repository": REPOSITORY, "tag": tag, "tag_commit": tag_commit, "tag_state": tag_state,
        "github_release": release, "release_runs": runs, "publications": published,
        "complete": (tag_state == "verified" and release["state"] == "published"
                     and release["immutable"]
                     and any(run.get("status") == "completed" and run.get("conclusion") == "success"
                             for run in runs)
                     and all(item["state"] == "published" for item in published.values())),
    }


def human(result):
    release, published = result["github_release"], result["publications"]
    lines = [
        f"Release {result['tag']}",
        f"  tag:       {result['tag_state']}"
        + (f" at {result['tag_commit']}" if result["tag_commit"] else ""),
        f"  GitHub:    {release['state']}" + (" (immutable)" if release["immutable"] else ""),
        f"  crates.io: {published['crates_io']['state']}",
        f"  PyPI SDK:  {published['pypi']['state']}"
        + (f" ({published['pypi']['version']})" if published["pypi"]["version"] else ""),
        f"  Homebrew:  {published['homebrew']['state']}",
        "  complete:  " + ("yes" if result["complete"] else "no"),
    ]
    if not result["release_runs"]:
        lines.append("  runs:       none")
    for run in result["release_runs"]:
        environments = run["pending_environments"]
        pending = ("unknown" if environments is None
                   else ", ".join(name or "" for name in environments) or "none")
        conclusion = f"/{run['conclusion']}" if run.get("conclusion") else ""
        lines.append(f"  run {run.get('databaseId')}: {run.get('status')}{conclusion}, "
                     f"pending environments: {pending}\n    {run.get('url')}")
    return "\n".join(lines)


def main():
    json_report = False
    tag = None
    for argument in sys.argv[1:]:
        if argument == "--json":
            json_report = True
        elif re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", argument):
            if tag:
                raise ToolError("only one tag may be supplied", 2)
            tag = argument
        else:
            raise ToolError(f"usage: {sys.argv[0]} [--json] [vMAJOR.MINOR.PATCH]", 2)
    tag = tag or "v" + cargo_version("Cargo.toml")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ToolError(f"invalid release tag: {tag}", 2)
    for tool in ("gh", "curl"):
        if not shutil.which(tool):
            raise ToolError(f"release status needs {tool}")
    try:
        result = status(tag)
    except (AttributeError, KeyError, TypeError, OSError, ValueError) as error:
        raise ToolError(f"unexpected GitHub or registry response ({error!r})") from None
    print(json.dumps(result, indent=2) if json_report else human(result))
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
