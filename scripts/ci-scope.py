#!/usr/bin/env python3
"""Classify a GitHub Actions change set for post-merge and manual validation.

Usage: scripts/ci-scope.py [GITHUB_EVENT_PATH]

Prints `key=value` lines for $GITHUB_OUTPUT. SYQ_TEST_CHANGED_PATHS_FILE
replaces the event with a list of changed paths for tests.

SYQ_CI_SUITES, set from ci.yml's `suites` dispatch input, selects named suites
instead of classifying paths; see SUITES below. Each selected suite's job then
shares a cancellation group with the same suite on the same branch, so a later
selection of that suite replaces an earlier run.
"""
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from tooling import ToolError, output, report_errors

SCRIPTS = Path(os.path.abspath(__file__)).parent
ALL_TOOLING = "package installer benchmark release orchestration focused branch workflows setup"
DOCUMENTATION_PATHS = "docs/mappings.md\ndocs/automation.md\ndocs/commands/map.md"
REAL_SSH = {
    "real-ssh-core": {"suite": "core", "profile": "default"},
    # Omit unaffected cases and workflows that require concurrent sessions
    # on one connection; both remain covered by the default profile.
    "real-ssh-max-sessions-1": {"suite": "core", "profile": "max-sessions-1",
                                "skip": "tests/real-ssh/max-sessions-1.skip"},
    "real-ssh-metadata": {"suite": "metadata", "profile": "default"},
    "real-ssh-benchmark": {"suite": "benchmark", "profile": "default"},
}
# Suites that ci.yml's `suites` input can select, as the scope outputs each sets.
SUITES = {
    "rust": {"native": True, "integration_targets": "all"},
    "quick": {"tooling": True, "quick_tooling": True},
    "tooling": {"tooling": True, "tooling_checks": ALL_TOOLING, "all_tooling": True},
    "shellcheck": {"shellcheck": True},
    "mapping-docs": {"mapping_docs": True},
    "python-sdk": {"sdks": True, "python_sdk": True},
    "linux-arm64": {"linux_arm64": True},
    "macos-intel": {"macos": True, "macos_intel": True},
    "s3": {"s3": True},
    "repository-checks": {"repository_checks": True},
    **{name: {"real_ssh": [entry]} for name, entry in REAL_SSH.items()},
    "real-ssh": {"real_ssh": list(REAL_SSH.values())},
}


def run_everything():
    print("\n".join([
        "suite_selection=false",
        "rust_label=full",
        "all_tooling=true",
        "quick_tooling=false",
        "s3=true",
        "repository_checks=true",
        "macos_intel=true",
        f"real_ssh_matrix={json.dumps(list(REAL_SSH.values()))}",
        "native=true",
        "sdks=true",
        "python_sdk=true",
        "tooling=true",
        f"tooling_checks={ALL_TOOLING}",
        "shellcheck=true",
        "mapping_docs=true",
        "conformance=true",
        "macos=true",
        "linux_arm64=true",
        "full_suite=true",
        'sdk_matrix=["python"]',
    ]))


def matches(path, *patterns):
    return any(fnmatchcase(path, pattern) for pattern in patterns)


def git(*args):
    return output("git", *args).strip()


def commit_exists(commit):
    return subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"],
                          stderr=subprocess.DEVNULL).returncode == 0


def read_event(event_path):
    try:
        with open(event_path, encoding="utf-8") as source:
            event = json.load(source)
    except ValueError as error:
        raise ToolError(f"cannot read GitHub event {event_path}: {error}") from None
    if not isinstance(event, dict):
        raise ToolError(f"unsupported GitHub event in {event_path}")
    return event


def changed_paths_from_event(event):
    """Return (changed paths, base, head), or None after printing a full scope."""
    try:
        if "pull_request" in event:
            base = event["pull_request"]["base"]["sha"]
            head = event["pull_request"]["head"]["sha"]
            diff_range = f"{base}...{head}"
        elif "before" in event:
            base, head = event["before"], event["after"]
            if re.fullmatch(r"0+", base):
                run_everything()
                print("CI scope: new branch or incomplete push history; running every check",
                      file=sys.stderr)
                return None
            diff_range = f"{base}..{head}"
        else:
            # A generated SDK follow-up uses a workflow dispatch because GitHub does
            # not trigger push workflows for merges made with GITHUB_TOKEN. It passes
            # the checked-out merge commit so this path has the same precise scope as
            # a normal push. Other manual runs retain the full-suite default.
            scope_commit = os.environ.get("SYQ_CI_SCOPE_COMMIT", "")
            if not scope_commit:
                run_everything()
                print("CI scope: manual run; running every check", file=sys.stderr)
                return None
            if not re.fullmatch(r"[0-9a-f]{40}", scope_commit):
                raise ToolError(f"invalid CI scope commit: {scope_commit}", 2)
            head = git("rev-parse", "HEAD")
            if head != scope_commit:
                raise ToolError(f"CI scope commit {scope_commit} is not checked out (found {head})")
            base = git("rev-parse", f"{head}^")
            diff_range = f"{base}..{head}"
    except (KeyError, TypeError):
        raise ToolError("the GitHub event has no usable commit range") from None
    if not isinstance(base, str) or not isinstance(head, str):
        raise ToolError("the GitHub event has no usable commit range")
    if not commit_exists(base):
        raise ToolError(f"CI scope base commit is unavailable: {base}")
    if not commit_exists(head):
        raise ToolError(f"CI scope head commit is unavailable: {head}")
    # Classify both sides of a rename so moving an affected input into an
    # otherwise inert directory cannot hide its former dependency boundary.
    return git("diff", "--no-renames", "--name-only", diff_range), base, head


def rust_label(selection):
    """What a partial rust job runs. Dispatched runs on task branches put it in
    the job's name, because scripts/branch-status.py matches checks by name."""
    parts = []
    if selection["native"]:
        parts.append("native:" + ",".join(selection["integration_targets"].split() or ["bin"]))
    if selection["tooling"]:
        parts.append("tooling:" + ("all" if selection.get("all_tooling") else
                                   "quick" if selection.get("quick_tooling") else
                                   ",".join(selection["tooling_checks"].split())))
    parts += [name for name, key in (("shellcheck", "shellcheck"), ("mapping-docs", "mapping_docs"))
              if selection[key]]
    return " ".join(parts) or "none"


def select_suites(names):
    """Print the scope for suites named in ci.yml's `suites` dispatch input."""
    if os.environ.get("SYQ_CI_SCOPE_COMMIT") or os.environ.get("SYQ_CI_DOCUMENTATION_ONLY") == "true":
        raise ToolError("suites cannot be combined with scope_commit or documentation_only", 2)
    # Release evidence uses the latest ci.yml run on a master commit, so a partial
    # run there would hide a full one. Selected suites are for task branches.
    if os.environ.get("GITHUB_REF") == "refs/heads/master":
        raise ToolError("run selected suites on a task branch, not master", 2)
    unknown = [name for name in names if name not in SUITES]
    if unknown:
        raise ToolError(f"unknown suite: {' '.join(unknown)} (choose from {' '.join(SUITES)})", 2)
    selection = {"native": False, "sdks": False, "python_sdk": False, "tooling": False,
                 "shellcheck": False, "mapping_docs": False, "linux_arm64": False,
                 "macos": False, "macos_intel": False, "s3": False, "repository_checks": False,
                 "all_tooling": False, "quick_tooling": False,
                 "integration_targets": "", "tooling_checks": "", "real_ssh": []}
    for name in names:
        for key, value in SUITES[name].items():
            if key == "real_ssh":
                selection[key] += value
            elif isinstance(value, str):
                selection[key] = value
            else:
                selection[key] = True
    # Keep the matrix in a fixed order so equal selections share cancellation groups.
    selected_real_ssh = selection.pop("real_ssh")
    real_ssh = [entry for entry in REAL_SSH.values() if entry in selected_real_ssh]
    for key, value in selection.items():
        print(f"{key}={str(value).lower() if isinstance(value, bool) else value}")
    print(f"rust_label={rust_label(selection)}")
    print(f"real_ssh_matrix={json.dumps(real_ssh)}")
    print("suite_selection=true\nconformance=false\nfull_suite=false")
    print('sdk_matrix=["python"]' if selection["python_sdk"] else 'sdk_matrix=["none"]')
    print(f"CI scope: selected suites {' '.join(names)}", file=sys.stderr)
    return 0


def main():
    event_path = (sys.argv[1] if len(sys.argv) > 1 else "") or os.environ.get("GITHUB_EVENT_PATH")
    base = head = ""
    suites = os.environ.get("SYQ_CI_SUITES", "").replace(",", " ").split()
    if suites:
        return select_suites(suites)
    changed_paths_file = os.environ.get("SYQ_TEST_CHANGED_PATHS_FILE", "")
    if changed_paths_file:
        try:
            changed_paths = Path(changed_paths_file).read_text()
        except OSError as error:
            raise ToolError(f"cannot read {changed_paths_file}: {error.strerror}") from None
    elif event_path and os.path.isfile(event_path) and "schedule" in read_event(event_path):
        nightly = subprocess.run([sys.executable, str(SCRIPTS / "nightly-ci.py")])
        if nightly.returncode == 0:
            run_everything()
            return 0
        if nightly.returncode != 3:
            return nightly.returncode
        # No changed test inputs: emit the ordinary all-false scope below.
        changed_paths = "README.md"
    elif os.environ.get("SYQ_CI_DOCUMENTATION_ONLY", "") == "true":
        changed_paths = DOCUMENTATION_PATHS
    elif event_path and os.path.isfile(event_path):
        result = changed_paths_from_event(read_event(event_path))
        if result is None:
            return 0
        changed_paths, base, head = result
    else:
        print(f"usage: {sys.argv[0]} GITHUB_EVENT_PATH", file=sys.stderr)
        return 2

    preparation_only = bool(base and head) and subprocess.run([
        sys.executable, str(SCRIPTS / "release_test_inputs.py"), head, "--native",
        "--equivalent-to", base]).returncode == 0
    selection = classify(changed_paths.split("\n"), preparation_only)

    print(f"tooling_checks={selection['tooling_checks']}")
    keys = ["native", "sdks", "python_sdk", "tooling", "shellcheck", "mapping_docs",
            "conformance", "macos", "linux_arm64", "full_suite"]
    for key in keys:
        print(f"{key}={str(selection[key]).lower()}")
    print(f"integration_targets={selection['integration_targets']}")
    # Only full runs and selected suites run these.
    print(f"rust_label={rust_label(selection)}")
    print("suite_selection=false\nall_tooling=false\nquick_tooling=false\ns3=false\n"
          "repository_checks=false\nmacos_intel=false\nreal_ssh_matrix=[]")
    print("CI scope: " + " ".join(f"{key}={str(selection[key]).lower()}" for key in keys),
          file=sys.stderr)
    print('sdk_matrix=["python"]' if selection["python_sdk"] else 'sdk_matrix=["none"]')
    return 0


def classify(paths, preparation_only):
    native = sdks = python_sdk = tooling = shellcheck = mapping_docs = False
    conformance = macos = linux_arm64 = full_suite = False
    integration_targets = []
    tooling_checks = []
    saw_path = False
    for path in paths:
        if not path:
            continue
        saw_path = True
        path_tooling = False
        path_tooling_checks = []
        # Shell lint is cheap and independent of the path's product surface.
        # Keep it selected even when the rules below deliberately ignore the path.
        if path.endswith(".sh"):
            shellcheck = True

        for patterns, target in [
            (("tests/local.rs", "tests/local/*"), "local"),
            (("tests/help.rs", "tests/help/*"), "help"),
            (("tests/output.rs", "tests/output/*"), "output"),
            (("tests/update.rs", "tests/update/*"), "update"),
            (("tests/return_handoff.rs", "tests/return_handoff/*"), "return_handoff"),
            (("tests/s3.rs", "tests/s3/*"), "s3"),
            (("tests/build_identity.rs",), "build_identity"),
            (("tests/temp_paths.rs",), "temp_paths"),
            (("tests/macos_exfat.rs",), "macos_exfat"),
            (("tests/support/*", "tests/fixtures/*"), "all"),
        ]:
            if matches(path, *patterns):
                integration_targets.append(target)
                break

        if matches(path, "sdk/README.md", "sdk/RELEASING.md", "sdk/python/README-PYTHON.md",
                   "sdk/python/NATIVE_API.md", "sdk/python/API_DESIGN.md"):
            # These are prose, not executable SDK test inputs. Keep the exception
            # explicit: native-api.json is compiled into Rust, and files elsewhere
            # in an SDK (including future Markdown fixtures) still select its tests.
            pass
        elif matches(path, "book.toml", "theme/*", ".agents/*"):
            # Documentation rendering and agent guidance do not affect the product
            # suites. Pages validates the book/theme; shell files still get linted.
            pass
        elif path == "sdk/python/native-api.json":
            # This SDK-owned specification is compiled into the Rust CLI.
            native = python_sdk = True
        elif matches(path, "sdk/python/*"):
            python_sdk = True
        elif matches(path, "sdk/*"):
            # Files shared across sdk/ can affect the Python SDK.
            python_sdk = True
        elif matches(path, "MAPPINGS.md", "docs/mappings.md", "docs/automation.md",
                     "docs/commands/map.md"):
            # The documented jq programs are executable integration-test inputs.
            mapping_docs = True
        elif matches(path, "tests/rsync-compat/*", "scripts/rsync-compat.py"):
            conformance = True
        elif matches(path, "tests/fixtures/*"):
            # The same protocol fixtures are consumed by Rust and Python tests.
            native = python_sdk = True
        elif matches(path, "Cargo.toml", "Cargo.lock"):
            if not preparation_only:
                native = True
        elif matches(path, "src/*macos*", "tests/macos*"):
            native = macos = True
        elif matches(path, "rust-toolchain.toml", "build.rs", "src/*", "tests/*.rs", "schemas/*"):
            native = True
        elif matches(path, ".github/workflows/*"):
            path_tooling = True
        elif matches(path, "nix/python-dist.nix", "scripts/build-python-dist.sh",
                     "scripts/package-python-wheel.py", "scripts/pin-python-native-source.py",
                     "scripts/normalize-python-wheel.py", "scripts/check-python-api-sync.py",
                     "scripts/normalize-python-sdist.py", "scripts/check-python-wheel.py",
                     "scripts/stage-python-sdk.py", "scripts/prepare-python-sdk-release.py",
                     "scripts/run-generated-sdk-post-merge-ci.py", "scripts/select-trusted-pr.jq",
                     "tests/tooling/test-python-sdk-release-tools.py",
                     "scripts/verify-python-release-preparation.py"):
            path_tooling = python_sdk = True
        elif matches(path, "scripts/generate-homebrew-formula.py", "scripts/test-homebrew-formula.py",
                     "scripts/generate-installer.py", "tests/tooling/test-installer.py"):
            path_tooling = True
        elif matches(path, "tests/real-ssh/*"):
            pass
        elif path == "scripts/setup.lock":
            # Pinned tools run the Rust, SDK, conformance, and tooling tests.
            native = python_sdk = path_tooling = shellcheck = mapping_docs = conformance = True
        elif matches(path, "scripts/*", "tests/tooling/*", "deny.toml"):
            path_tooling = True
        elif matches(path, "*.md", "docs/*", ".github/ISSUE_TEMPLATE/*", ".github/dependabot.yml",
                     "LICENSE", ".gitignore", ".claude/*"):
            pass
        else:
            # Unknown inputs fail safe until their dependency boundary is explicit.
            native = python_sdk = path_tooling = shellcheck = mapping_docs = conformance = True

        if matches(path, ".github/workflows/*", "scripts/check-workflows.py",
                   "scripts/check-script-references.py"):
            path_tooling_checks += ["workflows", "orchestration"]
        elif matches(path, "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            if not preparation_only:
                path_tooling_checks.append("package")
        elif matches(path, "tests/tooling/test-cargo-package.py", "build.rs", "src/identity.rs",
                     "tests/build_identity.rs"):
            path_tooling_checks.append("package")
        elif matches(path, "scripts/generate-installer.py", "tests/tooling/test-installer.py"):
            path_tooling_checks.append("installer")
        elif matches(path, "scripts/try-benchmark*", "tests/tooling/test-try-benchmark.py",
                     "scripts/benchmark-concurrency.py", "tests/tooling/test-benchmark-concurrency.py"):
            path_tooling_checks.append("benchmark")
        elif matches(path, "scripts/run-focused-check.py", "tests/tooling/test-run-focused-check.py"):
            path_tooling_checks.append("focused")
        elif matches(path, "scripts/branch-status.py", "tests/tooling/test-branch-status.py",
                     "scripts/dispatched_checks.py", "scripts/dispatched-checks-status.py",
                     "scripts/pr-checks.py", "tests/tooling/test-dispatched-checks-status.py"):
            path_tooling_checks.append("branch")
        elif matches(path, "scripts/setup.sh", "tests/tooling/test-setup.sh"):
            path_tooling_checks.append("setup")
        elif path == "scripts/setup.lock":
            path_tooling_checks += ALL_TOOLING.split()
        elif path == "scripts/verify-release-ci.py":
            path_tooling_checks += ["release", "orchestration"]
        elif matches(path, "tests/tooling/test-release-tools.py", "scripts/package-release.py",
                     "scripts/verify-crates-io-package.py", "scripts/verify-release-*",
                     "scripts/generate-release-*", "scripts/sign-release-*"):
            path_tooling_checks.append("release")
        elif matches(path, "scripts/ci-scope.py", "scripts/*release-orchestration*",
                     "tests/tooling/test-release-orchestration.py",
                     "tests/tooling/test-generated-sdk-post-merge-ci.py",
                     "scripts/release-preflight.py", "scripts/release-status.py",
                     "scripts/release-readiness.py", "scripts/release-timings.py",
                     "scripts/release_test_inputs.py", "scripts/release-tag-signers",
                     "scripts/find-release-build.py", "scripts/nightly-ci.py",
                     "tests/tooling/test-release-readiness.py", "tests/tooling/test-release-timings.py",
                     "tests/tooling/test-release-test-inputs.py", "tests/tooling/test-find-release-build.py",
                     "tests/tooling/test-nightly-ci.py", "scripts/*generated-sdk-post-merge-ci.py"):
            path_tooling_checks.append("orchestration")
        elif path == "scripts/rsync-compat.py":
            pass
        elif matches(path, "scripts/*", "tests/tooling/*", "deny.toml"):
            # Retain broad coverage for tooling whose ownership is not yet mapped,
            # including the shared scripts/tooling.py module.
            path_tooling_checks += ALL_TOOLING.split()
        # Workflows, the release skill, and release docs name scripts by path;
        # check those references whenever a script is added, renamed, or removed.
        if matches(path, "scripts/*", "tests/tooling/*") and "workflows" not in path_tooling_checks:
            path_tooling_checks.append("workflows")
        # Apply fallback to this path before combining it with other selections.
        if path_tooling and not path_tooling_checks:
            path_tooling_checks = ALL_TOOLING.split()
        tooling_checks += path_tooling_checks

    if not saw_path:
        native = python_sdk = shellcheck = mapping_docs = conformance = True
        tooling_checks = ALL_TOOLING.split()

    # Sort and deduplicate so equivalent selections share a cancellation group.
    checks = " ".join(sorted(set(tooling_checks)))
    if checks:
        tooling = True
    if python_sdk:
        sdks = True
    return {
        "tooling_checks": checks, "native": native, "sdks": sdks, "python_sdk": python_sdk,
        "tooling": tooling, "shellcheck": shellcheck, "mapping_docs": mapping_docs,
        "conformance": conformance, "macos": macos, "linux_arm64": linux_arm64,
        "full_suite": full_suite,
        # Canonicalize selections so equivalent changes share a cancellation group.
        "integration_targets": " ".join(sorted(set(integration_targets))),
    }


if __name__ == "__main__":
    sys.exit(report_errors(main))
