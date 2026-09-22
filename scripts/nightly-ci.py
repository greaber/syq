"""Exit 0 for changed nightly inputs, 3 for unchanged inputs; errors fail CI."""
import json
import os
import subprocess
import sys

from release_test_inputs import fingerprint


def needs_run(previous, current):
    return previous is None or fingerprint(previous) != fingerprint(current)


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    workflow = os.environ["GITHUB_WORKFLOW_REF"].split("@", 1)[0].rsplit("/", 1)[1]
    branch = os.environ["GITHUB_REF_NAME"]
    endpoint = (f"repos/{repository}/actions/workflows/{workflow}/runs"
                f"?event=schedule&status=success&branch={branch}&per_page=1")
    runs = json.loads(subprocess.check_output(["gh", "api", endpoint]))["workflow_runs"]
    previous = runs[0]["head_sha"] if runs else None
    current = os.environ["GITHUB_SHA"]
    changed = needs_run(previous, current)
    print(f"Nightly inputs: {previous or 'first run'} -> {current}; changed={changed}",
          file=sys.stderr)
    return 0 if changed else 3


if __name__ == "__main__":
    raise SystemExit(main())
