#!/usr/bin/env bash
# Classify a GitHub Actions change set without removing any required check.
set -euo pipefail

event_path=${1:-${GITHUB_EVENT_PATH:-}}
changed_paths=
full_suite=false

run_everything() {
  printf '%s\n' \
    'native=true' \
    'sdks=true' \
    'python_sdk=true' \
    'javascript_sdk=true' \
    'go_sdk=true' \
    'tooling=true' \
    'shellcheck=true' \
    'mapping_docs=true' \
    'conformance=true' \
    'macos=true' \
    'linux_arm64=true' \
    'full_suite=true'
}

if [ -n "${SYQ_TEST_CHANGED_PATHS_FILE:-}" ]; then
  changed_paths=$(cat "$SYQ_TEST_CHANGED_PATHS_FILE")
elif [ -n "$event_path" ] && [ -f "$event_path" ]; then
  event_name=$(jq -r 'if has("pull_request") then "pull_request" elif has("before") then "push" else "workflow_dispatch" end' "$event_path")
  case "$event_name" in
    pull_request)
      base=$(jq -er .pull_request.base.sha "$event_path")
      head=$(jq -er .pull_request.head.sha "$event_path")
      diff_range="$base...$head"
      ;;
    push)
      base=$(jq -er .before "$event_path")
      head=$(jq -er .after "$event_path")
      full_suite=true
      if [[ "$base" =~ ^0+$ ]]; then
        run_everything
        echo 'CI scope: new branch or incomplete push history; running every check' >&2
        exit 0
      fi
      diff_range="$base..$head"
      ;;
    workflow_dispatch)
      run_everything
      echo 'CI scope: manual run; running every check' >&2
      exit 0
      ;;
    *)
      echo "unsupported GitHub event in $event_path" >&2
      exit 1
      ;;
  esac
  git cat-file -e "$base^{commit}" 2>/dev/null \
    || { echo "CI scope base commit is unavailable: $base" >&2; exit 1; }
  git cat-file -e "$head^{commit}" 2>/dev/null \
    || { echo "CI scope head commit is unavailable: $head" >&2; exit 1; }
  # Classify both sides of a rename so moving an affected input into an
  # otherwise inert directory cannot hide its former dependency boundary.
  changed_paths=$(git diff --no-renames --name-only "$diff_range")
else
  echo "usage: $0 GITHUB_EVENT_PATH" >&2
  exit 2
fi

native=false
sdks=false
python_sdk=false
javascript_sdk=false
go_sdk=false
tooling=false
shellcheck=false
mapping_docs=false
conformance=false
macos=false
linux_arm64=false
saw_path=false
while IFS= read -r path; do
  [ -n "$path" ] || continue
  saw_path=true
  case "$path" in
    sdk/python/native-api.json)
      # This SDK-owned specification is compiled into the Rust CLI.
      native=true
      python_sdk=true
      ;;
    sdk/python/*)
      python_sdk=true
      ;;
    sdk/js/*)
      javascript_sdk=true
      ;;
    sdk/go/*)
      go_sdk=true
      ;;
    sdk/*)
      # Files shared by the language SDKs can affect all of them.
      python_sdk=true
      javascript_sdk=true
      go_sdk=true
      ;;
    MAPPINGS.md|docs/mappings.md)
      # The documented jq programs are executable integration-test inputs.
      mapping_docs=true
      ;;
    tests/rsync-compat/*|scripts/rsync-compat.py)
      conformance=true
      ;;
    tests/fixtures/*)
      # The same protocol fixtures are consumed by Rust and Python tests.
      native=true
      python_sdk=true
      ;;
    Cargo.toml|Cargo.lock|rust-toolchain.toml|build.rs|src/*|tests/*.rs|schemas/*)
      native=true
      ;;
    .github/workflows/ci.yml)
      tooling=true
      ;;
    .github/workflows/rsync-compat.yml)
      tooling=true
      conformance=true
      ;;
    .github/workflows/prepare-python-sdk.yml|.github/workflows/publish-sdks.yml|.github/workflows/python-api-sync.yml)
      tooling=true
      python_sdk=true
      ;;
    scripts/check-python-api-sync.py|scripts/normalize-python-sdist.py|scripts/prepare-python-sdk-release.py|scripts/select-trusted-pr.jq|scripts/test-python-sdk-release-tools.sh)
      tooling=true
      python_sdk=true
      ;;
    scripts/generate-homebrew-formula.sh|scripts/test-homebrew-formula.sh|scripts/generate-installer.sh|scripts/test-installer.sh)
      tooling=true
      ;;
    tests/real-ssh/*.sh)
      # The real-SSH suite is run locally when affected; CI still lints its
      # shell sources without promoting it to unrelated product suites.
      shellcheck=true
      ;;
    tests/real-ssh/*)
      ;;
    scripts/*|.github/workflows/*|.env.release|deny.toml)
      tooling=true
      ;;
    *.md|docs/*|use-cases/*|.github/ISSUE_TEMPLATE/*|.github/dependabot.yml|LICENSE|.gitignore|.claude/*)
      ;;
    *)
      # Unknown inputs fail safe until their dependency boundary is explicit.
      native=true
      python_sdk=true
      javascript_sdk=true
      go_sdk=true
      tooling=true
      shellcheck=true
      mapping_docs=true
      conformance=true
      ;;
  esac
done <<<"$changed_paths"

if [ "$saw_path" = false ]; then
  native=true
  python_sdk=true
  javascript_sdk=true
  go_sdk=true
  tooling=true
  shellcheck=true
  mapping_docs=true
  conformance=true
fi

# Pull requests run only affected Linux checks. The cumulative master state
# gets broad cross-subsystem and platform coverage once after merge.
if [ "$full_suite" = true ] && [ "$native" = true ]; then
  python_sdk=true
  javascript_sdk=true
  go_sdk=true
  conformance=true
  macos=true
  linux_arm64=true
fi

if [ "$python_sdk" = true ] || [ "$javascript_sdk" = true ] || [ "$go_sdk" = true ]; then
  sdks=true
fi

printf 'native=%s\nsdks=%s\npython_sdk=%s\njavascript_sdk=%s\ngo_sdk=%s\ntooling=%s\nshellcheck=%s\nmapping_docs=%s\nconformance=%s\nmacos=%s\nlinux_arm64=%s\nfull_suite=%s\n' \
  "$native" "$sdks" "$python_sdk" "$javascript_sdk" "$go_sdk" \
  "$tooling" "$shellcheck" "$mapping_docs" "$conformance" "$macos" \
  "$linux_arm64" "$full_suite"
echo "CI scope: native=$native sdks=$sdks python_sdk=$python_sdk javascript_sdk=$javascript_sdk go_sdk=$go_sdk tooling=$tooling shellcheck=$shellcheck mapping_docs=$mapping_docs conformance=$conformance macos=$macos linux_arm64=$linux_arm64 full_suite=$full_suite" >&2
