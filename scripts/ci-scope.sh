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
    'tooling=true' \
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
  changed_paths=$(git diff --name-only "$diff_range")
else
  echo "usage: $0 GITHUB_EVENT_PATH" >&2
  exit 2
fi

native=false
sdks=false
tooling=false
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
      sdks=true
      ;;
    sdk/*)
      sdks=true
      ;;
    MAPPINGS.md)
      # The documented jq programs are executable integration-test inputs.
      mapping_docs=true
      ;;
    tests/rsync-compat/*|scripts/rsync-compat.py)
      conformance=true
      ;;
    tests/fixtures/*)
      # The same protocol fixtures are consumed by Rust and Python tests.
      native=true
      sdks=true
      ;;
    Cargo.toml|Cargo.lock|rust-toolchain.toml|build.rs|src/*|tests/*.rs|schemas/*)
      native=true
      ;;
    .github/workflows/ci.yml)
      tooling=true
      sdks=true
      conformance=true
      macos=true
      linux_arm64=true
      ;;
    .github/workflows/rsync-compat.yml)
      tooling=true
      conformance=true
      ;;
    .github/workflows/prepare-python-sdk.yml|.github/workflows/publish-sdks.yml|.github/workflows/python-api-sync.yml)
      tooling=true
      sdks=true
      ;;
    scripts/generate-homebrew-formula.sh|scripts/test-homebrew-formula.sh|scripts/generate-installer.sh|scripts/test-installer.sh)
      tooling=true
      macos=true
      ;;
    scripts/*|.github/workflows/*|.env.release|deny.toml)
      tooling=true
      ;;
    *.md|docs/*|use-cases/*|.github/ISSUE_TEMPLATE/*|.github/dependabot.yml|LICENSE|.gitignore|.claude/*)
      ;;
    *)
      # Unknown inputs fail safe until their dependency boundary is explicit.
      native=true
      sdks=true
      tooling=true
      mapping_docs=true
      conformance=true
      macos=true
      linux_arm64=true
      ;;
  esac
done <<<"$changed_paths"

if [ "$saw_path" = false ]; then
  native=true
  sdks=true
  tooling=true
  mapping_docs=true
  conformance=true
  macos=true
  linux_arm64=true
fi

# Pull requests run affected fast checks. The cumulative master state gets the
# broad cross-subsystem and platform suites once after merge.
if [ "$full_suite" = true ] && [ "$native" = true ]; then
  sdks=true
  conformance=true
  macos=true
  linux_arm64=true
fi

printf 'native=%s\nsdks=%s\ntooling=%s\nmapping_docs=%s\nconformance=%s\nmacos=%s\nlinux_arm64=%s\nfull_suite=%s\n' \
  "$native" "$sdks" "$tooling" "$mapping_docs" "$conformance" "$macos" "$linux_arm64" "$full_suite"
echo "CI scope: native=$native sdks=$sdks tooling=$tooling mapping_docs=$mapping_docs conformance=$conformance macos=$macos linux_arm64=$linux_arm64 full_suite=$full_suite" >&2
