#!/usr/bin/env bash
# Classify a GitHub Actions change set for post-merge and manual validation.
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
elif [ "${SYQ_CI_DOCUMENTATION_ONLY:-}" = true ]; then
  changed_paths=$'docs/mappings.md\ndocs/automation.md\ndocs/commands/map.md'
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
      # A generated SDK follow-up uses a workflow dispatch because GitHub does
      # not trigger push workflows for merges made with GITHUB_TOKEN. It passes
      # the checked-out merge commit so this path has the same precise scope as
      # a normal push. Other manual runs retain the full-suite default.
      if [ -z "${SYQ_CI_SCOPE_COMMIT:-}" ]; then
        run_everything
        echo 'CI scope: manual run; running every check' >&2
        exit 0
      fi
      [[ "$SYQ_CI_SCOPE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
        echo "invalid CI scope commit: $SYQ_CI_SCOPE_COMMIT" >&2
        exit 2
      }
      head=$(git rev-parse HEAD)
      [ "$head" = "$SYQ_CI_SCOPE_COMMIT" ] || {
        echo "CI scope commit $SYQ_CI_SCOPE_COMMIT is not checked out (found $head)" >&2
        exit 1
      }
      base=$(git rev-parse "$head^")
      diff_range="$base..$head"
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

preparation_only=false
if [ -n "${base:-}" ] && [ -n "${head:-}" ]; then
  script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
  if python3 "$script_dir/release_test_inputs.py" "$head" --native --equivalent-to "$base"; then
    preparation_only=true
  fi
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
  # Shell lint is cheap and independent of the path's product surface.
  # Keep it selected even when the case below deliberately ignores the path.
  if [[ "$path" == *.sh ]]; then
    shellcheck=true
  fi
  case "$path" in
    sdk/README.md|sdk/RELEASING.md|sdk/python/README-PYTHON.md|sdk/python/NATIVE_API.md|sdk/python/API_DESIGN.md|sdk/js/README.md|sdk/go/README.md)
      # These are prose, not executable SDK test inputs. Keep the exception
      # explicit: native-api.json is compiled into Rust, and files elsewhere
      # in an SDK (including future Markdown fixtures) still select its tests.
      ;;
    book.toml|theme/*|.agents/*)
      # Documentation rendering and agent guidance do not affect the product
      # suites. Pages validates the book/theme; shell files still get linted.
      ;;
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
    MAPPINGS.md|docs/mappings.md|docs/automation.md|docs/commands/map.md)
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
    Cargo.toml|Cargo.lock)
      if [ "$preparation_only" != true ]; then native=true; fi
      ;;
    rust-toolchain.toml|build.rs|src/*|tests/*.rs|schemas/*)
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
    nix/python-dist.nix|scripts/build-python-dist.sh|scripts/package-python-wheel.py|scripts/pin-python-native-source.sh|scripts/normalize-python-wheel.py|scripts/check-python-api-sync.py|scripts/normalize-python-sdist.py|scripts/check-python-wheel.py|scripts/stage-python-sdk.py|scripts/prepare-python-sdk-release.py|scripts/run-generated-sdk-post-merge-ci.sh|scripts/select-trusted-pr.jq|scripts/test-python-sdk-release-tools.sh|scripts/test-python-release-preparation.py)
      tooling=true
      python_sdk=true
      ;;
    scripts/generate-homebrew-formula.sh|scripts/test-homebrew-formula.sh|scripts/generate-installer.sh|scripts/test-installer.sh)
      tooling=true
      ;;
    tests/real-ssh/*)
      ;;
    scripts/*|.github/workflows/*|deny.toml)
      tooling=true
      ;;
    *.md|docs/*|.github/ISSUE_TEMPLATE/*|.github/dependabot.yml|LICENSE|.gitignore|.claude/*)
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

# The cumulative master state gets broad cross-subsystem and platform coverage
# once after merge.
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
