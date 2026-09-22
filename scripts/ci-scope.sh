#!/usr/bin/env bash
# Classify a GitHub Actions change set for post-merge and manual validation.
set -euo pipefail

event_path=${1:-${GITHUB_EVENT_PATH:-}}
changed_paths=
full_suite=false
integration_targets=
tooling_checks=
all_tooling="package installer benchmark release orchestration focused branch workflows"

run_everything() {
  printf '%s\n' \
    'native=true' \
    'sdks=true' \
    'python_sdk=true' \
    'javascript_sdk=true' \
    'go_sdk=true' \
    'tooling=true' \
    "tooling_checks=$all_tooling" \
    'shellcheck=true' \
    'mapping_docs=true' \
    'conformance=true' \
    'macos=true' \
    'linux_arm64=true' \
    'full_suite=true' \
    'sdk_matrix=["python","javascript","go"]'
}

if [ -n "${SYQ_TEST_CHANGED_PATHS_FILE:-}" ]; then
  changed_paths=$(cat "$SYQ_TEST_CHANGED_PATHS_FILE")
elif [ -n "$event_path" ] && [ -f "$event_path" ] &&
    jq -e 'has("schedule")' "$event_path" >/dev/null; then
  script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
  if python3 "$script_dir/nightly-ci.py"; then
    run_everything
    exit 0
  else
    status=$?
    [ "$status" = 3 ] || exit "$status"
    # No changed test inputs: emit the ordinary all-false scope below.
    changed_paths=README.md
  fi
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
    tests/local.rs|tests/local/*) integration_targets+=" local" ;;
    tests/help.rs|tests/help/*) integration_targets+=" help" ;;
    tests/output.rs|tests/output/*) integration_targets+=" output" ;;
    tests/update.rs|tests/update/*) integration_targets+=" update" ;;
    tests/return_handoff.rs|tests/return_handoff/*) integration_targets+=" return_handoff" ;;
    tests/s3.rs|tests/s3/*) integration_targets+=" s3" ;;
    tests/build_identity.rs) integration_targets+=" build_identity" ;;
    tests/temp_paths.rs) integration_targets+=" temp_paths" ;;
    tests/macos_exfat.rs) integration_targets+=" macos_exfat" ;;
    tests/support/*|tests/fixtures/*) integration_targets+=" all" ;;
  esac
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
    src/*macos*|tests/macos*)
      native=true
      macos=true
      ;;
    rust-toolchain.toml|build.rs|src/*|tests/*.rs|schemas/*)
      native=true
      ;;
    .github/workflows/*)
      tooling=true
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
    scripts/*|deny.toml)
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
  case "$path" in
    .github/workflows/*|scripts/check-workflows.sh)
      tooling_checks+=" workflows orchestration"
      ;;
    Cargo.toml|Cargo.lock|rust-toolchain.toml)
      if [ "$preparation_only" != true ]; then tooling_checks+=" package"; fi
      ;;
    scripts/test-cargo-package.sh|build.rs|src/identity.rs|tests/build_identity.rs)
      tooling_checks+=" package"
      ;;
    scripts/generate-installer.sh|scripts/test-installer.sh)
      tooling_checks+=" installer"
      ;;
    scripts/try-benchmark*|scripts/test-try-benchmark.py)
      tooling_checks+=" benchmark"
      ;;
    scripts/run-focused-check.py|scripts/test-run-focused-check.py)
      tooling_checks+=" focused"
      ;;
    scripts/branch-status.sh|scripts/test-branch-status.sh)
      tooling_checks+=" branch"
      ;;
    scripts/verify-release-ci.sh)
      tooling_checks+=" release orchestration"
      ;;
    scripts/test-release-tools.sh|scripts/package-release.sh|scripts/verify-crates-io-package.sh|scripts/verify-release-*|scripts/generate-release-*|scripts/sign-release-*)
      tooling_checks+=" release"
      ;;
    scripts/ci-scope.sh|scripts/*release-orchestration*|scripts/release-preflight.sh|scripts/release-status.sh|scripts/release-readiness.py|scripts/release-timings.py|scripts/release_test_inputs.py|scripts/release-tag-signers|scripts/find-release-build.py|scripts/nightly-ci.py|scripts/test-release-readiness.py|scripts/test-release-timings.py|scripts/test-release-test-inputs.py|scripts/test-find-release-build.py|scripts/test-nightly-ci.py|scripts/*generated-sdk-post-merge-ci.sh)
      tooling_checks+=" orchestration"
      ;;
    scripts/rsync-compat.py) ;;
    scripts/*|deny.toml)
      # Retain broad coverage for tooling whose ownership is not yet mapped.
      tooling_checks+=" $all_tooling"
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

# Unknown non-script inputs retain the existing broad fallback.
if [ "$tooling" = true ] && [ -z "$tooling_checks" ]; then
  tooling_checks=$all_tooling
fi
if [ -n "$tooling_checks" ]; then tooling=true; fi
# Sort and deduplicate so equivalent selections share a cancellation group.
read -r -a selected_tooling <<< "$tooling_checks"
tooling_checks=$(printf '%s\n' "${selected_tooling[@]}" | sed '/^$/d' | sort -u | paste -sd ' ' -)
printf 'tooling_checks=%s\n' "$tooling_checks"

if [ "$python_sdk" = true ] || [ "$javascript_sdk" = true ] || [ "$go_sdk" = true ]; then
  sdks=true
fi

printf 'native=%s\nsdks=%s\npython_sdk=%s\njavascript_sdk=%s\ngo_sdk=%s\ntooling=%s\nshellcheck=%s\nmapping_docs=%s\nconformance=%s\nmacos=%s\nlinux_arm64=%s\nfull_suite=%s\n' \
  "$native" "$sdks" "$python_sdk" "$javascript_sdk" "$go_sdk" \
  "$tooling" "$shellcheck" "$mapping_docs" "$conformance" "$macos" \
  "$linux_arm64" "$full_suite"
# Canonicalize selections so equivalent changes share a cancellation group.
read -r -a selected_targets <<< "$integration_targets"
integration_targets=$(printf '%s\n' "${selected_targets[@]}" | LC_ALL=C sort -u | paste -sd ' ' -)
printf 'integration_targets=%s\n' "$integration_targets"
echo "CI scope: native=$native sdks=$sdks python_sdk=$python_sdk javascript_sdk=$javascript_sdk go_sdk=$go_sdk tooling=$tooling shellcheck=$shellcheck mapping_docs=$mapping_docs conformance=$conformance macos=$macos linux_arm64=$linux_arm64 full_suite=$full_suite" >&2

jq -cn --argjson python "$python_sdk" --argjson javascript "$javascript_sdk" --argjson go "$go_sdk" \
  '[$python, $javascript, $go] as $enabled | [range(3) | select($enabled[.]) | ["python", "javascript", "go"][.]] | if length == 0 then ["none"] else . end' | \
  sed 's/^/sdk_matrix=/'
