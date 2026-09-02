#!/usr/bin/env bash
# Classify a GitHub Actions change set without removing any required check.
set -euo pipefail

event_path=${1:-${GITHUB_EVENT_PATH:-}}
changed_paths=

if [ -n "${SYQ_TEST_CHANGED_PATHS_FILE:-}" ]; then
  changed_paths=$(cat "$SYQ_TEST_CHANGED_PATHS_FILE")
elif [ -n "$event_path" ] && [ -f "$event_path" ]; then
  event_name=$(jq -r 'if has("pull_request") then "pull_request" elif has("before") then "push" else "workflow_dispatch" end' "$event_path")
  case "$event_name" in
    pull_request)
      base=$(jq -er .pull_request.base.sha "$event_path")
      head=$(jq -er .pull_request.head.sha "$event_path")
      ;;
    push)
      base=$(jq -er .before "$event_path")
      head=$(jq -er .after "$event_path")
      if [[ "$base" =~ ^0+$ ]]; then
        printf 'native=true\nsdks=true\nconformance=true\n'
        echo 'CI scope: new branch or incomplete push history; running every check' >&2
        exit 0
      fi
      ;;
    workflow_dispatch)
      printf 'native=true\nsdks=true\nconformance=true\n'
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
  changed_paths=$(git diff --name-only "$base" "$head")
else
  echo "usage: $0 GITHUB_EVENT_PATH" >&2
  exit 2
fi

native=false
sdks=false
saw_path=false
while IFS= read -r path; do
  [ -n "$path" ] || continue
  saw_path=true
  case "$path" in
    sdk/*)
      sdks=true
      ;;
    *.md|docs/*|.github/ISSUE_TEMPLATE/*|.github/dependabot.yml|LICENSE)
      ;;
    *)
      native=true
      sdks=true
      ;;
  esac
done <<<"$changed_paths"

if [ "$saw_path" = false ]; then
  native=true
  sdks=true
fi

printf 'native=%s\nsdks=%s\nconformance=%s\n' "$native" "$sdks" "$native"
echo "CI scope: native=$native sdks=$sdks conformance=$native" >&2
