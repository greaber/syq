#!/usr/bin/env bash
# Require an explicit full CI certification for one exact release commit.
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

if [ "$#" -ne 2 ]; then
  echo "usage: $0 OWNER/REPOSITORY COMMIT" >&2
  exit 2
fi
repository=$1
commit=$2
case "$repository" in
  */*) ;;
  *) echo "invalid GitHub repository: $repository" >&2; exit 2 ;;
esac
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "invalid release commit: $commit" >&2; exit 2; }
command -v gh >/dev/null || die 'release CI verification needs gh'
command -v jq >/dev/null || die 'release CI verification needs jq'

for workflow in ci.yml rsync-compat.yml; do
  runs=$(gh api \
    "repos/$repository/actions/workflows/$workflow/runs?event=workflow_dispatch&head_sha=$commit&per_page=100")
  latest=$(jq -c --arg commit "$commit" '
    [.workflow_runs[]? |
      select(.head_sha == $commit and .event == "workflow_dispatch")] |
    sort_by([(.run_number // 0), (.run_attempt // 0)]) |
    last // empty
  ' <<<"$runs")
  [ -n "$latest" ] \
    || die "full release CI workflow $workflow has no workflow_dispatch run on $commit"
  status=$(jq -r '.status // "unknown"' <<<"$latest")
  conclusion=$(jq -r '.conclusion // "pending"' <<<"$latest")
  if [ "$status" != completed ] || [ "$conclusion" != success ]; then
    die "latest full release CI workflow $workflow is $status/$conclusion on $commit"
  fi
  run_id=$(jq -er .id <<<"$latest")
  printf 'Full release CI: %s run %s succeeded on %s.\n' \
    "$workflow" "$run_id" "$commit"
done
