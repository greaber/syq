#!/usr/bin/env bash
# Dispatch and await Python SDK validation on one generated SDK commit.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 OWNER/REPOSITORY BRANCH MERGE_SHA" >&2
  exit 2
fi
repository=$1
branch=$2
merge_sha=$3
trusted_repository=${SYQ_TRUSTED_REPOSITORY:-greaber/syq}

[ "$repository" = "$trusted_repository" ] || {
  echo "refusing generated-SDK CI dispatch for $repository; expected $trusted_repository" >&2
  exit 1
}
[[ "$branch" =~ ^automation/python-sdk-v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "unsafe generated branch: $branch" >&2
  exit 2
}
[[ "$merge_sha" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid merge commit: $merge_sha" >&2
  exit 2
}
command -v gh >/dev/null || { echo 'post-merge CI dispatch needs gh' >&2; exit 1; }
command -v jq >/dev/null || { echo 'post-merge CI dispatch needs jq' >&2; exit 1; }

reference=$(gh api "repos/$repository/git/ref/heads/$branch")
reference_sha=$(jq -er .object.sha <<<"$reference")
[ "$reference_sha" = "$merge_sha" ] || {
  echo "generated branch $branch does not point to expected merge commit $merge_sha (found $reference_sha)" >&2
  exit 1
}

workflows=(ci.yml)
poll_attempts=${SYQ_POST_MERGE_POLL_ATTEMPTS:-30}
[[ "$poll_attempts" =~ ^[1-9][0-9]*$ ]] || { echo "invalid poll attempt count" >&2; exit 2; }
run_ids=()
for workflow in "${workflows[@]}"; do
  gh api --method POST \
    -H 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$repository/actions/workflows/$workflow/dispatches" \
    -f ref="$branch" \
    -f "inputs[scope_commit]=$merge_sha" >/dev/null
  run_id=
  for ((attempt = 1; attempt <= poll_attempts; attempt++)); do
    runs=$(gh api "repos/$repository/actions/workflows/$workflow/runs?event=workflow_dispatch&branch=$branch&per_page=100")
    run_id=$(jq -r --arg sha "$merge_sha" '
      [.workflow_runs[] | select(.event == "workflow_dispatch" and .head_sha == $sha)]
      | sort_by(.created_at) | last | .id // empty
    ' <<<"$runs")
    [[ "$run_id" =~ ^[0-9]+$ ]] && break
    sleep 1
  done
  [[ "$run_id" =~ ^[0-9]+$ ]] || {
    echo "$workflow dispatch did not create a workflow_dispatch run for $merge_sha within $poll_attempts seconds" >&2
    exit 1
  }
  run_ids+=("$run_id")
  echo "Dispatched $workflow run $run_id for $merge_sha"
done

for index in "${!workflows[@]}"; do
  workflow=${workflows[$index]}
  run_id=${run_ids[$index]}
  gh run watch "$run_id" --repo "$repository" --exit-status
  echo "$workflow run $run_id passed for $merge_sha"
done

ci_run_id=${run_ids[0]}
jobs=$(gh api "repos/$repository/actions/runs/$ci_run_id/jobs?per_page=100")
sdk_state=$(jq -c '
  [.jobs[] | select(.name == "sdks")] |
  if length == 1 then
    {count: 1, status: .[0].status, conclusion: (.[0].conclusion // "pending")}
  else
    {count: length, status: "ambiguous", conclusion: "missing"}
  end
' <<<"$jobs")
sdk_count=$(jq -er .count <<<"$sdk_state")
sdk_status=$(jq -er .status <<<"$sdk_state")
sdk_conclusion=$(jq -er .conclusion <<<"$sdk_state")
if [ "$sdk_count" -ne 1 ] || [ "$sdk_status" != completed ] || \
  [ "$sdk_conclusion" != success ]; then
    echo "ci.yml run $ci_run_id sdks job is $sdk_status/$sdk_conclusion (count $sdk_count)" >&2
    exit 1
fi

echo "Post-merge Python SDK validation passed for $merge_sha"
