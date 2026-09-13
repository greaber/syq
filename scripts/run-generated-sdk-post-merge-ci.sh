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

# Updating the Git ref and resolving it in Actions can briefly disagree. Track
# the run returned by this dispatch, never an older run found by listing runs.
# Retry only a stale SHA; a failure on the requested commit is a real failure.
for attempt in 1 2 3; do
  reference=$(gh api "repos/$repository/git/ref/heads/$branch")
  reference_sha=$(jq -er .object.sha <<<"$reference")
  [ "$reference_sha" = "$merge_sha" ] || {
    echo "generated branch $branch does not point to expected merge commit $merge_sha (found $reference_sha)" >&2
    exit 1
  }
  dispatch=$(gh api --method POST \
    -H 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$repository/actions/workflows/ci.yml/dispatches" \
    -f ref="$branch" \
    -f "inputs[scope_commit]=$merge_sha")
  ci_run_id=$(jq -er '.workflow_run_id | select(type == "number" and . > 0 and . == floor)' <<<"$dispatch")
  run=$(gh api "repos/$repository/actions/runs/$ci_run_id")
  jq -e --argjson id "$ci_run_id" --arg repository "$repository" --arg branch "$branch" '
    .id == $id and .event == "workflow_dispatch" and
    .head_repository.full_name == $repository and .head_branch == $branch
  ' <<<"$run" >/dev/null || {
    echo "ci.yml dispatch returned an unexpected workflow run: $run" >&2
    exit 1
  }
  run_sha=$(jq -er '.head_sha | select(test("^[0-9a-f]{40}$"))' <<<"$run")
  if [ "$run_sha" = "$merge_sha" ]; then
    echo "Dispatched ci.yml run $ci_run_id for $merge_sha"
    gh run watch "$ci_run_id" --repo "$repository" --exit-status
    break
  fi

  echo "ci.yml dispatch attempt $attempt/3 started run $ci_run_id at stale commit $run_sha; expected $merge_sha" >&2
  # The scope guard rejects this run. Let it finish before creating another;
  # watch's failure is expected, but an API/monitor failure cannot prove it ended.
  gh run watch "$ci_run_id" --repo "$repository" --exit-status || true
  run=$(gh api "repos/$repository/actions/runs/$ci_run_id")
  [ "$(jq -er .status <<<"$run")" = completed ] || {
    echo "stale ci.yml run $ci_run_id is not completed; refusing another dispatch" >&2
    exit 1
  }
  [ "$attempt" -lt 3 ] || {
    echo "ci.yml dispatch still selected $run_sha instead of $merge_sha after 3 attempts (last run $ci_run_id)" >&2
    exit 1
  }
  echo "Stale run $ci_run_id finished; retrying dispatch in 5 seconds" >&2
  sleep 5
done

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
