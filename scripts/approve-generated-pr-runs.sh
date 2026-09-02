#!/usr/bin/env bash
# Approve only the native PR runs belonging to one exact trusted generated PR,
# then require the substantive SDK check to pass on that same head.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 OWNER/REPOSITORY BRANCH HEAD_SHA" >&2
  exit 2
fi
repository=$1
branch=$2
head_sha=$3
trusted_repository=${SYQ_TRUSTED_REPOSITORY:-greaber/syq}
timeout_seconds=${SYQ_APPROVAL_TIMEOUT_SECONDS:-60}
interval_seconds=${SYQ_APPROVAL_INTERVAL_SECONDS:-5}
check_timeout_seconds=${SYQ_REQUIRED_CHECK_TIMEOUT_SECONDS:-900}

[ "$repository" = "$trusted_repository" ] || {
  echo "refusing generated-PR approval for $repository; expected $trusted_repository" >&2
  exit 1
}
[[ "$branch" =~ ^automation/python-sdk-v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "unsafe generated branch: $branch" >&2
  exit 2
}
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid generated head SHA: $head_sha" >&2
  exit 2
}
[[ "$timeout_seconds" =~ ^[0-9]+$ ]] || {
  echo "invalid approval timeout: $timeout_seconds" >&2
  exit 2
}
[[ "$check_timeout_seconds" =~ ^[0-9]+$ ]] || {
  echo "invalid required-check timeout: $check_timeout_seconds" >&2
  exit 2
}
if ! [[ "$interval_seconds" =~ ^[0-9]+$ ]] || [ "$interval_seconds" -le 0 ]; then
  echo "invalid approval interval: $interval_seconds" >&2
  exit 2
fi
command -v gh >/dev/null || { echo 'generated-PR approval needs gh' >&2; exit 1; }
command -v jq >/dev/null || { echo 'generated-PR approval needs jq' >&2; exit 1; }

owner=${repository%%/*}
pulls=$(gh api --method GET "repos/$repository/pulls" \
  -f state=open -f head="$owner:$branch" -f per_page=100)
trusted_count=$(jq --arg repository "$repository" --arg branch "$branch" \
  --arg head_sha "$head_sha" '[.[] | select(
    .head.repo.full_name == $repository and .head.ref == $branch and
    .head.sha == $head_sha and .base.ref == "master"
  )] | length' <<<"$pulls")
[ "$trusted_count" -eq 1 ] || {
  echo "expected one trusted open pull request for $repository:$branch at $head_sha; found $trusted_count" >&2
  exit 1
}

deadline=$((SECONDS + timeout_seconds))
observed='[]'
while :; do
  observed=$(gh run list --repo "$repository" --branch "$branch" \
    --event pull_request --limit 20 \
    --json conclusion,databaseId,event,headSha,status,url,workflowName)
  if jq -e --arg head_sha "$head_sha" '
    . as $runs |
    all(["ci", "rsync compatibility"][];
      . as $workflow |
      any($runs[]; .headSha == $head_sha and .event == "pull_request" and
        .workflowName == $workflow))
  ' <<<"$observed" >/dev/null; then
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "timed out waiting for native pull-request workflow runs for $head_sha; last observed state:" >&2
    jq -c . <<<"$observed" >&2
    exit 1
  fi
  echo "Waiting for GitHub to register native pull-request workflow runs for $head_sha"
  sleep "$interval_seconds"
done

for workflow_name in ci 'rsync compatibility'; do
  run=$(jq -cer --arg head_sha "$head_sha" --arg workflow_name "$workflow_name" '
    [.[] | select(
      .headSha == $head_sha and .event == "pull_request" and
      .workflowName == $workflow_name
    )] | max_by(.databaseId)
  ' <<<"$observed")
  run_id=$(jq -er .databaseId <<<"$run")
  status=$(jq -er .status <<<"$run")
  conclusion=$(jq -r '.conclusion // empty' <<<"$run")
  case "$conclusion" in
    action_required)
      gh api --method POST "repos/$repository/actions/runs/$run_id/approve" >/dev/null
      echo "Approved $workflow_name pull-request workflow run $run_id for $head_sha"
      ;;
    success)
      echo "$workflow_name pull-request workflow run $run_id is already $status${conclusion:+/$conclusion}"
      ;;
    '')
      case "$status" in
        queued|in_progress|pending|requested|waiting)
          echo "$workflow_name pull-request workflow run $run_id is already $status"
          ;;
        *)
          echo "$workflow_name pull-request workflow run $run_id has no conclusion in unexpected status $status" >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "$workflow_name pull-request workflow run $run_id is terminal: $status/$conclusion" >&2
      exit 1
      ;;
  esac
done

check_deadline=$((SECONDS + check_timeout_seconds))
check_state='{"count":0,"status":"missing","conclusion":null}'
while :; do
  check_runs=$(gh api \
    "repos/$repository/commits/$head_sha/check-runs?filter=latest&per_page=100")
  check_state=$(jq -c '
    [.check_runs[] | select(.name == "sdks")] |
    if length == 0 then {count:0,status:"missing",conclusion:null}
    elif length > 1 then {count:length,status:"ambiguous",conclusion:null}
    else {count:1,status:.[0].status,conclusion:(.[0].conclusion // null)} end
  ' <<<"$check_runs")
  check_status=$(jq -er .status <<<"$check_state")
  check_conclusion=$(jq -r '.conclusion // empty' <<<"$check_state")
  if [ "$check_status" = completed ] && [ "$check_conclusion" = success ]; then
    echo "Required generated-PR check sdks passed for $head_sha"
    break
  fi
  if [ "$check_status" = completed ] && [ "$check_conclusion" != action_required ]; then
    echo "required generated-PR check sdks is $check_status/${check_conclusion:-missing} for $head_sha" >&2
    exit 1
  fi
  if [ "$check_status" = ambiguous ]; then
    echo "required generated-PR check sdks is ambiguous for $head_sha" >&2
    exit 1
  fi
  if [ "$SECONDS" -ge "$check_deadline" ]; then
    echo "timed out waiting for required generated-PR check sdks on $head_sha; last observed state:" >&2
    jq -c . <<<"$check_state" >&2
    exit 1
  fi
  echo "Waiting for required generated-PR check sdks on $head_sha; observed $check_status${check_conclusion:+/$check_conclusion}"
  sleep "$interval_seconds"
done
