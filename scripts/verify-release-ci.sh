#!/usr/bin/env bash
# Require an explicit full CI certification for one exact release commit.
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

json=false
if [ "${1:-}" = --json ]; then json=true; shift; fi
if [ "$#" -ne 2 ]; then
  echo "usage: $0 [--json] OWNER/REPOSITORY COMMIT" >&2
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

report='[]'
ready=true
for workflow in ci.yml rsync-compat.yml macos.yml; do
  runs=$(gh api --paginate --slurp \
    "repos/$repository/actions/workflows/$workflow/runs?head_sha=$commit&per_page=100") || exit 2
  latest=$(jq -c --arg commit "$commit" --arg repository "$repository" '
    [.[].workflow_runs[]? |
      select(.head_sha == $commit and .head_branch == "master"
        and .head_repository.full_name == $repository
        and (.event == "workflow_dispatch" or .event == "push"))] |
    sort_by([(.run_number // 0), (.run_attempt // 0)]) |
    last // null
  ' <<<"$runs") || exit 2
  run_id=$(jq '.id // null' <<<"$latest")
  attempt=$(jq '.run_attempt // null' <<<"$latest")
  url=$(jq -r '.html_url // ""' <<<"$latest")
  state=dispatch
  message="full release CI workflow $workflow has no push or workflow_dispatch run on master on $commit"
  if [ "$latest" != null ]; then
    status=$(jq -r '.status // "unknown"' <<<"$latest")
    conclusion=$(jq -r '.conclusion // "pending"' <<<"$latest")
    message="latest full release CI workflow $workflow is $status/$conclusion on $commit"
    if [ "$status" != completed ]; then
      state="wait"
    elif [ "$conclusion" != success ]; then
      state=repair
    else
      # Never borrow the certificate from a previous run attempt.
      jobs=$(gh api --paginate --slurp \
        "repos/$repository/actions/runs/$run_id/attempts/$attempt/jobs?per_page=100") || exit 2
      if jq -e '
        [.[].jobs[]? | select(.name == "release-certification")] |
        length == 1 and all(.[]; .status == "completed" and .conclusion == "success")
      ' <<<"$jobs" >/dev/null; then
        state=ready
        message="Full release CI: $workflow run $run_id succeeded on $commit."
      else
        message="workflow $workflow run $run_id attempt $attempt lacks successful full-suite release-certification on $commit; dispatch this workflow on master"
      fi
    fi
  fi
  case "$state" in
    ready) action="" ;;
    dispatch) action="gh workflow run $workflow --repo $repository --ref master" ;;
    wait) action="gh run watch $run_id --repo $repository --exit-status" ;;
    repair) action="gh run view $run_id --repo $repository --log-failed" ;;
  esac
  report=$(jq -c --arg workflow "$workflow" --arg state "$state" \
    --argjson run_id "$run_id" --argjson attempt "$attempt" --arg url "$url" \
    --arg message "$message" --arg action "$action" \
    '. + [{workflow:$workflow,state:$state,run_id:$run_id,attempt:$attempt,
      url:$url,message:$message,next_action:$action}]' <<<"$report")
  if [ "$state" != ready ]; then ready=false; fi
  if [ "$json" = false ]; then
    if [ "$state" = ready ]; then printf '%s\n' "$message";
    else printf 'error: %s\nNext: %s\n' "$message" "$action" >&2; fi
  fi
done
if [ "$json" = true ]; then
  jq -n --arg commit "$commit" --argjson ready "$ready" --argjson workflows "$report" \
    '{commit:$commit,ready:$ready,workflows:$workflows}'
fi
[ "$ready" = true ]
