#!/usr/bin/env bash
# Report the state of the current task branch: the worktree, the branch's
# pull request, and the latest post-merge CI runs on master. Its output is
# what a status report or review request should state.
#
# Only reads git and GitHub state. With --check it also runs the fixed Rust
# baseline (fmt, clippy, unit tests) in this worktree.
#
# Exit status: 0 when nothing needs attention; 1 when master's latest
# post-merge run failed, the pull request's checks failed, the GitHub head is
# stale or unrelated, or a --check step failed; 2 on usage or tooling errors.
set -euo pipefail

repository=greaber/syq
workflows=(ci.yml rsync-compat.yml macos.yml)
json=false
check=false
for argument in "$@"; do
  case "$argument" in
    --json) json=true ;;
    --check) check=true ;;
    *) echo "usage: $0 [--json] [--check]" >&2; exit 2 ;;
  esac
done
for command in git gh jq; do
  command -v "$command" >/dev/null || { echo "branch status needs $command" >&2; exit 2; }
done

warnings=()
warn() { warnings+=("$1"); }

# Worktree and branch.
toplevel=$(git rev-parse --show-toplevel)
head_sha=$(git rev-parse HEAD)
short_sha=$(git rev-parse --short HEAD)
branch=$(git symbolic-ref --quiet --short HEAD || echo HEAD)
status_lines=$(git status --porcelain --untracked-files=all)
staged=$(grep -c '^[MADRCT]' <<<"$status_lines" || true)
unstaged=$(grep -c '^.[MADRCT]' <<<"$status_lines" || true)
untracked=$(grep -c '^??' <<<"$status_lines" || true)
if [ -z "$status_lines" ]; then clean=true; else clean=false; fi
[ "$clean" = true ] || warn "worktree is dirty: $staged staged, $unstaged unstaged, $untracked untracked"

upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)
upstream_ahead=null
upstream_behind=null
if [ -n "$upstream" ]; then
  read -r upstream_ahead upstream_behind < <(git rev-list --left-right --count "HEAD...$upstream")
fi

master_ref=
for candidate in refs/heads/master refs/remotes/origin/master; do
  if git rev-parse --verify --quiet "$candidate^{commit}" >/dev/null; then master_ref=$candidate; break; fi
done
master_sha=null
master_short=
behind_master=null
ahead_of_master=null
if [ -n "$master_ref" ]; then
  master_sha=$(git rev-parse "$master_ref")
  master_short=$(git rev-parse --short "$master_ref")
  read -r ahead_of_master behind_master < <(git rev-list --left-right --count "HEAD...$master_ref")
fi

# Latest post-merge run of each workflow on master.
master_runs='[]'
for workflow in "${workflows[@]}"; do
  if ! runs=$(gh run list --repo "$repository" --workflow "$workflow" --branch master --event push --limit 1 \
      --json headSha,status,conclusion,url,createdAt,databaseId); then
    echo "could not list $workflow runs on master" >&2
    exit 2
  fi
  run=$(jq -c 'first // null' <<<"$runs")
  state=missing
  if [ "$run" != null ]; then
    status=$(jq -r .status <<<"$run")
    conclusion=$(jq -r '.conclusion // ""' <<<"$run")
    if [ "$status" = completed ]; then state=$conclusion; else state=$status; fi
  fi
  case "$state" in
    success) ;;
    missing) warn "$workflow has no post-merge run on master" ;;
    queued|in_progress|pending|waiting|requested) ;;
    *) warn "master is red: $workflow $state at $(jq -r '.headSha[0:7]' <<<"$run") $(jq -r .url <<<"$run")" ;;
  esac
  master_runs=$(jq -c --arg workflow "$workflow" --arg state "$state" --argjson run "$run" \
    '. + [{workflow:$workflow, state:$state, run:$run}]' <<<"$master_runs")
done

# The pull request for this branch, if any.
pr=null
if [ "$branch" != HEAD ]; then
  if pr_json=$(gh pr view "$branch" --repo "$repository" \
      --json number,url,state,isDraft,baseRefName,headRefOid,reviewDecision,mergeStateStatus,statusCheckRollup 2>/dev/null); then
    pr=$pr_json
  fi
fi
pr_head_relation=none
if [ "$pr" != null ]; then
  pr_head=$(jq -r .headRefOid <<<"$pr")
  pr_number=$(jq -r .number <<<"$pr")
  if [ "$pr_head" = "$head_sha" ]; then
    pr_head_relation=matches
  elif git merge-base --is-ancestor "$pr_head" HEAD 2>/dev/null; then
    pr_head_relation=github-behind
    warn "PR #$pr_number head ${pr_head:0:7} is behind local $short_sha; push before reporting"
  elif git merge-base --is-ancestor "$head_sha" "$pr_head" 2>/dev/null; then
    pr_head_relation=local-behind
    warn "local $short_sha is behind PR #$pr_number head ${pr_head:0:7}"
  else
    pr_head_relation=unrelated
    warn "PR #$pr_number head ${pr_head:0:7} is not related to local $short_sha"
  fi
  failed_checks=$(jq -r '[.statusCheckRollup[]? |
    select((.conclusion // "") as $c | ($c | ascii_upcase) as $u |
      ($u != "SUCCESS" and $u != "SKIPPED" and $u != "NEUTRAL" and $u != "")) |
    (.name // .context) + " " + (.conclusion | ascii_downcase)] | join(", ")' <<<"$pr")
  [ -z "$failed_checks" ] || warn "PR #$pr_number checks: $failed_checks"
  pending_checks=$(jq -r '[.statusCheckRollup[]? |
    select((.conclusion // "") == "" and ((.status // "") | ascii_upcase) != "COMPLETED") |
    (.name // .context)] | join(", ")' <<<"$pr")
fi

# Optional fixed Rust baseline.
checks='[]'
if [ "$check" = true ]; then
  run_check() {
    local name=$1; shift
    local result=pass
    if ! (cd "$toplevel" && "$@"); then result=fail; warn "$name failed"; fi
    checks=$(jq -c --arg name "$name" --arg command "$*" --arg result "$result" \
      '. + [{name:$name, command:$command, result:$result}]' <<<"$checks")
  }
  run_check fmt cargo fmt --all -- --check
  run_check clippy cargo clippy --all-targets --all-features -- -D warnings
  run_check unit-tests cargo test --bin syq
fi

exit_status=0
[ "${#warnings[@]}" -eq 0 ] || exit_status=1
# A dirty worktree is worth stating but is not by itself a problem.
if [ "${#warnings[@]}" -eq 1 ] && [[ "${warnings[0]}" == 'worktree is dirty'* ]]; then exit_status=0; fi

warnings_json='[]'
for warning in "${warnings[@]+"${warnings[@]}"}"; do
  warnings_json=$(jq -c --arg warning "$warning" '. + [$warning]' <<<"$warnings_json")
done

if [ "$json" = true ]; then
  jq -n \
    --arg toplevel "$toplevel" --arg branch "$branch" --arg head "$head_sha" --arg short "$short_sha" \
    --argjson clean "$clean" --argjson staged "$staged" --argjson unstaged "$unstaged" --argjson untracked "$untracked" \
    --arg upstream "$upstream" --argjson upstream_ahead "$upstream_ahead" --argjson upstream_behind "$upstream_behind" \
    --arg master_ref "$master_ref" --arg master_sha "$master_sha" \
    --argjson ahead_of_master "$ahead_of_master" --argjson behind_master "$behind_master" \
    --argjson master_runs "$master_runs" --argjson pr "$pr" --arg pr_head_relation "$pr_head_relation" \
    --argjson checks "$checks" --argjson warnings "$warnings_json" \
    --argjson exit_status "$exit_status" \
    '{worktree:{path:$toplevel, branch:$branch, head:$head, short:$short, clean:$clean,
       staged:$staged, unstaged:$unstaged, untracked:$untracked,
       upstream:(if $upstream == "" then null else $upstream end),
       ahead_of_upstream:$upstream_ahead, behind_upstream:$upstream_behind,
       master_ref:(if $master_ref == "" then null else $master_ref end),
       master:(if $master_sha == "null" then null else $master_sha end),
       ahead_of_master:$ahead_of_master, behind_master:$behind_master},
      master_ci:$master_runs, pull_request:$pr, pull_request_head:$pr_head_relation,
      checks:$checks, warnings:$warnings, exit_status:$exit_status}'
  exit "$exit_status"
fi

echo "Worktree: $toplevel"
if [ "$clean" = true ]; then
  echo "Branch:   $branch at $short_sha (clean)"
else
  echo "Branch:   $branch at $short_sha (dirty: $staged staged, $unstaged unstaged, $untracked untracked)"
fi
if [ -n "$upstream" ]; then
  echo "Upstream: $upstream (ahead $upstream_ahead, behind $upstream_behind)"
else
  echo "Upstream: none"
fi
if [ -n "$master_ref" ]; then
  echo "Master:   $master_short from $master_ref (branch is ahead $ahead_of_master, behind $behind_master)"
else
  echo "Master:   no local master ref"
fi
echo
echo "Master CI (latest post-merge run per workflow):"
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  workflow=$(jq -r .workflow <<<"$entry")
  state=$(jq -r .state <<<"$entry")
  if [ "$(jq -r .run <<<"$entry")" = null ]; then
    printf '  %-16s %-12s (no run)\n' "$workflow" "$state"
  else
    printf '  %-16s %-12s %s  %s\n' "$workflow" "$state" \
      "$(jq -r '.run.headSha[0:7]' <<<"$entry")" "$(jq -r .run.url <<<"$entry")"
  fi
done < <(jq -c '.[]' <<<"$master_runs")
echo
if [ "$pr" = null ]; then
  echo "Pull request: none for $branch"
else
  echo "Pull request: #$(jq -r .number <<<"$pr") $(jq -r .url <<<"$pr")"
  echo "  base $(jq -r .baseRefName <<<"$pr"), $(jq -r 'if .isDraft then "draft" else .state | ascii_downcase end' <<<"$pr"), review $(jq -r '.reviewDecision // "" | if . == "" then "none" else ascii_downcase end' <<<"$pr"), merge state $(jq -r '.mergeStateStatus // "unknown" | ascii_downcase' <<<"$pr")"
  echo "  GitHub head $(jq -r '.headRefOid[0:7]' <<<"$pr"): $pr_head_relation local $short_sha"
  if [ -n "$failed_checks" ]; then
    echo "  failed checks: $failed_checks"
  elif [ -n "$pending_checks" ]; then
    echo "  pending checks: $pending_checks"
  else
    echo "  checks: all completed successfully"
  fi
fi
if [ "$check" = true ]; then
  echo
  echo "Baseline checks:"
  jq -r '.[] | "  \(.name): \(.result)  (\(.command))"' <<<"$checks"
fi
if [ "${#warnings[@]}" -gt 0 ]; then
  echo
  for warning in "${warnings[@]}"; do echo "WARNING: $warning"; done
fi
exit "$exit_status"
