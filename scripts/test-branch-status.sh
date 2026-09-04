#!/usr/bin/env bash
# Exercise scripts/branch-status.sh against a scratch repository and a fake gh
# that serves controlled run and pull-request JSON.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
status_script="$script_dir/branch-status.sh"

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-branch-status-test.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

fakebin="$work/fakebin"
runs_dir="$work/runs"
mkdir -p "$fakebin" "$runs_dir"
cat > "$fakebin/gh" <<'FAKE'
#!/bin/sh
case "$1:$2" in
  run:list)
    shift 2
    workflow=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --workflow) workflow=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    cat "$SYQ_TEST_RUNS_DIR/$workflow.json"
    ;;
  pr:view)
    if [ "${SYQ_TEST_PR_JSON:-}" = FAIL ]; then
      echo 'GraphQL: simulated GraphQL failure' >&2
      exit 1
    elif [ -n "${SYQ_TEST_PR_JSON:-}" ]; then
      printf '%s\n' "$SYQ_TEST_PR_JSON"
    else
      echo 'no pull requests found for branch' >&2
      exit 1
    fi
    ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 2 ;;
esac
FAKE
chmod 755 "$fakebin/gh"

# A scratch repository with master and a task branch two commits ahead.
repo="$work/repo"
git init -q -b master "$repo"
git -C "$repo" config user.email test@example.com
git -C "$repo" config user.name test
git -C "$repo" commit -q --allow-empty -m 'initial'
git -C "$repo" checkout -q -b task
git -C "$repo" commit -q --allow-empty -m 'first task commit'
git -C "$repo" commit -q --allow-empty -m 'second task commit'
head_sha=$(git -C "$repo" rev-parse HEAD)
short_sha=$(git -C "$repo" rev-parse --short HEAD)
previous_sha=$(git -C "$repo" rev-parse HEAD^)
master_sha=$(git -C "$repo" rev-parse master)

set_run() {
  local workflow=$1 status=$2 conclusion=$3
  jq -cn --arg sha "$master_sha" --arg status "$status" --arg conclusion "$conclusion" --arg workflow "$workflow" \
    '[{headSha:$sha, status:$status, conclusion:(if $conclusion == "" then null else $conclusion end),
       url:("https://example.invalid/" + $workflow), createdAt:"2026-01-01T00:00:00Z", databaseId:1}]' \
    > "$runs_dir/$workflow.json"
}
for workflow in ci.yml rsync-compat.yml macos.yml; do set_run "$workflow" completed success; done

pr_json_for_run=
run_status() {
  (cd "$repo" && SYQ_TEST_RUNS_DIR="$runs_dir" SYQ_TEST_PR_JSON="$pr_json_for_run" \
    PATH="$fakebin:$PATH" "$status_script" "$@")
}
with_pr() {
  pr_json_for_run=$1
  shift
  "$@"
  pr_json_for_run=
}

expect_exit() {
  local expected=$1
  shift
  local actual=0
  "$@" > "$work/out" 2>&1 || actual=$?
  if [ "$actual" != "$expected" ]; then
    echo "expected exit $expected, got $actual from: $*" >&2
    sed 's/^/  /' "$work/out" >&2
    exit 1
  fi
}

expect_output() {
  grep -F -- "$1" "$work/out" >/dev/null || {
    echo "output did not contain '$1':" >&2
    sed 's/^/  /' "$work/out" >&2
    exit 1
  }
}

expect_no_output() {
  if grep -F -- "$1" "$work/out" >/dev/null; then
    echo "output unexpectedly contained '$1':" >&2
    sed 's/^/  /' "$work/out" >&2
    exit 1
  fi
}

# Clean branch, green master, no pull request.
expect_exit 0 run_status
expect_output "Branch:   task at $short_sha (clean)"
expect_output 'branch is ahead 2, behind 0'
expect_output 'ci.yml           success'
expect_output 'macos.yml        success'
expect_output 'Pull request: none for task'
expect_no_output WARNING

# A pull request whose GitHub head matches the local tip and whose checks passed.
pr_json=$(jq -cn --arg head "$head_sha" '{number:7, url:"https://example.invalid/pull/7", state:"OPEN",
  isDraft:false, baseRefName:"master", headRefOid:$head, reviewDecision:"", mergeStateStatus:"CLEAN",
  statusCheckRollup:[{name:"rust", status:"COMPLETED", conclusion:"SUCCESS"},
                     {name:"macos", status:"COMPLETED", conclusion:"SKIPPED"}]}')
with_pr "$pr_json" expect_exit 0 run_status
expect_output 'Pull request: #7 https://example.invalid/pull/7'
expect_output "GitHub head ${head_sha:0:7}: matches local $short_sha"
expect_output 'checks: all completed successfully'
expect_no_output WARNING

# The GitHub head lags an unpushed local commit.
stale_pr=$(jq -c --arg head "$previous_sha" '.headRefOid = $head' <<<"$pr_json")
with_pr "$stale_pr" expect_exit 1 run_status
expect_output "GitHub head ${previous_sha:0:7}: github-behind local $short_sha"
expect_output "WARNING: PR #7 head ${previous_sha:0:7} is behind local $short_sha; push before reporting"

# A failed pull-request check.
failed_pr=$(jq -c '.statusCheckRollup[0].conclusion = "FAILURE"' <<<"$pr_json")
with_pr "$failed_pr" expect_exit 1 run_status
expect_output 'failed checks: rust failure'
expect_output 'WARNING: PR #7 checks: rust failure'

# A failed commit status context, which carries state rather than conclusion.
context_pr=$(jq -c '.statusCheckRollup += [{context:"external", state:"FAILURE"}]' <<<"$pr_json")
with_pr "$context_pr" expect_exit 1 run_status
expect_output 'failed checks: external failure'
expect_output 'WARNING: PR #7 checks: external failure'

# A pending commit status context is neither green nor a failure.
context_pr=$(jq -c '.statusCheckRollup += [{context:"external", state:"PENDING"}]' <<<"$pr_json")
with_pr "$context_pr" expect_exit 0 run_status
expect_output 'pending checks: external'
expect_no_output WARNING

# An empty rollup is not success.
empty_pr=$(jq -c '.statusCheckRollup = []' <<<"$pr_json")
with_pr "$empty_pr" expect_exit 0 run_status
expect_output 'checks: none registered yet'
expect_no_output 'all completed successfully'

# A pull-request lookup failure other than "no pull request" is an error.
with_pr FAIL expect_exit 2 run_status
expect_output 'could not look up the pull request for task'
expect_output 'simulated GraphQL failure'
expect_no_output 'Pull request: none'

# A pending pull-request check is reported without a warning.
pending_pr=$(jq -c '.statusCheckRollup[0] = {name:"rust", status:"IN_PROGRESS", conclusion:null}' <<<"$pr_json")
with_pr "$pending_pr" expect_exit 0 run_status
expect_output 'pending checks: rust'
expect_no_output WARNING

# A red post-merge run on master is the alert this script exists for.
set_run macos.yml completed failure
expect_exit 1 run_status
expect_output 'macos.yml        failure'
expect_output "WARNING: master is red: macos.yml failure at ${master_sha:0:7} https://example.invalid/macos.yml"

# A run still in progress is neither green nor an alert.
set_run macos.yml in_progress ''
expect_exit 0 run_status
expect_output 'macos.yml        in_progress'
expect_no_output WARNING
set_run macos.yml completed success

# A dirty worktree is stated but does not fail the report.
touch "$repo/scratch"
expect_exit 0 run_status
expect_output "Branch:   task at $short_sha (dirty: 0 staged, 0 unstaged, 1 untracked)"
expect_output 'WARNING: worktree is dirty: 0 staged, 0 unstaged, 1 untracked'
rm "$repo/scratch"

# JSON output carries the same facts.
with_pr "$pr_json" expect_exit 0 run_status --json
jq -e --arg head "$head_sha" --arg master "$master_sha" '
  .worktree.branch == "task" and .worktree.head == $head and .worktree.clean == true
  and .worktree.master == $master and .worktree.ahead_of_master == 2 and .worktree.behind_master == 0
  and (.master_ci | map(.state)) == ["success", "success", "success"]
  and .pull_request.number == 7 and .pull_request_head == "matches"
  and .warnings == [] and .exit_status == 0' "$work/out" >/dev/null
set_run ci.yml completed failure
expect_exit 1 run_status --json
jq -e '.exit_status == 1 and (.warnings | length) == 1 and .master_ci[0].state == "failure"' "$work/out" >/dev/null
set_run ci.yml completed success

# --json --check stays one JSON document even when the checks write to stdout.
cat > "$fakebin/cargo" <<'FAKE'
#!/bin/sh
echo "fake cargo $*"
[ "$1" != clippy ] || exit 1
FAKE
chmod 755 "$fakebin/cargo"
json_check_status=0
run_status --json --check > "$work/out" 2>"$work/err" || json_check_status=$?
test "$json_check_status" = 1
grep -F 'fake cargo clippy' "$work/err" >/dev/null
jq -e '.checks == [{name:"fmt", command:"cargo fmt --all -- --check", result:"pass"},
  {name:"clippy", command:"cargo clippy --all-targets --all-features -- -D warnings", result:"fail"},
  {name:"unit-tests", command:"cargo test --bin syq", result:"pass"}]
  and .warnings == ["clippy failed"] and .exit_status == 1' "$work/out" >/dev/null
rm "$fakebin/cargo"

# Usage errors.
expect_exit 2 run_status --bogus
expect_output 'usage:'

echo 'branch-status tests passed'
