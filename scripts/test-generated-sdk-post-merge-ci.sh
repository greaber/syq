#!/usr/bin/env bash
# Reproduce Actions resolving a recently advanced branch to its old commit.
set -euo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-sdk-dispatch-test.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/bin"
export SYQ_TEST_STATE="$work"
export SYQ_TEST_MERGE_SHA=0123456789abcdef0123456789abcdef01234567
export PATH="$work/bin:$PATH"
cat >"$work/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$SYQ_TEST_STATE/calls"
count=$(cat "$SYQ_TEST_STATE/count")
case "$1:$2" in
  api:*)
    case " $* " in
      *'/git/ref/heads/automation/python-sdk-v0.1.9 '*)
        sha=$SYQ_TEST_MERGE_SHA
        if [ "${SYQ_TEST_REF_WRONG:-false}" = true ] ||
          { [ "${SYQ_TEST_REF_DRIFT:-false}" = true ] && [ "$count" -gt 0 ]; }; then
          sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        fi
        jq -cn --arg sha "$sha" '{object:{sha:$sha}}'
        ;;
      *'/actions/workflows/ci.yml/dispatches '*)
        case " $* " in
          *" inputs[scope_commit]=$SYQ_TEST_MERGE_SHA "*) ;;
          *) echo "dispatch omitted scope commit" >&2; exit 2 ;;
        esac
        case " $* " in
          *' X-GitHub-Api-Version: 2026-03-10 '*) ;;
          *) echo "dispatch omitted API version" >&2; exit 2 ;;
        esac
        count=$((count + 1))
        printf '%s\n' "$count" >"$SYQ_TEST_STATE/count"
        if [ "${SYQ_TEST_INVALID_RESPONSE:-false}" = true ]; then
          printf '{}\n'
        else
          jq -cn --argjson id "$((500 + count))" '{workflow_run_id:$id}'
        fi
        ;;
      *'/jobs?per_page=100 '*)
        jq -cn --arg conclusion "${SYQ_TEST_SDK_CONCLUSION:-success}" \
          '{jobs:[{name:"sdk-languages (python)",status:"completed",conclusion:$conclusion},
                  {name:"sdks",status:"completed",conclusion:$conclusion}]}'
        ;;
      *'/actions/runs/'*)
        id=${2##*/}
        sha=$SYQ_TEST_MERGE_SHA
        [ "$count" -gt "${SYQ_TEST_STALE_ATTEMPTS:-0}" ] || sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        status=queued
        if [ -f "$SYQ_TEST_STATE/watched-$id" ] && [ "${SYQ_TEST_UNFINISHED:-false}" != true ]; then
          status=completed
        fi
        jq -cn --arg sha "$sha" --arg status "$status" --argjson id "$id" \
          --arg branch "${SYQ_TEST_RUN_BRANCH:-automation/python-sdk-v0.1.9}" \
          '{id:$id,event:"workflow_dispatch",head_sha:$sha,head_branch:$branch,
            head_repository:{full_name:"greaber/syq"},status:$status}'
        ;;
      *) echo "unexpected fake gh api invocation: $*" >&2; exit 2 ;;
    esac
    ;;
  run:watch)
    touch "$SYQ_TEST_STATE/watched-$3"
    [ "$count" -gt "${SYQ_TEST_STALE_ATTEMPTS:-0}" ] && [ "${SYQ_TEST_WATCH_FAIL:-false}" != true ]
    ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 2 ;;
esac
GH
cat >"$work/bin/sleep" <<'SLEEP'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = 5 ]
printf 'sleep %s\n' "$1" >>"$SYQ_TEST_STATE/calls"
SLEEP
chmod 755 "$work/bin/gh" "$work/bin/sleep"

run_case() {
  local expected=$1 dispatches=$2
  shift 2
  printf '0\n' >"$work/count"
  : >"$work/calls"
  # Each case has its own monitor markers.
  for marker in "$work"/watched-*; do
    [ ! -f "$marker" ] || rm "$marker"
  done
  local status=0
  env "$@" "$script_dir/run-generated-sdk-post-merge-ci.sh" \
    greaber/syq automation/python-sdk-v0.1.9 "$SYQ_TEST_MERGE_SHA" \
    >"$work/output" 2>&1 || status=$?
  if [ "$expected" = success ]; then
    [ "$status" -eq 0 ] || { cat "$work/output"; exit 1; }
    grep -F "Post-merge Python SDK validation passed for $SYQ_TEST_MERGE_SHA" "$work/output" >/dev/null
  else
    [ "$status" -ne 0 ] || { echo 'unexpected dispatch success' >&2; exit 1; }
    if [ -n "$expected" ]; then
      grep -F "$expected" "$work/output" >/dev/null || { cat "$work/output"; exit 1; }
    fi
  fi
  [ "$(cat "$work/count")" -eq "$dispatches" ]
}

run_case success 1
# A run-list lookup is deliberately unsupported: only the returned run can count.
grep -F 'run watch 501 ' "$work/calls" >/dev/null
run_case success 2 SYQ_TEST_STALE_ATTEMPTS=1
# The stale run must finish and back off before dispatching the next run.
python3 - "$work/calls" <<'PY'
import sys
calls = open(sys.argv[1]).read().splitlines()
dispatches = [i for i, c in enumerate(calls) if '/dispatches ' in c]
watch = next(i for i, c in enumerate(calls) if c.startswith('run watch 501 '))
assert dispatches[0] < watch < calls.index('sleep 5') < dispatches[1]
assert any(c.startswith('run watch 502 ') for c in calls)
assert calls[-1].endswith('/actions/runs/502/jobs?per_page=100')
PY
run_case 'after 3 attempts (last run 503)' 3 SYQ_TEST_STALE_ATTEMPTS=3
run_case 'not completed; refusing another dispatch' 1 SYQ_TEST_STALE_ATTEMPTS=1 SYQ_TEST_UNFINISHED=true
run_case 'does not point to expected merge commit' 0 SYQ_TEST_REF_WRONG=true
run_case 'does not point to expected merge commit' 1 SYQ_TEST_STALE_ATTEMPTS=1 SYQ_TEST_REF_DRIFT=true
run_case 'unexpected workflow run' 1 SYQ_TEST_RUN_BRANCH=unrelated
run_case '' 1 SYQ_TEST_INVALID_RESPONSE=true
run_case '' 1 SYQ_TEST_WATCH_FAIL=true
run_case 'sdks job is completed/failure' 1 SYQ_TEST_SDK_CONCLUSION=failure
run_case 'sdks job is completed/skipped' 1 SYQ_TEST_SDK_CONCLUSION=skipped
printf 'generated SDK CI dispatch tests passed\n'

# Execute the aggregate's actual shell body against every dependency result.
workflow="$script_dir/../.github/workflows/ci.yml"
grep -Fx '    needs: [scope, sdk-languages]' "$workflow" >/dev/null
aggregate=$(sed -n '/^  sdks:$/,/^  # The release workflow builds/p' "$workflow" | sed -n '/^        run: |$/,/^$/p' | sed '1d; /^$/d; s/^          //')
[ -n "$aggregate" ]
SCOPE_RESULT=success SDK_RESULT=success bash -euo pipefail -c "$aggregate"
for result in failure cancelled skipped; do
  if SCOPE_RESULT=success SDK_RESULT="$result" bash -euo pipefail -c "$aggregate"; then
    echo "SDK aggregate accepted $result" >&2
    exit 1
  fi
  if SCOPE_RESULT="$result" SDK_RESULT=success bash -euo pipefail -c "$aggregate"; then
    echo "SDK aggregate accepted failed scope $result" >&2
    exit 1
  fi
done
