#!/usr/bin/env bash
# Fixture-driven checks for path selection, generated-PR approval, preflight,
# and release status reporting.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
grep -F 'rust,sdks,macos,linux-arm64,conformance' \
  "$script_dir/../.github/workflows/release.yml" >/dev/null
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-release-orchestration-test.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

expect_failure() {
  local expected=$1
  shift
  if "$@" >"$work/failure.out" 2>&1; then
    echo "command unexpectedly succeeded: $*" >&2
    exit 1
  fi
  grep -F "$expected" "$work/failure.out" >/dev/null || {
    echo "failure did not contain '$expected':" >&2
    sed 's/^/  /' "$work/failure.out" >&2
    exit 1
  }
}

# Scope pull requests to affected fast checks and reserve the cumulative suites
# for master pushes and explicit manual runs.
assert_scope() {
  local output=$1 key=$2 expected=$3
  grep -Fx "$key=$expected" <<<"$output" >/dev/null
}

paths="$work/paths"
printf 'README.md\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
for key in native sdks tooling mapping_docs conformance macos linux_arm64 full_suite; do
  assert_scope "$scope" "$key" false
done
printf 'MAPPINGS.md\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" mapping_docs true
assert_scope "$scope" native false
printf 'sdk/python/src/syq/syq-release-manifest.json\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" native false
assert_scope "$scope" sdks true
printf 'sdk/python/native-api.json\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" native true
assert_scope "$scope" sdks true
for sdk_script in \
  scripts/check-python-api-sync.py \
  scripts/normalize-python-sdist.py \
  scripts/prepare-python-sdk-release.py \
  scripts/select-trusted-pr.jq \
  scripts/test-python-sdk-release-tools.sh
do
  printf '%s\n' "$sdk_script" >"$paths"
  scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
  assert_scope "$scope" tooling true
  assert_scope "$scope" sdks true
  assert_scope "$scope" native false
done
printf 'tests/rsync-compat/LEDGER.md\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" conformance true
assert_scope "$scope" native false
printf 'src/main.rs\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" native true
assert_scope "$scope" sdks false
assert_scope "$scope" conformance false
assert_scope "$scope" macos false
assert_scope "$scope" linux_arm64 false
printf 'scripts/test-installer.sh\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" tooling true
assert_scope "$scope" native false
printf '.github/workflows/ci.yml\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" tooling true
assert_scope "$scope" native true
assert_scope "$scope" sdks true
assert_scope "$scope" mapping_docs true
assert_scope "$scope" conformance true
assert_scope "$scope" macos true
assert_scope "$scope" linux_arm64 true
printf '.github/workflows/rsync-compat.yml\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" tooling true
assert_scope "$scope" conformance true
assert_scope "$scope" native false
printf '.github/workflows/python-api-sync.yml\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" tooling true
assert_scope "$scope" sdks true
assert_scope "$scope" native false

scope_repo="$work/scope-repo"
mkdir "$scope_repo"
git -C "$scope_repo" init -b master -q
git -C "$scope_repo" config user.name Test
git -C "$scope_repo" config user.email test@example.com
printf 'documentation\n' >"$scope_repo/README.md"
printf 'mapping\n' >"$scope_repo/MAPPINGS.md"
git -C "$scope_repo" add README.md MAPPINGS.md
git -C "$scope_repo" commit -qm base
scope_base=$(git -C "$scope_repo" rev-parse HEAD)
mkdir -p "$scope_repo/sdk/python"
printf 'mapping\n' >"$scope_repo/sdk/python/mapping"
git -C "$scope_repo" add sdk/python/mapping
git -C "$scope_repo" commit -qm sdk
scope_head=$(git -C "$scope_repo" rev-parse HEAD)
scope_event="$work/pull-request-event.json"
jq -n --arg base "$scope_base" --arg head "$scope_head" \
  '{pull_request:{base:{sha:$base},head:{sha:$head}}}' >"$scope_event"
scope=$(cd "$scope_repo" && "$script_dir/ci-scope.sh" "$scope_event")
assert_scope "$scope" native false
assert_scope "$scope" sdks true
assert_scope "$scope" full_suite false

# A pull request branch may lag master. Scope its own three-dot diff rather
# than treating unrelated base-branch changes as part of the pull request.
git -C "$scope_repo" switch -qc docs "$scope_base"
printf 'more documentation\n' >>"$scope_repo/README.md"
git -C "$scope_repo" commit -qam docs
docs_head=$(git -C "$scope_repo" rev-parse HEAD)
git -C "$scope_repo" switch -q master
mkdir -p "$scope_repo/src"
printf 'fn main() {}\n' >"$scope_repo/src/main.rs"
git -C "$scope_repo" add src/main.rs
git -C "$scope_repo" commit -qm native
advanced_base=$(git -C "$scope_repo" rev-parse HEAD)
jq -n --arg base "$advanced_base" --arg head "$docs_head" \
  '{pull_request:{base:{sha:$base},head:{sha:$head}}}' >"$scope_event"
scope=$(cd "$scope_repo" && "$script_dir/ci-scope.sh" "$scope_event")
for key in native sdks tooling mapping_docs conformance macos linux_arm64 full_suite; do
  assert_scope "$scope" "$key" false
done

# Rename detection must expose both the affected source and inert destination.
git -C "$scope_repo" switch -qc rename "$scope_base"
mkdir "$scope_repo/docs"
git -C "$scope_repo" mv MAPPINGS.md docs/mappings.md
git -C "$scope_repo" commit -qm rename
rename_head=$(git -C "$scope_repo" rev-parse HEAD)
jq -n --arg base "$advanced_base" --arg head "$rename_head" \
  '{pull_request:{base:{sha:$base},head:{sha:$head}}}' >"$scope_event"
scope=$(cd "$scope_repo" && "$script_dir/ci-scope.sh" "$scope_event")
assert_scope "$scope" mapping_docs true
assert_scope "$scope" native false
assert_scope "$scope" sdks false

push_event="$work/push-event.json"
jq -n --arg before "$scope_head" --arg after "$advanced_base" \
  '{before:$before,after:$after}' >"$push_event"
scope=$(cd "$scope_repo" && "$script_dir/ci-scope.sh" "$push_event")
assert_scope "$scope" native true
assert_scope "$scope" sdks true
assert_scope "$scope" conformance true
assert_scope "$scope" macos true
assert_scope "$scope" linux_arm64 true
assert_scope "$scope" full_suite true

printf '{}\n' >"$work/workflow-dispatch-event.json"
scope=$(cd "$scope_repo" && \
  "$script_dir/ci-scope.sh" "$work/workflow-dispatch-event.json")
for key in native sdks tooling mapping_docs conformance macos linux_arm64 full_suite; do
  assert_scope "$scope" "$key" true
done

# The approval helper binds the PR and both workflow runs to the same trusted
# repository, native pull_request event, branch, and exact head SHA.
approval_bin="$work/approval-bin"
mkdir "$approval_bin"
approval_log="$work/approvals"
head_sha=0123456789abcdef0123456789abcdef01234567
cat >"$approval_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = api ] && [[ " $* " == *" repos/greaber/syq/pulls "* ]]; then
  jq -cn --arg repo "${SYQ_TEST_PR_REPOSITORY:-greaber/syq}" \
    --arg branch automation/python-sdk-v0.1.9 --arg sha "$SYQ_TEST_HEAD_SHA" '
    [{head:{repo:{full_name:$repo},ref:$branch,sha:$sha},base:{ref:"master"}}]'
elif [ "$1:$2" = 'run:list' ]; then
  jq -cn --arg sha "${SYQ_TEST_RUN_SHA:-$SYQ_TEST_HEAD_SHA}" \
    --arg event "${SYQ_TEST_RUN_EVENT:-pull_request}" '[
    {conclusion:"action_required",databaseId:101,event:$event,headSha:$sha,status:"completed",url:"https://example.test/101",workflowName:"ci"},
    {conclusion:"action_required",databaseId:102,event:$event,headSha:$sha,status:"completed",url:"https://example.test/102",workflowName:"rsync compatibility"}]'
elif [ "$1" = api ] && [[ " $* " == *'/approve '* ]]; then
  printf '%s\n' "$*" >>"$SYQ_TEST_APPROVAL_LOG"
elif [ "$1" = api ] && [[ "$2" == *'/check-runs?'* ]]; then
  status=${SYQ_TEST_SDK_STATUS:-completed}
  conclusion=${SYQ_TEST_SDK_CONCLUSION:-success}
  if [ "$conclusion" = null ]; then
    jq -cn --arg status "$status" \
      '{check_runs:[{name:"sdks",status:$status,conclusion:null}]}'
  else
    jq -cn --arg status "$status" --arg conclusion "$conclusion" \
      '{check_runs:[{name:"sdks",status:$status,conclusion:$conclusion}]}'
  fi
else
  echo "unexpected fake gh invocation: $*" >&2
  exit 2
fi
EOF
chmod 755 "$approval_bin/gh"
SYQ_TEST_HEAD_SHA="$head_sha" SYQ_TEST_APPROVAL_LOG="$approval_log" \
  PATH="$approval_bin:$PATH" \
  "$script_dir/approve-generated-pr-runs.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$head_sha" >/dev/null
[ "$(wc -l <"$approval_log")" -eq 2 ]
expect_failure 'expected one trusted open pull request' env \
  SYQ_TEST_HEAD_SHA="$head_sha" SYQ_TEST_PR_REPOSITORY=attacker/syq \
  SYQ_TEST_APPROVAL_LOG="$approval_log" PATH="$approval_bin:$PATH" \
  "$script_dir/approve-generated-pr-runs.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$head_sha"
expect_failure 'timed out waiting for native pull-request workflow runs' env \
  SYQ_TEST_HEAD_SHA="$head_sha" SYQ_TEST_RUN_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  SYQ_TEST_APPROVAL_LOG="$approval_log" SYQ_APPROVAL_TIMEOUT_SECONDS=0 \
  PATH="$approval_bin:$PATH" \
  "$script_dir/approve-generated-pr-runs.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$head_sha"
expect_failure 'required generated-PR check sdks is completed/failure' env \
  SYQ_TEST_HEAD_SHA="$head_sha" SYQ_TEST_SDK_CONCLUSION=failure \
  SYQ_TEST_APPROVAL_LOG="$approval_log" PATH="$approval_bin:$PATH" \
  "$script_dir/approve-generated-pr-runs.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$head_sha"
expect_failure 'timed out waiting for required generated-PR check sdks' env \
  SYQ_TEST_HEAD_SHA="$head_sha" SYQ_TEST_SDK_STATUS=in_progress \
  SYQ_TEST_SDK_CONCLUSION=null SYQ_REQUIRED_CHECK_TIMEOUT_SECONDS=0 \
  SYQ_TEST_APPROVAL_LOG="$approval_log" PATH="$approval_bin:$PATH" \
  "$script_dir/approve-generated-pr-runs.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$head_sha"
expect_failure 'timed out waiting for native pull-request workflow runs' env \
  SYQ_TEST_HEAD_SHA="$head_sha" SYQ_TEST_RUN_EVENT=workflow_dispatch \
  SYQ_TEST_APPROVAL_LOG="$approval_log" SYQ_APPROVAL_TIMEOUT_SECONDS=0 \
  PATH="$approval_bin:$PATH" \
  "$script_dir/approve-generated-pr-runs.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$head_sha"

# Build a clean disposable canonical checkout and serve every GitHub/registry
# response from fixtures. The preflight must not create a tag or publication.
preflight_repo="$work/preflight-repo"
preflight_bin="$work/preflight-bin"
mkdir -p "$preflight_repo/.github/workflows" "$preflight_repo/scripts" \
  "$preflight_repo/sdk/python" "$preflight_bin"
cp "$script_dir/check-python-api-sync.py" "$preflight_repo/scripts/"
cat >"$preflight_repo/sdk/python/native-api.json" <<'EOF'
{"schema":1,"commands":{}}
EOF
cat >"$preflight_repo/Cargo.toml" <<'EOF'
[package]
name = "syq"
version = "9.9.9"
EOF
cat >"$preflight_repo/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "syq"
version = "9.9.9"
EOF
cat >"$preflight_repo/.github/workflows/release.yml" <<'EOF'
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
  - uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
EOF
git -C "$preflight_repo" init -b master -q
git -C "$preflight_repo" config user.name Test
git -C "$preflight_repo" config user.email test@example.com
git -C "$preflight_repo" add .
git -C "$preflight_repo" commit -qm initial
git -C "$preflight_repo" remote add origin git@github.com:greaber/syq.git
preflight_head=$(git -C "$preflight_repo" rev-parse HEAD)
git -C "$preflight_repo" update-ref refs/remotes/origin/master "$preflight_head"
ssh-keygen -q -t ed25519 -N '' -f "$work/tag-signing-key"
signing_key=$(awk '{print $1 " " $2}' "$work/tag-signing-key.pub")
git -C "$preflight_repo" config gpg.format ssh
git -C "$preflight_repo" config user.signingkey "key::$signing_key"
git -C "$preflight_repo" config tag.gpgsign true
real_git=$(command -v git)
cat >"$preflight_bin/git" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = ls-remote ]; then
  case " $* " in
    *' refs/heads/master '*) printf '%s\trefs/heads/master\n' "$SYQ_TEST_PREFLIGHT_HEAD" ;;
  esac
  exit 0
fi
exec "$SYQ_TEST_REAL_GIT" "$@"
EOF
cat >"$preflight_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1:$2" in
  repo:view) printf 'greaber/syq\n' ;;
  secret:list) printf '[{"name":"SYQ_RELEASE_SIGNING_KEY_PEM_B64"},{"name":"HOMEBREW_TAP_DEPLOY_KEY"}]\n' ;;
  variable:list) printf '[{"name":"SYQ_RELEASE_PUBLIC_KEY","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]\n' ;;
  api:user) printf 'greaber\n' ;;
  api:*)
    case " $* " in
      *'/commits/'*'/check-runs'*) printf '%s\n' "$SYQ_TEST_CHECKS_JSON" ;;
      *'/actions/workflows/'*'/runs?'*) printf '%s\n' "$SYQ_TEST_WORKFLOW_RUNS_JSON" ;;
      *'/actions/permissions/selected-actions '*) printf '%s\n' "$SYQ_TEST_SELECTED_ACTIONS_JSON" ;;
      *'/actions/permissions '*) printf '{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}\n' ;;
      *'/deployment-branch-policies '*) printf '{"branch_policies":[{"name":"v*","type":"tag"}]}\n' ;;
      *'/environments/release '*) printf '{"name":"release","protection_rules":[{"type":"required_reviewers"}]}\n' ;;
      *'users/greaber/ssh_signing_keys'*) jq -cn --arg key "$SYQ_TEST_SIGNING_KEY" '[{key:$key}]' ;;
      *'/releases?per_page=100 '*) printf '[[]]\n' ;;
      *'homebrew-tap/contents/Formula/syq.rb '*) jq -cn --arg content "$SYQ_TEST_FORMULA_B64" '{content:$content}' ;;
      *) echo "unexpected fake gh api invocation: $*" >&2; exit 2 ;;
    esac
    ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 2 ;;
esac
EOF
cat >"$preflight_bin/curl" <<'EOF'
#!/usr/bin/env bash
jq -cn --arg version "${SYQ_TEST_EXISTING_CRATE_VERSION:-}" '
  {versions:(if $version == "" then [] else [{num:$version}] end)}'
EOF
chmod 755 "$preflight_bin/git" "$preflight_bin/gh" "$preflight_bin/curl"
checks_json=$(jq -cn '{check_runs:["rust","sdks","macos","linux-arm64","conformance"] | map({name:.,conclusion:"success"})}')
workflow_runs_json=$(jq -cn --arg head "$preflight_head" '{workflow_runs:[{
  id:601,event:"workflow_dispatch",head_sha:$head,status:"completed",
  conclusion:"success",run_number:1,run_attempt:1}]}')
selected_json=$(jq -cn '{github_owned_allowed:true,verified_allowed:false,
  patterns_allowed:["rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18"]}')
formula_b64=$(printf 'url "https://github.com/greaber/syq/releases/download/v9.9.8/syq"\n' | openssl base64 -A)
preflight_env=(
  SYQ_TEST_PREFLIGHT_HEAD="$preflight_head"
  SYQ_TEST_REAL_GIT="$real_git"
  SYQ_TEST_CHECKS_JSON="$checks_json"
  SYQ_TEST_WORKFLOW_RUNS_JSON="$workflow_runs_json"
  SYQ_TEST_SELECTED_ACTIONS_JSON="$selected_json"
  SYQ_TEST_SIGNING_KEY="$signing_key"
  SYQ_TEST_FORMULA_B64="$formula_b64"
  PATH="$preflight_bin:$PATH"
)
(cd "$preflight_repo" && env "${preflight_env[@]}" \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/preflight.out"
grep -F "Release preflight passed for v9.9.9 at $preflight_head" "$work/preflight.out" >/dev/null
checks_without_conformance=$(jq -cn '{check_runs:["rust","sdks","macos","linux-arm64"] | map({name:.,conclusion:"success"})}')
if (cd "$preflight_repo" && env "${preflight_env[@]}" \
  SYQ_TEST_CHECKS_JSON="$checks_without_conformance" \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/failure.out" 2>&1; then
  echo 'preflight unexpectedly accepted a missing conformance check' >&2
  exit 1
fi
grep -F 'required check conformance is missing' "$work/failure.out" >/dev/null
if (cd "$preflight_repo" && env "${preflight_env[@]}" \
  SYQ_TEST_WORKFLOW_RUNS_JSON='{"workflow_runs":[]}' \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/failure.out" 2>&1; then
  echo 'preflight unexpectedly accepted missing full release CI' >&2
  exit 1
fi
grep -F 'has no workflow_dispatch run' "$work/failure.out" >/dev/null
if (cd "$preflight_repo" && env "${preflight_env[@]}" \
  SYQ_TEST_EXISTING_CRATE_VERSION=9.9.9 \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/failure.out" 2>&1; then
  echo 'preflight unexpectedly accepted an existing crates.io version' >&2
  exit 1
fi
grep -F 'already published on crates.io' "$work/failure.out" >/dev/null

# Release status correlates the exact tag commit with runs, pending protected
# environments, and every publication destination.
status_bin="$work/status-bin"
mkdir "$status_bin"
status_commit=89abcdef0123456789abcdef0123456789abcdef
status_tag_object=76543210abcdef9876543210abcdef9876543210
status_formula_b64=$(printf 'url "https://github.com/greaber/syq/releases/download/v0.1.8/syq"\n' | openssl base64 -A)
cat >"$status_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1:$2" in
  run:list) jq -cn --arg sha "$SYQ_TEST_STATUS_COMMIT" '[
    {conclusion:null,databaseId:303,event:"push",headSha:$sha,status:"in_progress",url:"https://example.test/303",workflowName:"release"}]' ;;
  api:*)
    case " $* " in
      *'/git/matching-refs/tags/v0.1.8 '*) jq -cn --arg sha "$SYQ_TEST_STATUS_TAG_OBJECT" '[{ref:"refs/tags/v0.1.8",object:{type:"tag",sha:$sha}}]' ;;
      *'/git/tags/'*) jq -cn --arg sha "$SYQ_TEST_STATUS_COMMIT" \
        --arg tag "${SYQ_TEST_STATUS_OBJECT_TAG:-v0.1.8}" \
        --arg type "${SYQ_TEST_STATUS_TARGET_TYPE:-commit}" \
        '{tag:$tag,object:{type:$type,sha:$sha},verification:{verified:true,reason:"valid"}}' ;;
      *'/releases?per_page=100 '*) printf '[[{"tag_name":"v0.1.8","draft":false,"immutable":true,"html_url":"https://example.test/v0.1.8"}]]\n' ;;
      *'/actions/runs/303/pending_deployments '*) printf '[{"environment":{"name":"release"}}]\n' ;;
      *'homebrew-tap/contents/Formula/syq.rb '*) jq -cn --arg content "$SYQ_TEST_STATUS_FORMULA_B64" '{content:$content}' ;;
      *) echo "unexpected fake gh api invocation: $*" >&2; exit 2 ;;
    esac
    ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 2 ;;
esac
EOF
cat >"$status_bin/curl" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *'crates.io/'*) printf '{"versions":[{"num":"0.1.8"}]}\n' ;;
  *'pypi.org/'*) printf '{"info":{"version":"0.1.8"},"releases":{"0.1.8":[{}]}}\n' ;;
  *) exit 2 ;;
esac
EOF
chmod 755 "$status_bin/gh" "$status_bin/curl"
PATH="$status_bin:$PATH" \
SYQ_TEST_STATUS_COMMIT="$status_commit" \
SYQ_TEST_STATUS_TAG_OBJECT="$status_tag_object" \
SYQ_TEST_STATUS_FORMULA_B64="$status_formula_b64" \
  "$script_dir/release-status.sh" --json v0.1.8 >"$work/status.json"
jq -e --arg commit "$status_commit" '
  .tag_state == "verified" and .tag_commit == $commit and
  .github_release.state == "published" and .github_release.immutable == true and
  .release_runs[0].databaseId == 303 and
  .release_runs[0].pending_environments == ["release"] and
  .publications.crates_io.state == "published" and
  .publications.pypi.state == "published" and
  .publications.homebrew.state == "published"
' "$work/status.json" >/dev/null || {
  echo 'release status fixture did not produce the expected state:' >&2
  jq . "$work/status.json" >&2
  exit 1
}

PATH="$status_bin:$PATH" \
SYQ_TEST_STATUS_COMMIT="$status_commit" \
SYQ_TEST_STATUS_TAG_OBJECT="$status_tag_object" \
SYQ_TEST_STATUS_OBJECT_TAG=v0.1.7 \
SYQ_TEST_STATUS_FORMULA_B64="$status_formula_b64" \
  "$script_dir/release-status.sh" --json v0.1.8 >"$work/status-name-mismatch.json"
jq -e '.tag_state == "name-mismatch" and .tag_commit == null' \
  "$work/status-name-mismatch.json" >/dev/null

PATH="$status_bin:$PATH" \
SYQ_TEST_STATUS_COMMIT="$status_commit" \
SYQ_TEST_STATUS_TAG_OBJECT="$status_tag_object" \
SYQ_TEST_STATUS_TARGET_TYPE=tag \
SYQ_TEST_STATUS_FORMULA_B64="$status_formula_b64" \
  "$script_dir/release-status.sh" --json v0.1.8 >"$work/status-nested-tag.json"
jq -e '.tag_state == "invalid-target" and .tag_commit == null' \
  "$work/status-nested-tag.json" >/dev/null

echo 'release orchestration tests passed'
