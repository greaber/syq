#!/usr/bin/env bash
# Fixture-driven checks for path selection, preflight, and release status
# reporting.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
grep -F 'rust,sdks,macos,linux-arm64,conformance' \
  "$script_dir/../.github/workflows/release.yml" >/dev/null
grep -F ".github/release-notes/\$GITHUB_REF_NAME.md" \
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

# Select affected checks; native changes keep broader cross-subsystem,
# architecture, and platform coverage after merge.
assert_scope() {
  local output=$1 key=$2 expected=$3
  grep -Fx "$key=$expected" <<<"$output" >/dev/null
}

scope_keys=(
  native sdks python_sdk javascript_sdk go_sdk tooling shellcheck mapping_docs
  conformance macos linux_arm64 full_suite
)

paths="$work/paths"
for path in \
  README.md \
  sdk/README.md sdk/RELEASING.md \
  sdk/python/README.md sdk/python/NATIVE_API.md sdk/python/API_DESIGN.md \
  sdk/js/README.md sdk/go/README.md \
  book.toml theme/head.hbs theme/docs.css theme/copy-demo.js \
  .agents/skills/syq-release/SKILL.md \
  .agents/skills/syq-release/agents/openai.yaml
do
  printf '%s\n' "$path" >"$paths"
  scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
  for key in "${scope_keys[@]}"; do
    assert_scope "$scope" "$key" false
  done
done
# Documentation exceptions must not hide SDK fixtures, build metadata, or
# the API specification consumed by the native CLI.
for path in sdk/python/tests/example.md sdk/python/pyproject.toml; do
  printf '%s\n' "$path" >"$paths"
  scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
  assert_scope "$scope" python_sdk true
done
printf 'docs/mappings.md\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" mapping_docs true
assert_scope "$scope" native false
printf 'sdk/python/src/syq/syq-release-manifest.json\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" native false
assert_scope "$scope" sdks true
assert_scope "$scope" python_sdk true
assert_scope "$scope" javascript_sdk false
assert_scope "$scope" go_sdk false
printf 'sdk/js/src/index.js\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" sdks true
assert_scope "$scope" python_sdk false
assert_scope "$scope" javascript_sdk true
assert_scope "$scope" go_sdk false
printf 'sdk/go/client.go\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" sdks true
assert_scope "$scope" python_sdk false
assert_scope "$scope" javascript_sdk false
assert_scope "$scope" go_sdk true
printf 'sdk/python/native-api.json\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" native true
assert_scope "$scope" sdks true
assert_scope "$scope" python_sdk true
for sdk_script in \
  scripts/check-python-api-sync.py \
  scripts/normalize-python-sdist.py \
  scripts/prepare-python-sdk-release.py \
  scripts/run-generated-sdk-post-merge-ci.sh \
  scripts/select-trusted-pr.jq \
  scripts/test-python-sdk-release-tools.sh
do
  printf '%s\n' "$sdk_script" >"$paths"
  scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
  assert_scope "$scope" tooling true
  assert_scope "$scope" sdks true
  assert_scope "$scope" python_sdk true
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
printf 'docs/example.sh\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" shellcheck true
assert_scope "$scope" tooling false
assert_scope "$scope" native false
printf 'tests/real-ssh/scenarios.sh\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" shellcheck true
assert_scope "$scope" tooling false
assert_scope "$scope" native false
printf 'scripts/test-installer.sh\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" tooling true
assert_scope "$scope" native false
printf '.github/workflows/ci.yml\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" tooling true
for key in native sdks python_sdk javascript_sdk go_sdk shellcheck mapping_docs conformance macos linux_arm64 full_suite; do
  assert_scope "$scope" "$key" false
done
printf '.github/workflows/rsync-compat.yml\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" tooling true
assert_scope "$scope" conformance true
assert_scope "$scope" native false
printf '.github/workflows/python-api-sync.yml\n' >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" tooling true
assert_scope "$scope" sdks true
assert_scope "$scope" python_sdk true
assert_scope "$scope" native false

# The surface touched by PR #190 should run the Rust baseline, Python SDK, and
# shell lint without promoting the pull request to unrelated suites.
printf '%s\n' \
  docs/reference.md \
  sdk/python/native-api.json \
  sdk/python/src/syq/client.py \
  src/cli.rs \
  tests/local.rs \
  tests/real-ssh/scenarios.sh >"$paths"
scope=$(SYQ_TEST_CHANGED_PATHS_FILE="$paths" "$script_dir/ci-scope.sh")
assert_scope "$scope" native true
assert_scope "$scope" sdks true
assert_scope "$scope" python_sdk true
assert_scope "$scope" shellcheck true
for key in javascript_sdk go_sdk tooling mapping_docs conformance macos linux_arm64 full_suite; do
  assert_scope "$scope" "$key" false
done

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
assert_scope "$scope" python_sdk true
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
for key in "${scope_keys[@]}"; do
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
assert_scope "$scope" python_sdk true
assert_scope "$scope" javascript_sdk true
assert_scope "$scope" go_sdk true
assert_scope "$scope" conformance true
assert_scope "$scope" macos true
assert_scope "$scope" linux_arm64 true
assert_scope "$scope" full_suite true

# Exercise the real macOS classification step, rather than duplicating its
# selection logic here. Missing/renamed step boundaries fail this check.
# shellcheck disable=SC2016 # Match literal shell expressions in the workflow.
macos_step=$(sed -n '/^          scope=$(scripts\/ci-scope.sh/,/^          echo "needed=$needed" >> "$GITHUB_OUTPUT"/p' \
  "$script_dir/../.github/workflows/macos.yml")
[ -n "$macos_step" ]
assert_macos_needed() {
  local expected=$1
  shift
  printf '%s\n' "$@" >"$paths"
  : >"$work/macos-output"
  (cd "$script_dir/.." && \
    SYQ_TEST_CHANGED_PATHS_FILE="$paths" GITHUB_EVENT_PATH="$push_event" \
    GITHUB_OUTPUT="$work/macos-output" bash -euo pipefail -c "$macos_step")
  assert_scope "$(cat "$work/macos-output")" needed "$expected"
}
assert_macos_needed false docs/mappings.md sdk/python/NATIVE_API.md
assert_macos_needed false theme/docs.js book.toml
assert_macos_needed false tests/real-ssh/scenarios.sh docs/example.sh
assert_macos_needed true docs/mappings.md src/main.rs
assert_macos_needed true sdk/python/native-api.json
assert_macos_needed true sdk/python/src/syq/client.py
assert_macos_needed true scripts/test-installer.sh
assert_macos_needed true .github/workflows/macos.yml
assert_macos_needed true unknown-input

# Reproduce a documentation-only post-merge push, including the SDK guide and
# executable mapping examples. Only the focused example checks are selected.
git -C "$scope_repo" switch -qc documentation-push "$advanced_base"
mkdir -p "$scope_repo/docs" "$scope_repo/theme"
printf 'mapping examples\n' >"$scope_repo/docs/mappings.md"
printf 'API guide\n' >"$scope_repo/sdk/python/NATIVE_API.md"
printf 'body {}\n' >"$scope_repo/theme/docs.css"
git -C "$scope_repo" add .
git -C "$scope_repo" commit -qm documentation-push
documentation_head=$(git -C "$scope_repo" rev-parse HEAD)
jq -n --arg before "$advanced_base" --arg after "$documentation_head" \
  '{before:$before,after:$after}' >"$push_event"
scope=$(cd "$scope_repo" && "$script_dir/ci-scope.sh" "$push_event")
for key in "${scope_keys[@]}"; do
  case "$key" in
    mapping_docs|full_suite) assert_scope "$scope" "$key" true ;;
    *) assert_scope "$scope" "$key" false ;;
  esac
done

# Both sides of a rename remain visible even when the destination is one of
# the explicitly excluded SDK documents.
git -C "$scope_repo" switch -qc sdk-doc-rename "$advanced_base"
git -C "$scope_repo" mv sdk/python/mapping sdk/python/NATIVE_API.md
git -C "$scope_repo" commit -qm sdk-doc-rename
sdk_rename_head=$(git -C "$scope_repo" rev-parse HEAD)
jq -n --arg before "$advanced_base" --arg after "$sdk_rename_head" \
  '{before:$before,after:$after}' >"$push_event"
scope=$(cd "$scope_repo" && "$script_dir/ci-scope.sh" "$push_event")
assert_scope "$scope" python_sdk true

printf '{}\n' >"$work/workflow-dispatch-event.json"
scope=$(cd "$scope_repo" && \
  "$script_dir/ci-scope.sh" "$work/workflow-dispatch-event.json")
for key in "${scope_keys[@]}"; do
  assert_scope "$scope" "$key" true
done
# A manual release-validation run must still start the complete macOS suite.
: >"$work/macos-output"
(cd "$script_dir/.." && \
  GITHUB_EVENT_PATH="$work/workflow-dispatch-event.json" \
  GITHUB_OUTPUT="$work/macos-output" bash -euo pipefail -c "$macos_step")
assert_scope "$(cat "$work/macos-output")" needed true

# Generated Python SDK validation passes an exact checked-out commit, retaining
# normal path selection instead of treating its workflow dispatch as a manual
# full-suite request.
mkdir -p "$scope_repo/sdk/python"
printf 'release manifest\n' >"$scope_repo/sdk/python/syq-release-manifest.json"
git -C "$scope_repo" add sdk/python/syq-release-manifest.json
git -C "$scope_repo" commit -qm generated-python-sdk
scoped_dispatch_head=$(git -C "$scope_repo" rev-parse HEAD)
scope=$(cd "$scope_repo" && \
  SYQ_CI_SCOPE_COMMIT="$scoped_dispatch_head" \
  "$script_dir/ci-scope.sh" "$work/workflow-dispatch-event.json")
assert_scope "$scope" native false
assert_scope "$scope" sdks true
assert_scope "$scope" python_sdk true
for key in javascript_sdk go_sdk tooling shellcheck mapping_docs conformance macos linux_arm64 full_suite; do
  assert_scope "$scope" "$key" false
done
expect_failure 'is not checked out' env \
  SYQ_CI_SCOPE_COMMIT=0123456789abcdef0123456789abcdef01234567 \
  bash -c "cd '$scope_repo' && '$script_dir/ci-scope.sh' '$work/workflow-dispatch-event.json'"

# The generated SDK follow-up dispatches CI on a branch pinned to the exact
# merge commit, binds the returned run to that commit, and requires its SDK job.
post_merge_bin="$work/post-merge-bin"
mkdir "$post_merge_bin"
post_merge_sha=0123456789abcdef0123456789abcdef01234567
cat >"$post_merge_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1:$2" in
  api:*)
    case " $* " in
      *'/git/ref/heads/automation/python-sdk-v0.1.9 '*)
        jq -cn --arg sha "${SYQ_TEST_REF_SHA:-$SYQ_TEST_MERGE_SHA}" \
          '{object:{sha:$sha}}'
        ;;
      *'/actions/workflows/ci.yml/dispatches '*)
        case " $* " in
          *" inputs[scope_commit]=$SYQ_TEST_MERGE_SHA "*) ;;
          *) echo "scoped dispatch omitted merge commit: $*" >&2; exit 2 ;;
        esac
        printf '{"workflow_run_id":501}\n'
        ;;
      *'/actions/workflows/ci.yml/runs?'*)
        jq -cn --arg sha "${SYQ_TEST_RUN_SHA:-$SYQ_TEST_MERGE_SHA}" \
          '{workflow_runs:[{id:501,event:"workflow_dispatch",head_sha:$sha,created_at:"2026-01-01T00:00:00Z"}]}'
        ;;
      *'/actions/workflows/rsync-compat.yml/runs?'*)
        jq -cn --arg sha "${SYQ_TEST_RUN_SHA:-$SYQ_TEST_MERGE_SHA}" \
          '{workflow_runs:[{id:502,event:"workflow_dispatch",head_sha:$sha,created_at:"2026-01-01T00:00:00Z"}]}'
        ;;
      *'/actions/workflows/macos.yml/runs?'*)
        jq -cn --arg sha "${SYQ_TEST_RUN_SHA:-$SYQ_TEST_MERGE_SHA}" \
          '{workflow_runs:[{id:503,event:"workflow_dispatch",head_sha:$sha,created_at:"2026-01-01T00:00:00Z"}]}'
        ;;
      *'/actions/runs/501/jobs?per_page=100 '*)
        jq -cn --arg conclusion "${SYQ_TEST_SDK_CONCLUSION:-success}" \
          '{jobs:[{name:"sdks",status:"completed",conclusion:$conclusion}]}'
        ;;
      *'/actions/runs/'*)
        run_id=${2##*/}
        jq -cn --arg sha "${SYQ_TEST_RUN_SHA:-$SYQ_TEST_MERGE_SHA}" \
          --argjson id "$run_id" \
          '{id:$id,event:"workflow_dispatch",head_sha:$sha,status:"queued",conclusion:null}'
        ;;
      *) echo "unexpected fake gh api invocation: $*" >&2; exit 2 ;;
    esac
    ;;
  run:watch)
    [ "${SYQ_TEST_WATCH_RESULT:-success}" = success ]
    ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 2 ;;
esac
EOF
chmod 755 "$post_merge_bin/gh"
SYQ_TEST_MERGE_SHA="$post_merge_sha" PATH="$post_merge_bin:$PATH" \
  "$script_dir/run-generated-sdk-post-merge-ci.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$post_merge_sha" \
  >"$work/post-merge.out"
grep -F "Post-merge Python SDK validation passed for $post_merge_sha" \
  "$work/post-merge.out" >/dev/null
expect_failure 'does not point to expected merge commit' env \
  SYQ_TEST_MERGE_SHA="$post_merge_sha" \
  SYQ_TEST_REF_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  PATH="$post_merge_bin:$PATH" \
  "$script_dir/run-generated-sdk-post-merge-ci.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$post_merge_sha"
expect_failure 'ci.yml dispatch did not create' env \
  SYQ_TEST_MERGE_SHA="$post_merge_sha" \
  SYQ_TEST_RUN_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  SYQ_POST_MERGE_POLL_ATTEMPTS=1 \
  PATH="$post_merge_bin:$PATH" \
  "$script_dir/run-generated-sdk-post-merge-ci.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$post_merge_sha"
expect_failure 'ci.yml run 501 sdks job is completed/failure' env \
  SYQ_TEST_MERGE_SHA="$post_merge_sha" SYQ_TEST_SDK_CONCLUSION=failure \
  PATH="$post_merge_bin:$PATH" \
  "$script_dir/run-generated-sdk-post-merge-ci.sh" \
  greaber/syq automation/python-sdk-v0.1.9 "$post_merge_sha"

# Build a clean disposable canonical checkout and serve every GitHub/registry
# response from fixtures. The preflight must not create a tag or publication.
preflight_repo="$work/preflight-repo"
preflight_bin="$work/preflight-bin"
mkdir -p "$preflight_repo/.github/release-notes" "$preflight_repo/.github/workflows" "$preflight_repo/scripts" \
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
printf 'Release fixture notes\n' >"$preflight_repo/.github/release-notes/v9.9.9.md"
git -C "$preflight_repo" init -b master -q
git -C "$preflight_repo" config user.name Test
git -C "$preflight_repo" config user.email test@example.com
git -C "$preflight_repo" add .
git -C "$preflight_repo" commit -qm initial
git -C "$preflight_repo" remote add origin git@github.com:greaber/syq.git
preflight_head=$(git -C "$preflight_repo" rev-parse HEAD)
preflight_tree=$(git -C "$preflight_repo" rev-parse 'HEAD^{tree}')
mkdir -p "$preflight_repo/.git/syq-release/real-ssh"
jq -n --arg commit "$preflight_head" --arg tree "$preflight_tree" \
  '{schema:1,commit:$commit,tree:$tree,profile:"default",result:"success"}' \
  >"$preflight_repo/.git/syq-release/real-ssh/$preflight_tree.json"
git -C "$preflight_repo" update-ref refs/remotes/origin/master "$preflight_head"
signing_key=$(awk '$1 == "syq-release" {
  for (i = 2; i < NF; i++) {
    if ($i ~ /^ssh-/) {print $i " " $(i + 1); break}
  }
}' "$script_dir/release-tag-signers")
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
if [ "$1" = api ] && [ "${2:-}" = --paginate ]; then
  shift 3
  set -- api "$@"
fi
case "$1:$2" in
  repo:view) printf 'greaber/syq\n' ;;
  secret:list) printf '[{"name":"SYQ_RELEASE_SIGNING_KEY_PEM_B64"},{"name":"HOMEBREW_TAP_DEPLOY_KEY"}]\n' ;;
  variable:list) printf '[{"name":"SYQ_RELEASE_PUBLIC_KEY","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]\n' ;;
  api:user) printf 'greaber\n' ;;
  api:*)
    case " $* " in
      *'/commits/'*'/check-runs'*) printf '%s\n' "$SYQ_TEST_CHECKS_JSON" ;;
      *'/attempts/'*'/jobs?'*) printf '[{"jobs":[{"name":"release-certification","status":"completed","conclusion":"success"}]}]\n' ;;
      *'/actions/workflows/'*'/runs?'*) printf '[%s]\n' "$SYQ_TEST_WORKFLOW_RUNS_JSON" ;;
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
  head_branch:"master",head_repository:{full_name:"greaber/syq"},id:601,event:"workflow_dispatch",head_sha:$head,status:"completed",
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
# Exercise preflight with allowlist options whose quoted whitespace changes
# awk field positions. Keep the repository's real allowlist untouched.
option_scripts="$work/tag-option-scripts"
mkdir "$option_scripts"
cp "$script_dir/release-preflight.sh" "$option_scripts/"
ln -s "$script_dir/release-readiness.py" "$option_scripts/release-readiness.py"
ln -s "$script_dir/verify-release-ci.sh" "$option_scripts/verify-release-ci.sh"
for options in '' 'namespaces="git"' 'namespaces="git, file",valid-before="20990101"'; do
  printf 'syq-release %s %s\n' "$options" "$signing_key" >"$option_scripts/release-tag-signers"
  (cd "$preflight_repo" && env "${preflight_env[@]}" \
    "$option_scripts/release-preflight.sh" v9.9.9) >"$work/preflight-options.out"
done
ssh-keygen -q -t ed25519 -N '' -f "$work/other-preflight-key"
other_signing_key=$(awk '{print $1 " " $2}' "$work/other-preflight-key.pub")
git -C "$preflight_repo" config user.signingkey "key::$other_signing_key"
if (cd "$preflight_repo" && env "${preflight_env[@]}" \
  SYQ_TEST_SIGNING_KEY="$other_signing_key" \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/failure.out" 2>&1; then
  echo 'preflight unexpectedly accepted another GitHub-registered signing key' >&2
  exit 1
fi
grep -F 'not the pinned maintainer key' "$work/failure.out" >/dev/null
git -C "$preflight_repo" config user.signingkey "key::$signing_key"
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
grep -F 'has no push or workflow_dispatch run on master' "$work/failure.out" >/dev/null
if (cd "$preflight_repo" && env "${preflight_env[@]}" \
  SYQ_TEST_EXISTING_CRATE_VERSION=9.9.9 \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/failure.out" 2>&1; then
  echo 'preflight unexpectedly accepted an existing crates.io version' >&2
  exit 1
fi
grep -F 'already published on crates.io' "$work/failure.out" >/dev/null

# Branch names and the coordination branch tip do not define the candidate.
git -C "$preflight_repo" switch -qc release-task
(cd "$preflight_repo" && env "${preflight_env[@]}" \
  "$script_dir/release-preflight.sh" v9.9.9) >/dev/null
git -C "$preflight_repo" switch --detach -q
(cd "$preflight_repo" && env "${preflight_env[@]}" \
  "$script_dir/release-preflight.sh" v9.9.9) >/dev/null
(cd "$preflight_repo" && env "${preflight_env[@]}" \
  "$script_dir/release-readiness.py" v9.9.9 --json) >"$work/readiness.json"
jq -e '.ready and (.ci.workflows | length == 3) and (.ssh.profile == "default")' \
  "$work/readiness.json" >/dev/null
# A detached checkout of an old master cannot pass against advancing remote master.
if (cd "$preflight_repo" && env "${preflight_env[@]}" \
  SYQ_TEST_PREFLIGHT_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/failure.out" 2>&1; then
  echo 'preflight unexpectedly accepted stale HEAD' >&2; exit 1
fi
grep -F 'HEAD is not synchronized with the remote master' "$work/failure.out" >/dev/null
printf 'uncommitted' >"$preflight_repo/untracked"
if (cd "$preflight_repo" && env "${preflight_env[@]}" \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/failure.out" 2>&1; then
  echo 'preflight unexpectedly accepted dirty HEAD' >&2; exit 1
fi
grep -F 'working tree is not clean' "$work/failure.out" >/dev/null
rm "$preflight_repo/untracked"
rm "$preflight_repo/.git/syq-release/real-ssh/$preflight_tree.json"
if (cd "$preflight_repo" && env "${preflight_env[@]}" \
  "$script_dir/release-preflight.sh" v9.9.9) >"$work/failure.out" 2>&1; then
  echo 'preflight unexpectedly accepted missing SSH evidence' >&2; exit 1
fi
grep -F 'real-SSH evidence is missing' "$work/failure.out" >/dev/null

# Existing releases resume immediately, even without local SSH receipts or CI.
git -C "$preflight_repo" -c tag.gpgsign=false tag v9.9.9
status=0
(cd "$preflight_repo" && env "${preflight_env[@]}" \
  SYQ_TEST_WORKFLOW_RUNS_JSON='{"workflow_runs":[]}' \
  "$script_dir/release-readiness.py" v9.9.9 --json) >"$work/resume.json" || status=$?
test "$status" -eq 1
jq -e '.ci == null and .next_action == "scripts/release-status.sh v9.9.9"' "$work/resume.json" >/dev/null

# Release status correlates the exact tag commit with runs, pending protected
# environments, and every publication destination.
status_bin="$work/status-bin"
mkdir "$status_bin"
status_commit=89abcdef0123456789abcdef0123456789abcdef
status_tag_object=76543210abcdef9876543210abcdef9876543210
status_tag=$(jq -er .tag sdk/python/src/syq/syq-release-manifest.json)
status_version=$(jq -er .version sdk/python/src/syq/syq-release-manifest.json)
status_formula_b64=$(printf 'url "https://github.com/greaber/syq/releases/download/%s/syq"\n' "$status_tag" | openssl base64 -A)
cat >"$status_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1:$2" in
  run:list) jq -cn --arg sha "$SYQ_TEST_STATUS_COMMIT" \
    --arg status "${SYQ_TEST_STATUS_RUN_STATUS:-in_progress}" \
    --arg conclusion "${SYQ_TEST_STATUS_RUN_CONCLUSION:-}" \
    --argjson include_failed "${SYQ_TEST_STATUS_INCLUDE_FAILED_RUN:-false}" '[
    (if $include_failed then
      {conclusion:"failure",databaseId:302,event:"push",headSha:$sha,status:"completed",
       url:"https://example.test/302",workflowName:"release"}
    else empty end),
    {conclusion:($conclusion | if length == 0 then null else . end),
     databaseId:303,event:"push",headSha:$sha,status:$status,
     url:"https://example.test/303",workflowName:"release"}]' ;;
  api:*)
    case " $* " in
      *"/git/matching-refs/tags/$SYQ_TEST_STATUS_TAG "*) jq -cn \
        --arg sha "$SYQ_TEST_STATUS_TAG_OBJECT" --arg tag "$SYQ_TEST_STATUS_TAG" \
        '[{ref:("refs/tags/" + $tag),object:{type:"tag",sha:$sha}}]' ;;
      *'/git/tags/'*) jq -cn --arg sha "$SYQ_TEST_STATUS_COMMIT" \
        --arg tag "${SYQ_TEST_STATUS_OBJECT_TAG:-$SYQ_TEST_STATUS_TAG}" \
        --arg type "${SYQ_TEST_STATUS_TARGET_TYPE:-commit}" \
        '{tag:$tag,object:{type:$type,sha:$sha},verification:{verified:true,reason:"valid"}}' ;;
      *'/releases?per_page=100 '*) jq -cn --arg tag "$SYQ_TEST_STATUS_TAG" \
        '[[{tag_name:$tag,draft:false,immutable:true,html_url:("https://example.test/" + $tag)}]]' ;;
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
  *'crates.io/'*) jq -cn --arg version "$SYQ_TEST_STATUS_VERSION" \
    '{versions:[{num:$version}]}' ;;
  *'pypi.org/'*) jq -cn --arg version "$SYQ_TEST_STATUS_VERSION" \
    '{info:{version:$version},releases:{($version):[{}]}}' ;;
  *) exit 2 ;;
esac
EOF
chmod 755 "$status_bin/gh" "$status_bin/curl"
PATH="$status_bin:$PATH" \
SYQ_TEST_STATUS_COMMIT="$status_commit" \
SYQ_TEST_STATUS_TAG_OBJECT="$status_tag_object" \
SYQ_TEST_STATUS_TAG="$status_tag" \
SYQ_TEST_STATUS_VERSION="$status_version" \
SYQ_TEST_STATUS_FORMULA_B64="$status_formula_b64" \
  "$script_dir/release-status.sh" --json "$status_tag" >"$work/status.json"
jq -e --arg commit "$status_commit" '
  .tag_state == "verified" and .tag_commit == $commit and
  .github_release.state == "published" and .github_release.immutable == true and
  .release_runs[0].databaseId == 303 and
  .release_runs[0].pending_environments == ["release"] and .complete == false and
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
SYQ_TEST_STATUS_TAG="$status_tag" \
SYQ_TEST_STATUS_VERSION="$status_version" \
SYQ_TEST_STATUS_FORMULA_B64="$status_formula_b64" \
SYQ_TEST_STATUS_RUN_STATUS=completed \
SYQ_TEST_STATUS_RUN_CONCLUSION=success \
  "$script_dir/release-status.sh" --json "$status_tag" >"$work/status-complete.json"
jq -e '.complete == true' "$work/status-complete.json" >/dev/null

# A failed provisional attempt does not make a later successful publication
# incomplete. Keep both runs in the report for auditability.
PATH="$status_bin:$PATH" \
SYQ_TEST_STATUS_COMMIT="$status_commit" \
SYQ_TEST_STATUS_TAG_OBJECT="$status_tag_object" \
SYQ_TEST_STATUS_TAG="$status_tag" \
SYQ_TEST_STATUS_VERSION="$status_version" \
SYQ_TEST_STATUS_FORMULA_B64="$status_formula_b64" \
SYQ_TEST_STATUS_INCLUDE_FAILED_RUN=true \
SYQ_TEST_STATUS_RUN_STATUS=completed \
SYQ_TEST_STATUS_RUN_CONCLUSION=success \
  "$script_dir/release-status.sh" --json "$status_tag" >"$work/status-retried.json"
jq -e '
  .complete == true and
  ([.release_runs[] | select(.conclusion == "failure")] | length) == 1 and
  ([.release_runs[] | select(.conclusion == "success")] | length) == 1
' "$work/status-retried.json" >/dev/null

PATH="$status_bin:$PATH" \
SYQ_TEST_STATUS_COMMIT="$status_commit" \
SYQ_TEST_STATUS_TAG_OBJECT="$status_tag_object" \
SYQ_TEST_STATUS_TAG="$status_tag" \
SYQ_TEST_STATUS_VERSION="$status_version" \
SYQ_TEST_STATUS_OBJECT_TAG="${status_tag}-mismatch" \
SYQ_TEST_STATUS_FORMULA_B64="$status_formula_b64" \
  "$script_dir/release-status.sh" --json "$status_tag" >"$work/status-name-mismatch.json"
jq -e '.tag_state == "name-mismatch" and .tag_commit == null' \
  "$work/status-name-mismatch.json" >/dev/null

PATH="$status_bin:$PATH" \
SYQ_TEST_STATUS_COMMIT="$status_commit" \
SYQ_TEST_STATUS_TAG_OBJECT="$status_tag_object" \
SYQ_TEST_STATUS_TAG="$status_tag" \
SYQ_TEST_STATUS_VERSION="$status_version" \
SYQ_TEST_STATUS_TARGET_TYPE=tag \
SYQ_TEST_STATUS_FORMULA_B64="$status_formula_b64" \
  "$script_dir/release-status.sh" --json "$status_tag" >"$work/status-nested-tag.json"
jq -e '.tag_state == "invalid-target" and .tag_commit == null' \
  "$work/status-nested-tag.json" >/dev/null

python3 "$script_dir/test-release-readiness.py"
python3 "$script_dir/test-release-timings.py"

echo 'release orchestration tests passed'
