#!/usr/bin/env bash
# Read-only validation of every locally auditable prerequisite before a tag is pushed.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CANONICAL_REPOSITORY=greaber/syq
HOMEBREW_REPOSITORY=greaber/homebrew-tap
RELEASE_ENVIRONMENT=release
REQUIRED_CHECKS=rust,sdks,macos,linux-arm64,conformance
CRATES_AUTH_ACTION=rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

if [ "$#" -ne 1 ]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH" >&2
  exit 2
fi
tag=$1
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "invalid syq release tag: $tag" >&2
  exit 2
}
version=${tag#v}

for command in git gh jq curl openssl ssh-keygen python3; do
  command -v "$command" >/dev/null || die "release preflight needs $command"
done

root=$(git rev-parse --show-toplevel 2>/dev/null) || die 'run this from the syq repository'
cd "$root"
[ "$(git symbolic-ref --short HEAD 2>/dev/null)" = master ] \
  || die 'release preflight must run on the master branch'
[ -z "$(git status --porcelain)" ] || die 'working tree is not clean'
python3 scripts/check-python-api-sync.py

origin_url=$(git config --get remote.origin.url 2>/dev/null || true)
origin_url=${origin_url%.git}
if [ "$origin_url" != "git@github.com:$CANONICAL_REPOSITORY" ] \
  && [ "$origin_url" != "ssh://git@github.com/$CANONICAL_REPOSITORY" ] \
  && [ "$origin_url" != "https://github.com/$CANONICAL_REPOSITORY" ]; then
  die "origin is not the canonical $CANONICAL_REPOSITORY repository"
fi
[ "${GH_HOST:-github.com}" = github.com ] || die 'GH_HOST must be github.com'
[ "$(gh repo view "$CANONICAL_REPOSITORY" --json nameWithOwner --jq .nameWithOwner)" = "$CANONICAL_REPOSITORY" ] \
  || die "gh resolved an unexpected repository"

head=$(git rev-parse HEAD)
local_master=$(git rev-parse refs/heads/master)
tracking_master=$(git rev-parse refs/remotes/origin/master 2>/dev/null) \
  || die 'origin/master is unavailable; fetch it first'
remote_master=$(git ls-remote origin refs/heads/master | awk 'NR == 1 {print $1}')
[ "$head" = "$local_master" ] || die 'HEAD is not the local master tip'
[ "$head" = "$tracking_master" ] || die "master is not synchronized with origin/master ($tracking_master)"
[ "$head" = "$remote_master" ] || die "master is not synchronized with the remote master ($remote_master)"

cargo_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ "$cargo_version" = "$version" ] \
  || die "tag $tag does not match Cargo.toml version $cargo_version"
lock_version=$(awk '
  $0 == "[[package]]" {name=""; version=""}
  $0 == "name = \"syq\"" {name="syq"}
  name == "syq" && /^version = / {gsub(/^version = "|"$/, ""); print; exit}
' Cargo.lock)
[ "$lock_version" = "$version" ] \
  || die "Cargo.lock syq version $lock_version does not match $version"

if git show-ref --verify --quiet "refs/tags/$tag"; then
  die "local tag $tag already exists"
fi
remote_tags=$(git ls-remote --tags origin "refs/tags/$tag" "refs/tags/$tag^{}") \
  || die "cannot inspect remote tag $tag"
[ -z "$remote_tags" ] \
  || die "remote tag $tag already exists"

checks=$(gh api "repos/$CANONICAL_REPOSITORY/commits/$head/check-runs?filter=latest&per_page=100")
IFS=, read -ra check_names <<<"$REQUIRED_CHECKS"
for check_name in "${check_names[@]}"; do
  conclusion=$(jq -r --arg name "$check_name" '
    [.check_runs[] | select(.name == $name)] |
    sort_by([(.started_at // .completed_at // ""), (.id // 0)]) |
    if length == 0 then "missing" else last.conclusion // "pending" end
  ' <<<"$checks")
  [ "$conclusion" = success ] \
    || die "required check $check_name is $conclusion on $head"
done
"$script_dir/verify-release-ci.sh" "$CANONICAL_REPOSITORY" "$head"

signing_key=$(git config --get user.signingkey 2>/dev/null || true)
signing_key=${signing_key#key::}
signing_identity=$(awk '{print $1 " " $2}' <<<"$signing_key")
[ "$(git config --get gpg.format 2>/dev/null || true)" = ssh ] \
  || die 'gpg.format must be ssh for release tag signing'
[ "$(git config --bool --get tag.gpgsign 2>/dev/null || true)" = true ] \
  || die 'tag.gpgsign must be enabled'
[[ "$signing_identity" == ssh-*' '* ]] || die 'user.signingkey is not an inline SSH public key'
signing_fingerprint=$(ssh-keygen -lf /dev/stdin <<<"$signing_identity" | awk '{print $2}') \
  || die 'cannot fingerprint user.signingkey'
github_login=$(gh api user --jq .login)
github_signing_keys=$(gh api "users/$github_login/ssh_signing_keys?per_page=100")
jq -e --arg key "$signing_identity" '
  any(.[]; ((.key | split(" "))[0:2] | join(" ")) == $key)
' <<<"$github_signing_keys" >/dev/null \
  || die "tag signing key $signing_fingerprint is not registered as a GitHub SSH signing key"

permissions=$(gh api "repos/$CANONICAL_REPOSITORY/actions/permissions")
jq -e '.enabled == true and .allowed_actions == "selected" and .sha_pinning_required == true' \
  <<<"$permissions" >/dev/null \
  || die 'GitHub Actions must be enabled with selected actions and SHA pinning required'
selected_actions=$(gh api "repos/$CANONICAL_REPOSITORY/actions/permissions/selected-actions")
jq -e '.github_owned_allowed == true and .verified_allowed == false' \
  <<<"$selected_actions" >/dev/null \
  || die 'unexpected GitHub selected-actions policy'
mapfile -t workflow_actions < <(sed -n 's/^[[:space:]]*uses:[[:space:]]*\([^ #]*\).*/\1/p' .github/workflows/*.yml | sort -u)
for action in "${workflow_actions[@]}"; do
  case "$action" in
    ./*) continue ;;
  esac
  ref=${action##*@}
  [[ "$ref" =~ ^[0-9a-f]{40}$ ]] || die "workflow action is not pinned to a full SHA: $action"
  case "$action" in
    actions/*) ;;
    *) jq -e --arg action "$action" '.patterns_allowed | index($action) != null' \
         <<<"$selected_actions" >/dev/null \
         || die "workflow action is not selected in repository policy: $action" ;;
  esac
done
jq -e --arg action "$CRATES_AUTH_ACTION" '.patterns_allowed | index($action) != null' \
  <<<"$selected_actions" >/dev/null \
  || die "crates.io authentication action is not selected: $CRATES_AUTH_ACTION"

environment=$(gh api "repos/$CANONICAL_REPOSITORY/environments/$RELEASE_ENVIRONMENT")
jq -e '.name == "release" and any(.protection_rules[]?; .type == "required_reviewers")' \
  <<<"$environment" >/dev/null \
  || die 'release environment is missing its required-reviewer protection'
deployment_policies=$(gh api "repos/$CANONICAL_REPOSITORY/environments/$RELEASE_ENVIRONMENT/deployment-branch-policies")
jq -e 'any(.branch_policies[]?; .type == "tag" and .name == "v*")' \
  <<<"$deployment_policies" >/dev/null \
  || die 'release environment is not restricted to v* tags'
secrets=$(gh secret list --repo "$CANONICAL_REPOSITORY" --env "$RELEASE_ENVIRONMENT" --json name)
for secret in SYQ_RELEASE_SIGNING_KEY_PEM_B64 HOMEBREW_TAP_DEPLOY_KEY; do
  jq -e --arg name "$secret" 'any(.[]; .name == $name)' <<<"$secrets" >/dev/null \
    || die "release environment secret is missing: $secret"
done
variables=$(gh variable list --repo "$CANONICAL_REPOSITORY" --json name,value)
public_key=$(jq -er '.[] | select(.name == "SYQ_RELEASE_PUBLIC_KEY") | .value' <<<"$variables") \
  || die 'repository variable is missing: SYQ_RELEASE_PUBLIC_KEY'
[ "$(printf '%s' "$public_key" | openssl base64 -d -A | wc -c | tr -d '[:space:]')" -eq 32 ] \
  || die 'SYQ_RELEASE_PUBLIC_KEY is not a base64-encoded 32-byte key'

releases=$(gh api --paginate --slurp "repos/$CANONICAL_REPOSITORY/releases?per_page=100")
jq -e --arg tag "$tag" 'flatten | any(.[]; .tag_name == $tag) | not' <<<"$releases" >/dev/null \
  || die "GitHub release $tag already exists"
crates=$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --user-agent 'syq-release-preflight (https://github.com/greaber/syq)' \
  https://crates.io/api/v1/crates/syq)
jq -e --arg version "$version" 'any(.versions[]?; .num == $version) | not' <<<"$crates" >/dev/null \
  || die "syq $version is already published on crates.io"
formula_json=$(gh api "repos/$HOMEBREW_REPOSITORY/contents/Formula/syq.rb")
formula=$(jq -er .content <<<"$formula_json" | tr -d '\n' | openssl base64 -d -A)
if grep -F "/releases/download/$tag/" <<<"$formula" >/dev/null; then
  die "Homebrew tap already references $tag"
fi

printf 'Release preflight passed for %s at %s.\n' "$tag" "$head"
printf 'Tag signing key: %s\n' "$signing_fingerprint"
printf 'Required checks: %s\n' "$REQUIRED_CHECKS"
printf 'No existing GitHub release, crates.io version, or Homebrew formula was found.\n'
