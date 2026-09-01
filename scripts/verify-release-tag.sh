#!/usr/bin/env bash
# Require a GitHub-verified annotated tag that directly names the commit being
# built by this release workflow, is reachable from the protected branch, and
# has every named CI check concluded successfully. Pull requests are checked
# against their own head, not against the branch they land on, so a merge can
# leave the branch red; the tagged commit's own check runs are what prove it.
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 OWNER/REPOSITORY TAG EXPECTED_COMMIT PROTECTED_BRANCH REQUIRED_CHECKS" >&2
  echo "REQUIRED_CHECKS is a comma-separated list of check run names" >&2
  exit 2
fi
repository=$1
tag=$2
expected_commit=$3
protected_branch=$4
required_checks=$5
case "$repository" in
  */*) ;;
  *) echo "invalid GitHub repository: $repository" >&2; exit 2 ;;
esac
case "$tag" in
  ''|*[!A-Za-z0-9._-]*) echo "unsafe release tag: $tag" >&2; exit 2 ;;
esac
case "$expected_commit" in
  *[!0-9a-f]*|'') echo "invalid expected commit: $expected_commit" >&2; exit 2 ;;
esac
case "$protected_branch" in
  ''|*[!A-Za-z0-9._/-]*) echo "unsafe protected branch: $protected_branch" >&2; exit 2 ;;
esac
case "$required_checks" in
  ''|*[!A-Za-z0-9._,-]*) echo "unsafe required check list: $required_checks" >&2; exit 2 ;;
esac
command -v gh >/dev/null || { echo 'tag verification needs gh' >&2; exit 1; }
command -v jq >/dev/null || { echo 'tag verification needs jq' >&2; exit 1; }

reference=$(gh api "repos/$repository/git/ref/tags/$tag")
object_type=$(jq -er '.object.type' <<<"$reference")
tag_sha=$(jq -er '.object.sha' <<<"$reference")
test "$object_type" = tag || {
  echo "release tag $tag is lightweight; a signed annotated tag is required" >&2
  exit 1
}

tag_object=$(gh api "repos/$repository/git/tags/$tag_sha")
actual_tag=$(jq -er '.tag' <<<"$tag_object")
target_type=$(jq -er '.object.type' <<<"$tag_object")
target_commit=$(jq -er '.object.sha' <<<"$tag_object")
verified=$(jq -r '.verification.verified' <<<"$tag_object")
reason=$(jq -r '.verification.reason' <<<"$tag_object")
test "$actual_tag" = "$tag" || {
  echo "tag object names $actual_tag, expected $tag" >&2
  exit 1
}
test "$target_type" = commit || {
  echo "release tag $tag points to a $target_type, not a commit" >&2
  exit 1
}
test "$target_commit" = "$expected_commit" || {
  echo "release tag $tag resolves to $target_commit, not workflow commit $expected_commit" >&2
  exit 1
}
if [ "$verified" != true ] || [ "$reason" != valid ]; then
  echo "GitHub did not verify the signature on release tag $tag (reason: $reason)" >&2
  exit 1
fi

comparison=$(gh api "repos/$repository/compare/$target_commit...$protected_branch")
base_commit=$(jq -er '.base_commit.sha' <<<"$comparison")
merge_base=$(jq -er '.merge_base_commit.sha' <<<"$comparison")
if [ "$base_commit" != "$target_commit" ] || [ "$merge_base" != "$target_commit" ]; then
  echo "release commit $target_commit is not reachable from protected branch $protected_branch" >&2
  exit 1
fi

check_runs=$(gh api "repos/$repository/commits/$target_commit/check-runs?filter=latest&per_page=100")
IFS=, read -ra check_names <<<"$required_checks"
for check_name in "${check_names[@]}"; do
  conclusion=$(jq -r --arg name "$check_name" '
    [.check_runs[] | select(.name == $name)] | if length == 0 then "missing"
    elif length > 1 then "ambiguous" else .[0].conclusion // "pending" end' <<<"$check_runs")
  test "$conclusion" = success || {
    echo "required check $check_name is $conclusion on release commit $target_commit" >&2
    exit 1
  }
done

echo "verified signed annotated tag $tag at $target_commit on $protected_branch with checks $required_checks"
