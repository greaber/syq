#!/usr/bin/env bash
# Report release progress without changing GitHub, registries, or local refs.
set -euo pipefail

repository=greaber/syq
homebrew_repository=greaber/homebrew-tap
json=false
tag=
for argument in "$@"; do
  case "$argument" in
    --json) json=true ;;
    v[0-9]*.[0-9]*.[0-9]*) [ -z "$tag" ] || { echo 'only one tag may be supplied' >&2; exit 2; }; tag=$argument ;;
    *) echo "usage: $0 [--json] [vMAJOR.MINOR.PATCH]" >&2; exit 2 ;;
  esac
done
if [ -z "$tag" ]; then
  version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
  tag="v$version"
fi
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid release tag: $tag" >&2; exit 2; }
version=${tag#v}
for command in gh jq curl openssl; do
  command -v "$command" >/dev/null || { echo "release status needs $command" >&2; exit 1; }
done

tag_commit=
tag_state=missing
references=$(gh api "repos/$repository/git/matching-refs/tags/$tag")
reference=$(jq -c --arg ref "refs/tags/$tag" 'map(select(.ref == $ref)) | first // null' <<<"$references")
if [ "$reference" != null ]; then
  object_type=$(jq -er .object.type <<<"$reference")
  object_sha=$(jq -er .object.sha <<<"$reference")
  if [ "$object_type" = tag ]; then
    tag_object=$(gh api "repos/$repository/git/tags/$object_sha")
    actual_tag=$(jq -er .tag <<<"$tag_object")
    target_type=$(jq -er .object.type <<<"$tag_object")
    target_sha=$(jq -er .object.sha <<<"$tag_object")
    verified=$(jq -r '.verification.verified == true and .verification.reason == "valid"' <<<"$tag_object")
    if [ "$actual_tag" != "$tag" ]; then
      tag_state=name-mismatch
    elif [ "$target_type" != commit ]; then
      tag_state=invalid-target
    else
      tag_commit=$target_sha
      [ "$verified" = true ] && tag_state=verified || tag_state=unverified
    fi
  elif [ "$object_type" = commit ]; then
    tag_commit=$object_sha
    tag_state=lightweight
  else
    tag_state=invalid-target
  fi
fi

releases=$(gh api --paginate --slurp "repos/$repository/releases?per_page=100")
release=$(jq -c --arg tag "$tag" 'flatten | map(select(.tag_name == $tag)) | first // null' <<<"$releases")
github_state=missing
github_url=
github_immutable=false
if [ "$release" != null ]; then
  github_url=$(jq -r .html_url <<<"$release")
  github_immutable=$(jq -r '.immutable // false' <<<"$release")
  if [ "$(jq -r .draft <<<"$release")" = true ]; then github_state=draft; else github_state=published; fi
fi

runs=$(gh run list --repo "$repository" --workflow release.yml --branch "$tag" --limit 20 \
  --json conclusion,databaseId,event,headSha,status,url,workflowName)
if [ -n "$tag_commit" ]; then
  runs=$(jq -c --arg sha "$tag_commit" '[.[] | select(.headSha == $sha)]' <<<"$runs")
fi
runs_with_environments='[]'
while IFS= read -r run; do
  [ -n "$run" ] || continue
  run_id=$(jq -er .databaseId <<<"$run")
  if pending=$(gh api "repos/$repository/actions/runs/$run_id/pending_deployments" 2>/dev/null); then
    environments=$(jq -c '[.[] | .environment.name]' <<<"$pending")
  else
    environments=null
  fi
  run=$(jq -c --argjson environments "$environments" '. + {pending_environments:$environments}' <<<"$run")
  runs_with_environments=$(jq -c --argjson run "$run" '. + [$run]' <<<"$runs_with_environments")
done < <(jq -c '.[]' <<<"$runs")

crates_state=unknown
if crates=$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --user-agent 'syq-release-status (https://github.com/greaber/syq)' \
  https://crates.io/api/v1/crates/syq 2>/dev/null); then
  if jq -e --arg version "$version" 'any(.versions[]?; .num == $version)' <<<"$crates" >/dev/null; then
    crates_state=published
  else
    crates_state=missing
  fi
fi

pypi_state=unknown
pypi_version=
mapped_tag=$(jq -r '.tag // empty' sdk/python/src/syq/syq-release-manifest.json 2>/dev/null || true)
if [ "$mapped_tag" = "$tag" ]; then
  pypi_version=$(sed -n 's/^version = "\(.*\)"/\1/p' sdk/python/pyproject.toml | head -1)
fi
if pypi=$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  https://pypi.org/pypi/syq/json 2>/dev/null); then
  if [ -n "$pypi_version" ]; then
    if jq -e --arg version "$pypi_version" '.releases[$version] | length > 0' <<<"$pypi" >/dev/null; then
      pypi_state=published
    else
      pypi_state=missing
    fi
  else
    pypi_state=unmapped
    pypi_version=$(jq -r '.info.version // empty' <<<"$pypi")
  fi
fi

homebrew_state=unknown
if formula_json=$(gh api "repos/$homebrew_repository/contents/Formula/syq.rb" 2>/dev/null); then
  formula=$(jq -er .content <<<"$formula_json" | tr -d '\n' | openssl base64 -d -A)
  if grep -F "/releases/download/$tag/" <<<"$formula" >/dev/null; then
    homebrew_state=published
  else
    homebrew_state=missing
  fi
fi

result=$(jq -n \
  --arg repository "$repository" --arg tag "$tag" --arg tag_commit "$tag_commit" \
  --arg tag_state "$tag_state" --arg github_state "$github_state" \
  --arg github_url "$github_url" --argjson github_immutable "$github_immutable" \
  --argjson runs "$runs_with_environments" --arg crates "$crates_state" \
  --arg pypi "$pypi_state" --arg pypi_version "$pypi_version" \
  --arg homebrew "$homebrew_state" '
  {repository:$repository, tag:$tag,
   tag_commit:($tag_commit | if length > 0 then . else null end),
   tag_state:$tag_state,
   github_release:{state:$github_state, immutable:$github_immutable,
     url:($github_url | if length > 0 then . else null end)},
   release_runs:$runs,
   publications:{crates_io:{version:($tag | ltrimstr("v")), state:$crates},
     pypi:{version:($pypi_version | if length > 0 then . else null end), state:$pypi},
     homebrew:{tag:$tag, state:$homebrew}}}
  ')

if [ "$json" = true ]; then
  jq . <<<"$result"
  exit 0
fi
jq -r '
  "Release \(.tag)",
  "  tag:       \(.tag_state)\(if .tag_commit then " at " + .tag_commit else "" end)",
  "  GitHub:    \(.github_release.state)\(if .github_release.immutable then " (immutable)" else "" end)",
  "  crates.io: \(.publications.crates_io.state)",
  "  PyPI SDK:  \(.publications.pypi.state)\(if .publications.pypi.version then " (" + .publications.pypi.version + ")" else "" end)",
  "  Homebrew:  \(.publications.homebrew.state)",
  (if (.release_runs | length) == 0 then "  runs:       none"
   else .release_runs[] | "  run \(.databaseId): \(.status)\(if .conclusion then "/" + .conclusion else "" end), pending environments: \(if .pending_environments == null then "unknown" else (.pending_environments | join(", ") | if length == 0 then "none" else . end) end)\n    \(.url)" end)
' <<<"$result"
