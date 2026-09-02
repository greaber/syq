#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-python-sdk-release-test.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/sdk/python/src/syq"
cp "$repo_dir/sdk/README.md" "$work/sdk/README.md"
cp "$repo_dir/sdk/python/README.md" "$work/sdk/python/README.md"
cp "$repo_dir/sdk/python/pyproject.toml" "$work/sdk/python/pyproject.toml"
cp "$repo_dir/sdk/python/src/syq/syq-release-manifest.json" \
  "$work/sdk/python/src/syq/syq-release-manifest.json"

current_manifest="$repo_dir/sdk/python/src/syq/syq-release-manifest.json"
current_syq_version=$(jq -er .version "$current_manifest")
current_python_version=$(sed -n 's/^version = "\(.*\)"/\1/p' \
  "$repo_dir/sdk/python/pyproject.toml")
IFS=. read -r syq_major syq_minor syq_patch <<<"$current_syq_version"
IFS=. read -r python_major python_minor python_patch <<<"$current_python_version"
next_syq_version="$syq_major.$syq_minor.$((syq_patch + 1))"
next_python_version="$python_major.$python_minor.$((python_patch + 1))"
candidate="$work/candidate.json"
jq --arg version "$next_syq_version" \
  '{
    schema,
    repository,
    version:$version,
    tag:("v" + $version),
    artifacts,
    installer,
    homebrew_formula,
    signature_scheme,
    signature
  }' \
  "$current_manifest" > "$candidate"
python3 "$script_dir/prepare-python-sdk-release.py" \
  --root "$work" --manifest "$candidate"

grep -Fx "version = \"$next_python_version\"" \
  "$work/sdk/python/pyproject.toml" >/dev/null
grep -F "For Python package \`$next_python_version\`, that release is syq \`$next_syq_version\`." \
  "$work/sdk/python/README.md" >/dev/null
test "$(grep -Fc "syq/sdk/python/v$next_syq_version/" \
  "$work/sdk/python/README.md")" -eq 2
grep -Fx "| \`$next_python_version\` | \`$next_syq_version\` |" \
  "$work/sdk/README.md" >/dev/null
cmp "$candidate" "$work/sdk/python/src/syq/syq-release-manifest.json"

before=$(find "$work/sdk" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)
python3 "$script_dir/prepare-python-sdk-release.py" \
  --root "$work" --manifest "$candidate"
after=$(find "$work/sdk" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)
test "$before" = "$after"

invalid="$work/invalid.json"
jq 'del(.signature)' "$candidate" > "$invalid"
if python3 "$script_dir/prepare-python-sdk-release.py" \
  --root "$work" --manifest "$invalid" > "$work/invalid.out" 2>&1; then
  echo 'manifest without a signature unexpectedly succeeded' >&2
  exit 1
fi
grep -F 'release manifest has no valid base64 signature' "$work/invalid.out" >/dev/null

jq '.unexpected = true' "$candidate" > "$invalid"
if python3 "$script_dir/prepare-python-sdk-release.py" \
  --root "$work" --manifest "$invalid" > "$work/invalid.out" 2>&1; then
  echo 'manifest with an unexpected field succeeded' >&2
  exit 1
fi
grep -F 'release manifest fields do not match the current schema' \
  "$work/invalid.out" >/dev/null

trusted_pr='https://github.com/greaber/syq/pull/123'
cat > "$work/pull-requests.json" <<EOF
[
  {
    "headRepository": {"nameWithOwner": "attacker/syq"},
    "url": "https://github.com/greaber/syq/pull/122"
  },
  {
    "headRepository": {"nameWithOwner": "greaber/syq"},
    "url": "$trusted_pr"
  }
]
EOF
selected_pr=$(jq -r --arg repository greaber/syq \
  -f "$script_dir/select-trusted-pr.jq" "$work/pull-requests.json")
test "$selected_pr" = "$trusted_pr"
selected_pr=$(jq -r --arg repository greaber/syq \
  -f "$script_dir/select-trusted-pr.jq" \
  <(jq 'map(select(.headRepository.nameWithOwner != "greaber/syq"))' \
    "$work/pull-requests.json"))
test -z "$selected_pr"

echo 'Python SDK release tool tests passed'
