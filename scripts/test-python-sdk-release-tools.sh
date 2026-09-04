#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-python-sdk-release-test.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/sdk/python/src/syq"
cp "$repo_dir/sdk/python/README.md" "$work/sdk/python/README.md"
cp "$repo_dir/sdk/python/pyproject.toml" "$work/sdk/python/pyproject.toml"
cp "$repo_dir/sdk/python/src/syq/syq-release-manifest.json" \
  "$work/sdk/python/src/syq/syq-release-manifest.json"

current_manifest="$repo_dir/sdk/python/src/syq/syq-release-manifest.json"
current_syq_version=$(jq -er .version "$current_manifest")
current_python_version=$(sed -n 's/^version = "\(.*\)"/\1/p' \
  "$repo_dir/sdk/python/pyproject.toml")
test "$current_python_version" = "$current_syq_version"
IFS=. read -r syq_major syq_minor _ <<<"$current_syq_version"
# Use a non-patch increment so the test proves that the incoming syq version is
# copied instead of independently incrementing the Python patch component.
next_syq_version="$syq_major.$((syq_minor + 1)).0"
next_python_version=$next_syq_version
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
grep -F "package \`$next_python_version\`" \
  "$work/sdk/python/README.md" >/dev/null
grep -F "manages syq \`$next_syq_version\`." \
  "$work/sdk/python/README.md" >/dev/null
test "$(grep -Fc "syq/sdk/python/v$next_syq_version/" \
  "$work/sdk/python/README.md")" -eq 2
cmp "$candidate" "$work/sdk/python/src/syq/syq-release-manifest.json"

# Portable tree fingerprint: GNU coreutils on Linux, Perl shasum on macOS.
tree_digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    find "$1" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum
  else
    find "$1" -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256
  fi
}
before=$(tree_digest "$work/sdk")
python3 "$script_dir/prepare-python-sdk-release.py" \
  --root "$work" --manifest "$candidate"
after=$(tree_digest "$work/sdk")
test "$before" = "$after"

misaligned="$work/misaligned"
mkdir -p "$misaligned/sdk/python/src/syq"
cp "$repo_dir/sdk/python/README.md" "$misaligned/sdk/python/README.md"
cp "$repo_dir/sdk/python/pyproject.toml" "$misaligned/sdk/python/pyproject.toml"
cp "$repo_dir/sdk/python/src/syq/syq-release-manifest.json" \
  "$misaligned/sdk/python/src/syq/syq-release-manifest.json"
sed -i 's/^version = ".*"/version = "0.0.0"/' \
  "$misaligned/sdk/python/pyproject.toml"
if python3 "$script_dir/prepare-python-sdk-release.py" \
  --root "$misaligned" --manifest "$candidate" \
  > "$work/misaligned.out" 2>&1; then
  echo 'misaligned Python and syq versions unexpectedly succeeded' >&2
  exit 1
fi
grep -F "current Python SDK 0.0.0 does not match pinned syq $current_syq_version" \
  "$work/misaligned.out" >/dev/null

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
