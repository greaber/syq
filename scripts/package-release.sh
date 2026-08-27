#!/usr/bin/env bash
# Validate a complete four-target build and create deterministic release
# metadata, checksums, the standalone installer, and the Homebrew formula.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 vVERSION DIST_DIR" >&2
  exit 2
fi

tag=$1
dist=$2
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "invalid release tag: $tag" >&2; exit 2 ;;
esac
version=${tag#v}
test -d "$dist" || { echo "missing distribution directory: $dist" >&2; exit 1; }
command -v jq >/dev/null || { echo "package-release needs jq" >&2; exit 1; }

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
package_version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_dir/Cargo.toml" | head -1)
test "$version" = "$package_version" || {
  echo "tag $tag does not match Cargo.toml version $package_version" >&2
  exit 1
}
protocol=$(sed -n 's/^pub const VERSION: u32 = \([0-9][0-9]*\);/\1/p' "$repo_dir/src/proto.rs")
test -n "$protocol" || { echo "could not read protocol version" >&2; exit 1; }

targets=(linux-x86_64 linux-aarch64 macos-arm64 macos-x86_64)
assets=(syq-linux-x86_64 syq-linux-aarch64 syq-macos-arm64 syq-macos-x86_64)
artifacts='{}'

for index in "${!targets[@]}"; do
  target=${targets[$index]}
  asset=${assets[$index]}
  binary="$dist/$asset"
  archive="$binary.gz"
  if [ ! -f "$binary" ] || [ -L "$binary" ]; then
    echo "missing regular asset: $binary" >&2
    exit 1
  fi
  if [ ! -f "$archive" ] || [ -L "$archive" ]; then
    echo "missing regular asset: $archive" >&2
    exit 1
  fi

  binary_hash=$(sha256sum "$binary" | awk '{print $1}')
  archive_hash=$(sha256sum "$archive" | awk '{print $1}')
  binary_size=$(stat -c '%s' "$binary")
  archive_size=$(stat -c '%s' "$archive")
  printf '%s  %s\n' "$binary_hash" "$asset" > "$binary.sha256"
  printf '%s  %s\n' "$archive_hash" "$asset.gz" > "$archive.sha256"

  entry=$(jq -cn \
    --arg binary_name "$asset" --arg binary_sha "$binary_hash" --argjson binary_size "$binary_size" \
    --arg archive_name "$asset.gz" --arg archive_sha "$archive_hash" --argjson archive_size "$archive_size" \
    '{binary:{name:$binary_name,sha256:$binary_sha,size:$binary_size},archive:{name:$archive_name,sha256:$archive_sha,size:$archive_size}}')
  artifacts=$(jq -cn --argjson all "$artifacts" --arg target "$target" --argjson entry "$entry" '$all + {($target):$entry}')
done

manifest_core=$(mktemp)
jq -n --sort-keys \
  --arg repository 'https://github.com/greaber/syq' \
  --arg version "$version" \
  --arg tag "$tag" \
  --arg helper_id "$tag-p$protocol" \
  --argjson artifacts "$artifacts" \
  '{schema:1,repository:$repository,version:$version,tag:$tag,helper_id:$helper_id,artifacts:$artifacts}' \
  > "$manifest_core"

"$script_dir/generate-installer.sh" "$manifest_core" "$dist/install.sh"
"$script_dir/generate-homebrew-formula.sh" "$manifest_core" "$dist/syq.rb"
installer_hash=$(sha256sum "$dist/install.sh" | awk '{print $1}')
installer_size=$(stat -c '%s' "$dist/install.sh")
formula_hash=$(sha256sum "$dist/syq.rb" | awk '{print $1}')
formula_size=$(stat -c '%s' "$dist/syq.rb")
jq --sort-keys \
  --arg installer_sha "$installer_hash" --argjson installer_size "$installer_size" \
  --arg formula_sha "$formula_hash" --argjson formula_size "$formula_size" \
  '. + {
    installer:{name:"install.sh",sha256:$installer_sha,size:$installer_size},
    homebrew_formula:{name:"syq.rb",sha256:$formula_sha,size:$formula_size}
  }' "$manifest_core" > "$dist/syq-release-manifest.json"
rm -f "$manifest_core"

# Anything unexpected here indicates a partial or contaminated release job.
expected=$(mktemp)
actual=$(mktemp)
trap 'rm -f "$expected" "$actual"' EXIT
for asset in "${assets[@]}"; do
  printf '%s\n' "$asset" "$asset.sha256" "$asset.gz" "$asset.gz.sha256"
done | sort > "$expected"
printf '%s\n' install.sh syq-release-manifest.json syq.rb >> "$expected"
sort -o "$expected" "$expected"
find "$dist" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort > "$actual"
diff -u "$expected" "$actual" || {
  echo "release directory contains missing or unexpected files" >&2
  exit 1
}
