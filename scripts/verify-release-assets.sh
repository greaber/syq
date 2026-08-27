#!/usr/bin/env bash
# Download a GitHub release and require every published asset to be byte-for-
# byte identical to the locally assembled release directory.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 TAG LOCAL_DIST_DIR" >&2
  exit 2
fi
tag=$1
local_dist=$2
test -d "$local_dist" || { echo "missing local release directory: $local_dist" >&2; exit 1; }
command -v gh >/dev/null || { echo 'release verification needs gh' >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-release-assets.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
published="$work/published"
mkdir "$published"
gh release download "$tag" --dir "$published"

local_names="$work/local-names"
published_names="$work/published-names"
find "$local_dist" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort > "$local_names"
find "$published" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort > "$published_names"
diff -u "$local_names" "$published_names" || {
  echo "published release $tag has a different asset inventory" >&2
  exit 1
}

while IFS= read -r name; do
  cmp -s "$local_dist/$name" "$published/$name" || {
    echo "published release asset differs from this build: $name" >&2
    exit 1
  }
done < "$local_names"

echo "published release $tag is byte-for-byte identical to this build"
