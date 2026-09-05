#!/usr/bin/env bash
# Compile the registry package before any permanent release publication.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 vVERSION OUTPUT_DIR" >&2; exit 2; }
tag=$1
output=$2
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
version=${tag#v}
[ -z "$(git status --porcelain)" ] || { echo 'source package needs a clean checkout' >&2; exit 1; }
metadata=$(cargo metadata --locked --no-deps --format-version 1)
[ "$(jq -r '.packages[] | select(.name == "syq") | .version' <<<"$metadata")" = "$version" ]
target=$(jq -er .target_directory <<<"$metadata")
package="$target/package/syq-$version.crate"
rm -f -- "$package"
cargo package --locked
mkdir -p "$output"
cp "$package" "$output/"
echo "Validated source crate $tag at $(git rev-parse HEAD)"
