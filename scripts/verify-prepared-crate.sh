#!/usr/bin/env bash
# Repack cheaply and compare against the package compiled in source-crate.
# cargo publish --no-verify uses the same locked inputs after this check.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 vVERSION PREPARED_DIR" >&2; exit 2; }
tag=$1
prepared=$2
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
version=${tag#v}
[ -z "$(git status --porcelain)" ] || { echo 'source package needs a clean checkout' >&2; exit 1; }
metadata=$(cargo metadata --locked --no-deps --format-version 1)
[ "$(jq -r '.packages[] | select(.name == "syq") | .version' <<<"$metadata")" = "$version" ]
target=$(jq -er .target_directory <<<"$metadata")
package="$target/package/syq-$version.crate"
[ -f "$prepared/syq-$version.crate" ] && [ ! -L "$prepared/syq-$version.crate" ]
rm -f -- "$package"
cargo package --locked --no-verify
cmp "$prepared/syq-$version.crate" "$package" || {
  echo 'source package differs from the validated artifact; refusing publication' >&2
  exit 1
}
echo "Source package matches validated $tag bytes."
