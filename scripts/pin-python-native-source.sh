#!/usr/bin/env bash
# Record the source tree used by the Python release recipe.
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
tag=$(jq -er .tag sdk/python/src/syq/syq-release-manifest.json)
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
revision=$(git rev-parse "refs/tags/$tag^{commit}")
source=$(nix --extra-experimental-features 'nix-command flakes' flake prefetch \
  --json "github:greaber/syq/$revision")
jq -n --arg tag "$tag" --arg rev "$revision" --arg hash "$(jq -er .hash <<<"$source")" \
  '{tag:$tag, rev:$rev, narHash:$hash}' > sdk/python/native-source.json
