#!/usr/bin/env bash
# Build exactly the Python artifacts used by publishing, without publishing.
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
dist=${1:?usage: scripts/build-python-dist.sh OUTPUT_DIRECTORY}
mkdir -p "$dist"
output=$(nix --extra-experimental-features 'nix-command flakes' build \
  .#python-dist --no-update-lock-file --no-link --print-out-paths -L)
cp "$output"/* "$dist/"
