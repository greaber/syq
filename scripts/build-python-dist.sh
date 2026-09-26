#!/bin/sh
# Build exactly the Python artifacts used by publishing, without publishing.
# POSIX sh: release runners on every platform run this without pinned tools.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
dist=${1:?usage: scripts/build-python-dist.sh OUTPUT_DIRECTORY}
mkdir -p "$dist"
output=$(nix --extra-experimental-features 'nix-command flakes' build \
  .#python-dist --no-update-lock-file --no-link --print-out-paths -L)
cp "$output"/* "$dist/"
