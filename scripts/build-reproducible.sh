#!/usr/bin/env bash
# Build the host's standalone release artifact from the checked-in Nix lock.
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "usage: $0 DIST_DIR" >&2
  exit 2
fi
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dist=$1
mkdir -p "$dist"
dist=$(CDPATH='' cd -- "$dist" && pwd)
cd "$repo"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) asset=syq-linux-x86_64 ;;
  Linux:aarch64) asset=syq-linux-aarch64 ;;
  Darwin:arm64) asset=syq-macos-arm64 ;;
  Darwin:x86_64) asset=syq-macos-x86_64 ;;
  *) echo 'No reproducible release recipe for this host.' >&2; exit 1 ;;
esac
output=$(nix --extra-experimental-features 'nix-command flakes' build \
  .#release --no-update-lock-file --no-link --print-out-paths -L)
cp "$output/bin/syq" "$dist/$asset"
cp "$output/bin/syq.gz" "$dist/$asset.gz"
chmod 755 "$dist/$asset"

# Execute the copied artifact outside the Nix output and exercise a real copy.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'reproducible syq smoke test\n' > "$work/source"
"$dist/$asset" cp "$work/source" --into "$work/destination"
cmp "$work/source" "$work/destination/source"
if [ "$(uname -s)" = Linux ]; then
  # A release must run without a Nix installation or a dynamic ELF loader.
  if readelf -l "$dist/$asset" | grep 'INTERP'; then
    echo 'Release executable unexpectedly requires a dynamic loader.' >&2
    exit 1
  fi
else
  otool -L "$dist/$asset"
  if otool -L "$dist/$asset" | grep '/nix/store/'; then
    echo 'Release executable unexpectedly links to the Nix store.' >&2
    exit 1
  fi
  codesign --verify "$dist/$asset"
fi
