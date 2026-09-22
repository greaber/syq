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
  .#release --no-update-lock-file --no-link --print-out-paths --max-jobs auto -L)
install -m 755 "$output/bin/syq" "$dist/$asset"
install -m 644 "$output/bin/syq.gz" "$dist/$asset.gz"

# Execute the copied artifact outside the Nix output and exercise a real copy.
work=$(mktemp -d)
work=$(CDPATH='' cd -- "$work" && pwd -P)
trap 'rm -rf "$work"' EXIT
printf 'reproducible syq smoke test\n' > "$work/source"
"$dist/$asset" cp "$work/source" --into "$work/destination"
cmp "$work/source" "$work/destination/source"
gzip -d -c "$dist/$asset.gz" > "$work/uncompressed"
cmp "$dist/$asset" "$work/uncompressed"
if [ "$(uname -s)" = Linux ]; then
  # A release must run without a Nix installation or a dynamic ELF loader.
  readelf -l "$dist/$asset" > "$work/elf-headers"
  if grep 'INTERP' "$work/elf-headers"; then
    echo 'Release executable unexpectedly requires a dynamic loader.' >&2
    exit 1
  fi
else
  otool -L "$dist/$asset"
  if otool -L "$dist/$asset" | grep '/nix/store/'; then
    echo 'Release executable unexpectedly links to the Nix store.' >&2
    exit 1
  fi
  minimum=$(otool -l "$dist/$asset" | awk '$1 == "cmd" { command = $2 }
    (command == "LC_BUILD_VERSION" && $1 == "minos") ||
    (command == "LC_VERSION_MIN_MACOSX" && $1 == "version") { print $2 }')
  if [ "$(uname -m)" = arm64 ]; then
    test "$minimum" = 11.0 || { echo "Expected macOS 11.0, got $minimum" >&2; exit 1; }
    codesign --verify "$dist/$asset"
  else
    test "$minimum" = 10.12 || { echo "Expected macOS 10.12, got $minimum" >&2; exit 1; }
  fi
fi
