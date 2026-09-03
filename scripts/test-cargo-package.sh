#!/usr/bin/env bash
# Build the registry package outside the checkout and require Cargo's VCS
# metadata to produce a stable source identity.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_dir/Cargo.toml" | head -1)
target_dir=$(cargo metadata --no-deps --format-version 1 \
  --manifest-path "$repo_dir/Cargo.toml" | jq -r .target_directory)
package="$target_dir/package/syq-$version.crate"

# Cargo can leave trailing bytes when replacing a same-version archive with a
# shorter one. Remove only this generated package so extraction verifies the
# newly written archive rather than stale local target state.
rm -f -- "$package"
cargo package --locked --manifest-path "$repo_dir/Cargo.toml"
if [ ! -f "$package" ] || [ -L "$package" ]; then
  echo "cargo did not create $package" >&2
  exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-cargo-package.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
tar -xzf "$package" -C "$work"
source_dir="$work/syq-$version"
revision=$(jq -er '.git.sha1 | select(test("^[0-9a-fA-F]{40}$"))' \
  "$source_dir/.cargo_vcs_info.json")
expected="v$version+dev.${revision:0:12}"

CARGO_TARGET_DIR="$work/target" cargo build --locked \
  --manifest-path "$source_dir/Cargo.toml" --bin syq
actual=$("$work/target/debug/syq" --build-identity)
[ "$actual" = "$expected" ] || {
  echo "packaged source identity is $actual, expected $expected" >&2
  exit 1
}

echo "cargo package source identity is stable at $expected"
