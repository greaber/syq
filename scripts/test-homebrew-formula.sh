#!/usr/bin/env bash
# Generate the formula in a path Homebrew recognizes as a tap and run its
# native style/parser checks. Intended for the disposable macOS CI runner.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
command -v brew >/dev/null || { echo 'Homebrew formula tests need brew' >&2; exit 1; }
command -v jq >/dev/null || { echo 'Homebrew formula tests need jq' >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-homebrew-test.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
formula_dir="$work/homebrew-tap/Formula"
mkdir -p "$formula_dir"
manifest="$work/manifest.json"
formula="$formula_dir/syq.rb"

jq -n --sort-keys '
  {repository:"https://github.com/greaber/syq",version:"0.1.0",tag:"v0.1.0",
   artifacts:{
    "linux-x86_64":{binary:{name:"syq-linux-x86_64",sha256:("1"*64)}},
    "linux-aarch64":{binary:{name:"syq-linux-aarch64",sha256:("2"*64)}},
    "macos-arm64":{binary:{name:"syq-macos-arm64",sha256:("3"*64)}},
    "macos-x86_64":{binary:{name:"syq-macos-x86_64",sha256:("4"*64)}}}}
' > "$manifest"
"$script_dir/generate-homebrew-formula.sh" "$manifest" "$formula"

HOMEBREW_NO_AUTO_UPDATE=1 brew style "$formula"
echo 'Homebrew formula tests passed'
