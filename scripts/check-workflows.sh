#!/usr/bin/env bash
# Run a checksum-pinned actionlint without installing it globally.
set -euo pipefail

ACTIONLINT_VERSION=1.7.12
os=$(uname -s)
architecture=$(uname -m)
case "$os:$architecture" in
  Linux:x86_64)
    platform=linux_amd64
    sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
    ;;
  Linux:aarch64|Linux:arm64)
    platform=linux_arm64
    sha256=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
    ;;
  Darwin:x86_64)
    platform=darwin_amd64
    sha256=5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644
    ;;
  Darwin:arm64)
    platform=darwin_arm64
    sha256=aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f
    ;;
  *)
    echo "actionlint $ACTIONLINT_VERSION is not pinned for $os $architecture" >&2
    exit 1
    ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-actionlint.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
archive="$work/actionlint.tar.gz"
url="https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT_VERSION/actionlint_${ACTIONLINT_VERSION}_${platform}.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --output "$archive" "$url"
if command -v sha256sum >/dev/null; then
  actual_sha256=$(sha256sum "$archive" | awk '{print $1}')
else
  actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
[ "$actual_sha256" = "$sha256" ] || {
  echo "actionlint archive checksum mismatch: $actual_sha256" >&2
  exit 1
}
tar -xzf "$archive" -C "$work" actionlint
"$work/actionlint" "$@"
