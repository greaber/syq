#!/usr/bin/env bash
# Require a published crates.io version to be the exact package assembled from
# the release tag. Exit 3 means that the version has not been published yet.
set -euo pipefail

# Portable SHA-256 of one file: GNU coreutils on Linux, Perl shasum on macOS.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION CRATE_FILE" >&2
  exit 2
fi

version=$1
package=$2
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
  echo "invalid crate version: $version" >&2
  exit 2
fi
if [ ! -f "$package" ] || [ -L "$package" ]; then
  echo "missing regular crate package: $package" >&2
  exit 1
fi
command -v jq >/dev/null || { echo 'crate verification needs jq' >&2; exit 1; }
command -v sha256sum >/dev/null || command -v shasum >/dev/null \
  || { echo 'crate verification needs sha256sum or shasum' >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-crates-io.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
response="$work/response.json"

if [ -n "${SYQ_TEST_CRATES_IO_RESPONSE:-}" ]; then
  [ -n "${SYQ_TEST_CRATES_IO_STATUS:-}" ] || {
    echo 'SYQ_TEST_CRATES_IO_RESPONSE requires SYQ_TEST_CRATES_IO_STATUS' >&2
    exit 2
  }
  cp "$SYQ_TEST_CRATES_IO_RESPONSE" "$response"
  status=$SYQ_TEST_CRATES_IO_STATUS
else
  command -v curl >/dev/null || { echo 'crate verification needs curl' >&2; exit 1; }
  status=$(curl --silent --show-error --proto '=https' \
    --user-agent 'syq-release-verifier (https://github.com/greaber/syq)' \
    --output "$response" --write-out '%{http_code}' \
    "https://crates.io/api/v1/crates/syq/$version")
fi

case "$status" in
  200) ;;
  404)
    echo "syq $version is not published on crates.io"
    exit 3
    ;;
  *)
    echo "crates.io returned HTTP $status for syq $version" >&2
    jq -r '.errors[]?.detail // empty' "$response" >&2 || true
    exit 1
    ;;
esac

published_version=$(jq -er '.version.num' "$response") || {
  echo 'crates.io response has no version number' >&2
  exit 1
}
published_checksum=$(jq -er '.version.checksum' "$response") || {
  echo 'crates.io response has no package checksum' >&2
  exit 1
}
[ "$published_version" = "$version" ] || {
  echo "crates.io returned version $published_version, expected $version" >&2
  exit 1
}

local_checksum=$(sha256_file "$package")
[ "$published_checksum" = "$local_checksum" ] || {
  echo "crates.io syq $version differs from the package assembled from this tag" >&2
  echo "published: $published_checksum" >&2
  echo "local:     $local_checksum" >&2
  exit 1
}

echo "crates.io syq $version is byte-for-byte identical to this package"
