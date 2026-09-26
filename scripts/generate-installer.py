#!/usr/bin/env python3
"""Generate a version-pinned installer whose trusted hashes come from the signed
release manifest. The generated script needs only POSIX sh at install time.

Usage: scripts/generate-installer.py MANIFEST OUTPUT
"""
import os
import re
import subprocess
import sys

from tooling import (JqError, captured, exit_on_failure, get, is_number, load_file, require,
                     test)

DOWNLOAD_BASE = "https://dl.syq.christmas"
TARGETS = {
    "linux-x86_64": "Linux:x86_64",
    "linux-aarch64": "Linux:aarch64|Linux:arm64",
    "macos-arm64": "Darwin:arm64|Darwin:aarch64",
    "macos-x86_64": "Darwin:x86_64",
}

# The installer's opening; @VERSION@, @DOWNLOAD_BASE@, and @TAG@ are replaced.
HEAD = r'''#!/bin/sh
# Generated for syq @VERSION@. Inspect this script before running it; the exact
# version remains at @DOWNLOAD_BASE@/@TAG@/install.sh.
set -eu

version='@VERSION@'
tag='@TAG@'
base_url=${SYQ_INSTALL_BASE_URL:-'@DOWNLOAD_BASE@/@TAG@'}
bin_dir=${HOME:+$HOME/.local/bin}

usage() {
  cat <<USAGE
Install syq @VERSION@ without sudo.

Usage: install.sh [--bin-dir DIR]

The default is $HOME/.local/bin. The installer detects this host, downloads
the pinned release archive, checks its embedded SHA-256 and size, verifies the
binary's version and release identity, then replaces the destination atomically.
USAGE
}

while [ $# -gt 0 ]; do
  case $1 in
    --bin-dir)
      [ $# -ge 2 ] || { echo 'install.sh: --bin-dir needs a value' >&2; exit 2; }
      bin_dir=$2
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) echo "install.sh: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[ -n "${bin_dir:-}" ] || { echo 'install.sh: HOME is not set; pass --bin-dir DIR' >&2; exit 1; }

case "$(uname -s):$(uname -m)" in
'''

# The installer after its platform table, copied verbatim.
TAIL = r'''*) echo "install.sh: unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-install.XXXXXXXX")
install_tmp=
cleanup() {
  rm -rf "$work"
  [ -z "$install_tmp" ] || rm -f "$install_tmp"
}
trap cleanup EXIT HUP INT TERM
download="$work/$archive"
program="$work/syq"

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --retry 2 --connect-timeout 10 \
      --proto '=https' --proto-redir '=https' --output "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget --quiet --https-only --timeout=10 --tries=3 -O "$2" "$1"
  else
    echo 'install.sh: downloading syq requires curl or wget' >&2
    return 1
  fi
}

fetch "$base_url/$archive" "$download"
actual_size=$(wc -c < "$download" | tr -d '[:space:]')
[ "$actual_size" = "$expected_size" ] || {
  echo "install.sh: downloaded archive has size $actual_size, expected $expected_size" >&2
  exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
  actual_sha=$(sha256sum "$download" | sed 's/[[:space:]].*$//')
elif command -v shasum >/dev/null 2>&1; then
  actual_sha=$(shasum -a 256 "$download" | sed 's/[[:space:]].*$//')
elif command -v openssl >/dev/null 2>&1; then
  actual_sha=$(openssl dgst -sha256 "$download" | sed 's/^.*= //')
else
  echo 'install.sh: verification requires sha256sum, shasum, or openssl' >&2
  exit 1
fi
[ "$actual_sha" = "$expected_sha" ] || {
  echo 'install.sh: downloaded archive failed SHA-256 verification' >&2
  exit 1
}

gzip -dc "$download" > "$program"
chmod 755 "$program"
got=$("$program" --version 2>/dev/null) || {
  echo 'install.sh: downloaded syq cannot run on this host' >&2
  exit 1
}
[ "$got" = "syq $version" ] || {
  echo "install.sh: downloaded binary reports an unexpected version: $got" >&2
  exit 1
}
got_id=$("$program" --build-identity 2>/dev/null) || {
  echo 'install.sh: downloaded syq has no build identity' >&2
  exit 1
}
[ "$got_id" = "$tag" ] || {
  echo "install.sh: downloaded binary reports an unexpected identity: $got_id" >&2
  exit 1
}

mkdir -p "$bin_dir"
[ ! -d "$bin_dir/syq" ] || {
  echo "install.sh: destination is a directory: $bin_dir/syq" >&2
  exit 1
}
install_tmp=$(mktemp "$bin_dir/.syq-install.XXXXXXXX")
cp "$program" "$install_tmp"
chmod 755 "$install_tmp"
mv -f "$install_tmp" "$bin_dir/syq"
install_tmp=
"$bin_dir/syq" --register-standalone-install
trap - EXIT HUP INT TERM
cleanup

echo "installed syq $version at $bin_dir/syq"
case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) echo "add $bin_dir to PATH, for example: export PATH=\"$bin_dir:\$PATH\"" ;;
esac
'''


def valid_archive(manifest, target):
    """The archive metadata check, failing on anything jq would reject."""
    try:
        archive = get(manifest, "artifacts", target, "archive")
        size = get(archive, "size")
        return (test(get(archive, "name"), r"^[A-Za-z0-9._-]+$")
                and test(get(archive, "sha256"), r"^[0-9a-f]{64}$")
                and is_number(size) and float(size) > 0)
    except JqError:
        return False


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} MANIFEST OUTPUT", file=sys.stderr)
        return 2
    manifest_path, output = sys.argv[1:]
    try:
        manifest = load_file(manifest_path)
    except OSError as error:
        print(f"jq: error: Could not open {manifest_path}: {error.strerror}", file=sys.stderr)
        return 2
    version = captured(require(get(manifest, "version")))
    tag = captured(require(get(manifest, "tag")))
    repository = captured(require(get(manifest, "repository")))
    if repository != "https://github.com/greaber/syq":
        print("unexpected repository", file=sys.stderr)
        return 1
    for target in TARGETS:
        if not valid_archive(manifest, target):
            print(f"invalid archive metadata for {target}", file=sys.stderr)
            return 1

    values = {"VERSION": version, "DOWNLOAD_BASE": DOWNLOAD_BASE, "TAG": tag}
    script = re.sub(r"@(VERSION|DOWNLOAD_BASE|TAG)@", lambda match: values[match.group(1)], HEAD)
    for target, pattern in TARGETS.items():
        archive = get(manifest, "artifacts", target, "archive")
        fields = [captured(get(archive, key)) for key in ("name", "sha256", "size")]
        script += "{}) archive='{}'; expected_sha='{}'; expected_size='{}' ;;\n".format(pattern, *fields)
    script += TAIL
    with open(output, "w", encoding="utf-8", newline="") as destination:
        destination.write(script)
    os.chmod(output, 0o755)
    return subprocess.run(["sh", "-n", output]).returncode


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
