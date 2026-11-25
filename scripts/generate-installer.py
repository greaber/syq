#!/usr/bin/env python3
"""Generate a version-pinned installer whose trusted hashes come from the signed
release manifest and zstd archive listing. The generated script needs only
POSIX sh at install time, and uses the zstd archive where `zstd` is installed.

Usage: scripts/generate-installer.py MANIFEST ZSTD_MANIFEST OUTPUT
"""
import os
import re
import subprocess
import sys

from tooling import ToolError, load_release_manifest, report_errors

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
the pinned release archive (zstd when zstd is installed, gzip otherwise), checks
its embedded SHA-256 and size, verifies the binary's version and release
identity, then replaces the destination atomically.
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

# The zstd archive is smaller and unpacks faster; gzip is everywhere.
format=gzip
if command -v zstd >/dev/null 2>&1; then
  format=zstd
  archive=$zstd_archive
  expected_sha=$zstd_sha
  expected_size=$zstd_size
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-install.XXXXXXXX")
install_tmp=
cleanup() {
  rm -rf "$work"
  [ -z "$install_tmp" ] || rm -f "$install_tmp"
}
trap cleanup EXIT HUP INT TERM
download="$work/$archive"
program="$work/syq"

if command -v curl >/dev/null 2>&1; then
  downloader=curl
elif command -v wget >/dev/null 2>&1; then
  downloader=wget
else
  echo 'install.sh: downloading syq requires curl or wget' >&2
  exit 1
fi
fetch() {
  if [ "$downloader" = curl ]; then
    curl --fail --silent --show-error --location --retry 2 --connect-timeout 10 \
      --proto '=https' --proto-redir '=https' --output - "$1"
  else
    wget --quiet --https-only --timeout=10 --tries=3 -O - "$1"
  fi
}

# Keep at most one byte more than the archive, so that a larger download stops
# early instead of filling the disk.
fetch "$base_url/$archive" | head -c "$((expected_size + 1))" > "$download"
actual_size=$(wc -c < "$download" | tr -d '[:space:]')
[ "$actual_size" -le "$expected_size" ] || {
  echo "install.sh: downloaded archive is larger than the expected $expected_size bytes" >&2
  exit 1
}
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

if [ "$format" = zstd ]; then
  zstd -d -q -c "$download" > "$program"
else
  gzip -dc "$download" > "$program"
fi || {
  echo "install.sh: could not decompress the downloaded $format archive" >&2
  exit 1
}
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


def archive_fields(archive, target, suffix):
    """The name, SHA-256, and size of a target's archive, after validation."""
    try:
        name, sha256, size = archive["name"], archive["sha256"], archive["size"]
    except (KeyError, TypeError):
        name = sha256 = size = None
    if not (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9._-]+", name)
            and name.endswith(suffix)
            and isinstance(sha256, str) and re.fullmatch(r"[0-9a-f]{64}", sha256)
            and type(size) is int and size > 0):
        raise ToolError(f"invalid {suffix} archive metadata for {target}")
    return name, sha256, str(size)


def entry(document, *keys):
    for key in keys:
        document = document.get(key) if isinstance(document, dict) else None
    return document


def main():
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} MANIFEST ZSTD_MANIFEST OUTPUT", file=sys.stderr)
        return 2
    manifest_path, zstd_manifest_path, output = sys.argv[1:]
    manifest = load_release_manifest(manifest_path)
    zstd_manifest = load_release_manifest(zstd_manifest_path)
    if zstd_manifest["tag"] != manifest["tag"]:
        raise ToolError("the zstd archive manifest describes another release")
    values = {"VERSION": manifest["version"], "DOWNLOAD_BASE": DOWNLOAD_BASE,
              "TAG": manifest["tag"]}
    script = re.sub(r"@(VERSION|DOWNLOAD_BASE|TAG)@", lambda match: values[match.group(1)], HEAD)
    for target, pattern in TARGETS.items():
        gzip = archive_fields(entry(manifest, "artifacts", target, "archive"), target, ".gz")
        zstd = archive_fields(entry(zstd_manifest, "archives", target), target, ".zst")
        script += ("{}) archive='{}'; expected_sha='{}'; expected_size='{}';"
                   " zstd_archive='{}'; zstd_sha='{}'; zstd_size='{}' ;;\n").format(
                       pattern, *gzip, *zstd)
    script += TAIL
    with open(output, "w", encoding="utf-8", newline="") as destination:
        destination.write(script)
    os.chmod(output, 0o755)
    return subprocess.run(["sh", "-n", output]).returncode


if __name__ == "__main__":
    sys.exit(report_errors(main))
