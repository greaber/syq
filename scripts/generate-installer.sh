#!/usr/bin/env bash
# Generate a version-pinned installer whose trusted hashes come from the signed
# release manifest. The generated script needs only POSIX sh at install time.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 MANIFEST OUTPUT" >&2
  exit 2
fi
manifest=$1
output=$2
command -v jq >/dev/null || { echo "generate-installer needs jq" >&2; exit 1; }

version=$(jq -er '.version' "$manifest")
tag=$(jq -er '.tag' "$manifest")
repository=$(jq -er '.repository' "$manifest")
test "$repository" = 'https://github.com/greaber/syq' || { echo "unexpected repository" >&2; exit 1; }

for target in linux-x86_64 linux-aarch64 macos-arm64 macos-x86_64; do
  jq -e --arg target "$target" '
    .artifacts[$target].archive
    | (.name | test("^[A-Za-z0-9._-]+$"))
      and (.sha256 | test("^[0-9a-f]{64}$"))
      and (.size | type == "number" and . > 0)
  ' "$manifest" >/dev/null || { echo "invalid archive metadata for $target" >&2; exit 1; }
done

{
  cat <<EOF
#!/bin/sh
# Generated for syq $version. Inspect this script before running it; the exact
# version remains at $repository/releases/download/$tag/install.sh.
set -eu

version='$version'
tag='$tag'
base_url=\${SYQ_INSTALL_BASE_URL:-'$repository/releases/download/$tag'}
bin_dir=\${HOME:+\$HOME/.local/bin}

usage() {
  cat <<USAGE
Install syq $version without sudo.

Usage: install.sh [--bin-dir DIR]

The default is \$HOME/.local/bin. The installer detects this host, downloads
the pinned release archive, checks its embedded SHA-256 and size, verifies the
binary's version and release identity, then replaces the destination atomically.
USAGE
}

while [ \$# -gt 0 ]; do
  case \$1 in
    --bin-dir)
      [ \$# -ge 2 ] || { echo 'install.sh: --bin-dir needs a value' >&2; exit 2; }
      bin_dir=\$2
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) echo "install.sh: unknown option: \$1" >&2; usage >&2; exit 2 ;;
  esac
done
[ -n "\${bin_dir:-}" ] || { echo 'install.sh: HOME is not set; pass --bin-dir DIR' >&2; exit 1; }
[ -n "\${XDG_CONFIG_HOME:-}" ] || [ -n "\${HOME:-}" ] || {
  echo 'install.sh: HOME and XDG_CONFIG_HOME are not set; cannot record a managed installation' >&2
  exit 1
}
if [ -n "\${XDG_CONFIG_HOME:-}" ]; then
  receipt_dir=\$XDG_CONFIG_HOME/syq
else
  receipt_dir=\$HOME/.config/syq
fi
mkdir -p "\$receipt_dir" || {
  echo "install.sh: cannot prepare install receipt directory: \$receipt_dir" >&2
  exit 1
}
receipt_probe=\$(mktemp "\$receipt_dir/.syq-install-preflight.XXXXXXXX") || {
  echo "install.sh: install receipt directory is not writable: \$receipt_dir" >&2
  exit 1
}
rm -f "\$receipt_probe"

case "\$(uname -s):\$(uname -m)" in
EOF
  for target in linux-x86_64 linux-aarch64 macos-arm64 macos-x86_64; do
    archive=$(jq -r --arg target "$target" '.artifacts[$target].archive.name' "$manifest")
    hash=$(jq -r --arg target "$target" '.artifacts[$target].archive.sha256' "$manifest")
    size=$(jq -r --arg target "$target" '.artifacts[$target].archive.size' "$manifest")
    case "$target" in
      linux-x86_64) pattern='Linux:x86_64' ;;
      linux-aarch64) pattern='Linux:aarch64|Linux:arm64' ;;
      macos-arm64) pattern='Darwin:arm64|Darwin:aarch64' ;;
      macos-x86_64) pattern='Darwin:x86_64' ;;
    esac
    printf '%s) archive=%s; expected_sha=%s; expected_size=%s ;;\n' \
      "$pattern" "'$archive'" "'$hash'" "'$size'"
  done
  cat <<'EOF'
*) echo "install.sh: unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
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
EOF
} > "$output"
chmod 755 "$output"
sh -n "$output"
