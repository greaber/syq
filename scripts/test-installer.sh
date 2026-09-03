#!/usr/bin/env bash
# Exercise generated installer target selection and failure paths without
# network access or real user paths.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-installer-test.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
export XDG_CONFIG_HOME="$work/config"

release="$work/release"
fakebin="$work/fakebin"
mkdir -p "$release" "$fakebin"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | sed 's/^.*= //'
  fi
}

size_file() {
  wc -c < "$1" | tr -d '[:space:]'
}

write_program() {
  local path=$1 target=$2 version=${3:-0.1.0} identity=${4:-v0.1.0}
  cat > "$path" <<EOF
#!/bin/sh
case "\$1" in
  --version) echo 'syq $version' ;;
  --build-identity) echo '$identity' ;;
  --register-standalone-install) exit 0 ;;
  --test-target) echo '$target' ;;
  *) exit 2 ;;
esac
EOF
  chmod 755 "$path"
}

write_archive() {
  local target=$1 version=${2:-0.1.0} identity=${3:-v0.1.0}
  local program="$work/program-$target"
  write_program "$program" "$target" "$version" "$identity"
  gzip -9 -n -c "$program" > "$release/syq-$target.gz"
}

write_manifest() {
  local output=$1 artifacts='{}'
  local target archive program archive_sha archive_size binary_sha binary_size entry
  for target in linux-x86_64 linux-aarch64 macos-arm64 macos-x86_64; do
    archive="$release/syq-$target.gz"
    program="$work/program-$target"
    archive_sha=$(hash_file "$archive")
    archive_size=$(size_file "$archive")
    binary_sha=$(hash_file "$program")
    binary_size=$(size_file "$program")
    entry=$(jq -cn \
      --arg name "syq-$target" \
      --arg binary_sha "$binary_sha" --argjson binary_size "$binary_size" \
      --arg archive_sha "$archive_sha" --argjson archive_size "$archive_size" \
      '{binary:{name:$name,sha256:$binary_sha,size:$binary_size},
        archive:{name:($name+".gz"),sha256:$archive_sha,size:$archive_size}}')
    artifacts=$(jq -cn \
      --argjson artifacts "$artifacts" --arg target "$target" --argjson entry "$entry" \
      '$artifacts + {($target):$entry}')
  done
  jq -n --sort-keys --argjson artifacts "$artifacts" '
    {schema:1,repository:"https://github.com/greaber/syq",version:"0.1.0",
     tag:"v0.1.0",artifacts:$artifacts,
     installer:{name:"install.sh",sha256:("1"*64),size:1},
     homebrew_formula:{name:"syq.rb",sha256:("2"*64),size:1}}' > "$output"
}

expect_failure() {
  local expected=$1
  shift
  if "$@" > "$work/failure.out" 2>&1; then
    echo "command unexpectedly succeeded: $*" >&2
    exit 1
  fi
  grep -F -- "$expected" "$work/failure.out" >/dev/null || {
    echo "failure did not contain '$expected':" >&2
    sed 's/^/  /' "$work/failure.out" >&2
    exit 1
  }
}

for target in linux-x86_64 linux-aarch64 macos-arm64 macos-x86_64; do
  write_archive "$target"
done
write_manifest "$work/manifest.json"
"$script_dir/generate-installer.sh" "$work/manifest.json" "$work/install.sh"

cat > "$fakebin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' "$SYQ_TEST_UNAME_S" ;;
  -m) printf '%s\n' "$SYQ_TEST_UNAME_M" ;;
  *) exit 2 ;;
esac
EOF
cat > "$fakebin/curl" <<'EOF'
#!/bin/sh
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
cp "$SYQ_TEST_RELEASE_DIR/${url##*/}" "$output"
EOF
chmod 755 "$fakebin/uname" "$fakebin/curl"

while read -r os arch target; do
  install_dir="$work/install-$target"
  SYQ_TEST_UNAME_S="$os" SYQ_TEST_UNAME_M="$arch" \
    SYQ_TEST_RELEASE_DIR="$release" PATH="$fakebin:$PATH" \
    sh "$work/install.sh" --bin-dir "$install_dir" >/dev/null
  test "$("$install_dir/syq" --version)" = 'syq 0.1.0'
  test "$("$install_dir/syq" --test-target)" = "$target"
done <<'EOF'
Linux x86_64 linux-x86_64
Linux arm64 linux-aarch64
Darwin arm64 macos-arm64
Darwin x86_64 macos-x86_64
EOF

# Exercise the wget-only branch with a PATH containing every required utility
# except curl.
wgetbin="$work/wgetbin"
mkdir -p "$wgetbin"
checksum_utility=
for candidate in sha256sum shasum openssl; do
  if command -v "$candidate" >/dev/null 2>&1; then
    checksum_utility=$candidate
    break
  fi
done
test -n "$checksum_utility"
for utility in chmod cp gzip mkdir mktemp mv rm sed tr wc "$checksum_utility"; do
  ln -s "$(command -v "$utility")" "$wgetbin/$utility"
done
cp "$fakebin/uname" "$wgetbin/uname"
cat > "$wgetbin/wget" <<'EOF'
#!/bin/sh
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -O) output=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
cp "$SYQ_TEST_RELEASE_DIR/${url##*/}" "$output"
EOF
chmod 755 "$wgetbin/uname" "$wgetbin/wget"
SYQ_TEST_UNAME_S=Linux SYQ_TEST_UNAME_M=x86_64 \
  SYQ_TEST_RELEASE_DIR="$release" PATH="$wgetbin" \
  /bin/sh "$work/install.sh" --bin-dir "$work/install-wget" >/dev/null
test "$("$work/install-wget/syq" --test-target)" = linux-x86_64

test "$(sh "$work/install.sh" --help | head -1)" = 'Install syq 0.1.0 without sudo.'
expect_failure 'unknown option: --bogus' sh "$work/install.sh" --bogus
expect_failure '--bin-dir needs a value' sh "$work/install.sh" --bin-dir
expect_failure 'HOME is not set' env -u HOME -u XDG_CONFIG_HOME sh "$work/install.sh"
no_receipt_config="$work/no-receipt-config"
expect_failure 'HOME and XDG_CONFIG_HOME are not set' env -u HOME -u XDG_CONFIG_HOME \
  sh "$work/install.sh" --bin-dir "$no_receipt_config"
test ! -e "$no_receipt_config/syq"
invalid_receipt_config="$work/invalid-receipt-config"
printf 'not a directory\n' > "$invalid_receipt_config"
invalid_receipt_bin="$work/invalid-receipt-bin"
expect_failure 'cannot prepare install receipt directory' env \
  XDG_CONFIG_HOME="$invalid_receipt_config" \
  sh "$work/install.sh" --bin-dir "$invalid_receipt_bin"
test ! -e "$invalid_receipt_bin/syq"
expect_failure 'unsupported platform: Plan9 mips' env \
  SYQ_TEST_UNAME_S=Plan9 SYQ_TEST_UNAME_M=mips PATH="$fakebin:$PATH" \
  sh "$work/install.sh" --bin-dir "$work/unsupported"

directory_destination="$work/directory-destination"
mkdir -p "$directory_destination/syq"
expect_failure 'destination is a directory' env \
  SYQ_TEST_UNAME_S=Linux SYQ_TEST_UNAME_M=x86_64 \
  SYQ_TEST_RELEASE_DIR="$release" PATH="$fakebin:$PATH" \
  sh "$work/install.sh" --bin-dir "$directory_destination"

# A bad download must not alter a working installation.
install_dir="$work/install-linux-x86_64"
installed_sha=$(hash_file "$install_dir/syq")
printf 'tamper' >> "$release/syq-linux-x86_64.gz"
expect_failure 'downloaded archive has size' env \
  SYQ_TEST_UNAME_S=Linux SYQ_TEST_UNAME_M=x86_64 \
  SYQ_TEST_RELEASE_DIR="$release" PATH="$fakebin:$PATH" \
  sh "$work/install.sh" --bin-dir "$install_dir"
test "$(hash_file "$install_dir/syq")" = "$installed_sha"

# Even correctly hashed content is rejected if its build identity does not
# match the release metadata, again without replacing the installed binary.
write_archive linux-x86_64 0.1.0 v0.1.0+dev.wrong
write_manifest "$work/wrong-identity-manifest.json"
"$script_dir/generate-installer.sh" \
  "$work/wrong-identity-manifest.json" "$work/wrong-identity-install.sh"
expect_failure 'unexpected identity' env \
  SYQ_TEST_UNAME_S=Linux SYQ_TEST_UNAME_M=x86_64 \
  SYQ_TEST_RELEASE_DIR="$release" PATH="$fakebin:$PATH" \
  sh "$work/wrong-identity-install.sh" --bin-dir "$install_dir"
test "$(hash_file "$install_dir/syq")" = "$installed_sha"

echo 'installer tests passed'
