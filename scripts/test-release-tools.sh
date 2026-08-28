#!/usr/bin/env bash
# Exercise complete release assembly and Ed25519 signing with small stand-in
# binaries.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-release-test.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_dir/Cargo.toml" | head -1)
tag="v$version"

prepare_dist() {
  local dist=$1 asset
  mkdir -p "$dist"
  for asset in syq-linux-x86_64 syq-linux-aarch64 syq-macos-arm64 syq-macos-x86_64; do
    cp /bin/true "$dist/$asset"
    gzip -9 -n -c "$dist/$asset" > "$dist/$asset.gz"
  done
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

first="$work/first"
second="$work/second"
prepare_dist "$first"
prepare_dist "$second"
"$script_dir/package-release.sh" "$tag" "$first"
"$script_dir/package-release.sh" "$tag" "$second"

test "$(find "$first" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 19
(cd "$first" && sha256sum -c syq-linux-x86_64.sha256 syq-linux-x86_64.gz.sha256)
installer_sha=$(sha256sum "$first/install.sh" | awk '{print $1}')
formula_sha=$(sha256sum "$first/syq.rb" | awk '{print $1}')
jq -e \
  --arg installer_sha "$installer_sha" --arg formula_sha "$formula_sha" '
    .schema == 1
    and (.artifacts | length == 4)
    and .installer.name == "install.sh"
    and .installer.sha256 == $installer_sha
    and .homebrew_formula.name == "syq.rb"
    and .homebrew_formula.sha256 == $formula_sha
  ' "$first/syq-release-manifest.json" >/dev/null
sh -n "$first/install.sh"
grep -q '^class Syq < Formula$' "$first/syq.rb"
grep -q '/releases/download/v' "$first/syq.rb"
if command -v ruby >/dev/null 2>&1; then
  ruby -c "$first/syq.rb" >/dev/null
fi

# Packaging is reproducible byte-for-byte and rejects both partial and
# contaminated release directories.
diff -qr "$first" "$second" >/dev/null
missing="$work/missing"
prepare_dist "$missing"
rm "$missing/syq-macos-arm64.gz"
expect_failure 'missing regular asset' \
  "$script_dir/package-release.sh" "$tag" "$missing"
unexpected="$work/unexpected"
prepare_dist "$unexpected"
printf 'not a release asset\n' > "$unexpected/extra"
expect_failure 'release directory contains missing or unexpected files' \
  "$script_dir/package-release.sh" "$tag" "$unexpected"
expect_failure 'does not match Cargo.toml version' \
  "$script_dir/package-release.sh" v99.99.99 "$first"

# Run the same signing operation used by the release workflow, verify the
# result independently, and prove that a mismatched configured public key is
# rejected without creating an output.
key="$work/signing.pem"
public="$work/public.pem"
openssl genpkey -algorithm ED25519 -out "$key" >/dev/null 2>&1
openssl pkey -in "$key" -pubout -out "$public" >/dev/null
key_b64=$(openssl base64 -A -in "$key")
public_b64=$(openssl pkey -in "$key" -pubout -outform DER | tail -c 32 | openssl base64 -A)
SYQ_RELEASE_SIGNING_KEY_PEM_B64="$key_b64" SYQ_RELEASE_PUBLIC_KEY="$public_b64" \
  "$script_dir/sign-release-manifest.sh" \
  "$first/syq-release-manifest.json" "$first/syq-release-manifest.json.sig"
openssl base64 -d -A -in "$first/syq-release-manifest.json.sig" \
  -out "$work/signature.raw"
openssl pkeyutl -verify -rawin -pubin -inkey "$public" \
  -in "$first/syq-release-manifest.json" -sigfile "$work/signature.raw" >/dev/null

other_key="$work/other.pem"
openssl genpkey -algorithm ED25519 -out "$other_key" >/dev/null 2>&1
other_public_b64=$(openssl pkey -in "$other_key" -pubout -outform DER | \
  tail -c 32 | openssl base64 -A)
mismatch_output="$work/mismatched.sig"
expect_failure 'does not match SYQ_RELEASE_PUBLIC_KEY' env \
  SYQ_RELEASE_SIGNING_KEY_PEM_B64="$key_b64" SYQ_RELEASE_PUBLIC_KEY="$other_public_b64" \
  "$script_dir/sign-release-manifest.sh" \
  "$first/syq-release-manifest.json" "$mismatch_output"
test ! -e "$mismatch_output"

# Verify the workflow's GitHub tag checks against controlled API responses.
fakebin="$work/fakebin"
mkdir "$fakebin"
cat > "$fakebin/gh" <<'EOF'
#!/bin/sh
case "$1:$2" in
  api:*/git/ref/tags/*) printf '%s\n' "$SYQ_TEST_REF_JSON" ;;
  api:*/git/tags/*) printf '%s\n' "$SYQ_TEST_TAG_JSON" ;;
  api:*/compare/*) printf '%s\n' "$SYQ_TEST_COMPARE_JSON" ;;
  release:download)
    shift 2
    destination=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --dir) destination=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    cp "$SYQ_TEST_PUBLISHED_DIR/"* "$destination/"
    ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 2 ;;
esac
EOF
chmod 755 "$fakebin/gh"
commit=0123456789abcdef0123456789abcdef01234567
tag_sha=89abcdef0123456789abcdef0123456789abcdef
ref_json=$(jq -cn --arg sha "$tag_sha" '{object:{type:"tag",sha:$sha}}')
tag_json=$(jq -cn --arg commit "$commit" '
  {tag:"v0.1.0",object:{type:"commit",sha:$commit},
   verification:{verified:true,reason:"valid"}}')
compare_json=$(jq -cn --arg commit "$commit" \
  '{base_commit:{sha:$commit},merge_base_commit:{sha:$commit}}')
SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" \
  SYQ_TEST_COMPARE_JSON="$compare_json" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master >/dev/null

lightweight=$(jq -cn --arg sha "$commit" '{object:{type:"commit",sha:$sha}}')
expect_failure 'is lightweight' env \
  SYQ_TEST_REF_JSON="$lightweight" SYQ_TEST_TAG_JSON="$tag_json" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master
unsigned=$(jq -cn --arg commit "$commit" '
  {tag:"v0.1.0",object:{type:"commit",sha:$commit},
   verification:{verified:false,reason:"unsigned"}}')
expect_failure 'reason: unsigned' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$unsigned" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master
expect_failure 'not workflow commit' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa master
unmerged_compare=$(jq -cn --arg commit "$commit" \
  '{base_commit:{sha:$commit},merge_base_commit:{sha:("b"*40)}}')
expect_failure 'not reachable from protected branch master' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" \
  SYQ_TEST_COMPARE_JSON="$unmerged_compare" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master

# Published-release reruns compare content, not just asset names.
local_assets="$work/local-assets"
published_assets="$work/published-assets"
mkdir "$local_assets" "$published_assets"
printf 'formula\n' > "$local_assets/syq.rb"
printf 'binary\n' > "$local_assets/syq-linux-x86_64"
cp "$local_assets/"* "$published_assets/"
SYQ_TEST_PUBLISHED_DIR="$published_assets" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-assets.sh" v0.1.0 "$local_assets" >/dev/null
printf 'changed formula\n' > "$published_assets/syq.rb"
expect_failure 'published release asset differs' env \
  SYQ_TEST_PUBLISHED_DIR="$published_assets" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-assets.sh" v0.1.0 "$local_assets"
cp "$local_assets/syq.rb" "$published_assets/syq.rb"
rm "$published_assets/syq-linux-x86_64"
expect_failure 'different asset inventory' env \
  SYQ_TEST_PUBLISHED_DIR="$published_assets" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-assets.sh" v0.1.0 "$local_assets"

echo 'release tool tests passed'
