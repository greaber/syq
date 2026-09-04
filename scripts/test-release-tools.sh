#!/usr/bin/env bash
# Exercise complete release assembly and Ed25519 signing with small stand-in
# binaries.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
# Ed25519 raw signing needs OpenSSL 1.1.1 or newer. macOS ships LibreSSL as
# `openssl`, which has no `pkeyutl -rawin`; Homebrew's openssl@3 works once
# its bin directory is first on PATH.
require_ed25519_openssl() {
  if ! openssl pkeyutl -help 2>&1 | grep -q -- '-rawin'; then
    echo "$0 needs OpenSSL 1.1.1 or newer with Ed25519 raw signing; found: $(openssl version 2>/dev/null || echo unknown)" >&2
    echo 'on macOS, install openssl@3 with Homebrew and put its bin directory first on PATH' >&2
    exit 1
  fi
}
require_ed25519_openssl

work=$(mktemp -d "${TMPDIR:-/tmp}/syq-release-test.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_dir/Cargo.toml" | head -1)
tag="v$version"
cargo build --locked --manifest-path "$repo_dir/Cargo.toml" --bin syq
target_dir=$(cargo metadata --no-deps --format-version 1 \
  --manifest-path "$repo_dir/Cargo.toml" | jq -r .target_directory)
canonicalizer="$target_dir/debug/syq"

# Portable SHA-256 of one file: GNU coreutils on Linux, Perl shasum on macOS.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$@"
  else
    shasum -a 256 -c "$@"
  fi
}

prepare_dist() {
  local dist=$1 asset
  mkdir -p "$dist"
  for asset in syq-linux-x86_64 syq-linux-aarch64 syq-macos-arm64 syq-macos-x86_64; do
    printf '#!/bin/sh\nexit 0\n' > "$dist/$asset"
    chmod 755 "$dist/$asset"
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
(cd "$first" && sha256_check syq-linux-x86_64.sha256 syq-linux-x86_64.gz.sha256)
installer_sha=$(sha256_file "$first/install.sh")
formula_sha=$(sha256_file "$first/syq.rb")
jq -e \
  --arg installer_sha "$installer_sha" --arg formula_sha "$formula_sha" '
    .schema == 1
    and (keys == ["artifacts", "homebrew_formula", "installer", "repository", "schema", "signature_scheme", "tag", "version"])
    and (.artifacts | length == 4)
    and .installer.name == "install.sh"
    and .installer.sha256 == $installer_sha
    and .homebrew_formula.name == "syq.rb"
    and .homebrew_formula.sha256 == $formula_sha
    and .signature_scheme == "ed25519-jcs-v1"
    and (has("signature") | not)
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

# crates.io reruns accept only the exact package checksum, distinguish a
# missing version with exit 3, and fail closed on registry errors.
source_crate="$work/syq-0.1.0.crate"
printf 'source crate\n' > "$source_crate"
source_checksum=$(sha256_file "$source_crate")
crate_response="$work/crate-response.json"
jq -n --arg checksum "$source_checksum" \
  '{version:{num:"0.1.0",checksum:$checksum}}' > "$crate_response"
SYQ_TEST_CRATES_IO_RESPONSE="$crate_response" SYQ_TEST_CRATES_IO_STATUS=200 \
  "$script_dir/verify-crates-io-package.sh" 0.1.0 "$source_crate" >/dev/null

set +e
SYQ_TEST_CRATES_IO_RESPONSE="$crate_response" SYQ_TEST_CRATES_IO_STATUS=404 \
  "$script_dir/verify-crates-io-package.sh" 0.1.0 "$source_crate" \
  > "$work/crate-missing.out" 2>&1
missing_status=$?
set -e
test "$missing_status" -eq 3
grep -F 'is not published on crates.io' "$work/crate-missing.out" >/dev/null

jq -n '{version:{num:"0.1.0",checksum:("a" * 64)}}' > "$crate_response"
expect_failure 'differs from the package assembled from this tag' env \
  SYQ_TEST_CRATES_IO_RESPONSE="$crate_response" SYQ_TEST_CRATES_IO_STATUS=200 \
  "$script_dir/verify-crates-io-package.sh" 0.1.0 "$source_crate"
expect_failure 'returned HTTP 500' env \
  SYQ_TEST_CRATES_IO_RESPONSE="$crate_response" SYQ_TEST_CRATES_IO_STATUS=500 \
  "$script_dir/verify-crates-io-package.sh" 0.1.0 "$source_crate"

# Run the same signing operation used by the release workflow, verify the
# result independently, and prove that a mismatched configured public key is
# rejected without modifying the manifest.
key="$work/signing.pem"
public="$work/public.pem"
openssl genpkey -algorithm ED25519 -out "$key" >/dev/null 2>&1
openssl pkey -in "$key" -pubout -out "$public" >/dev/null
key_b64=$(openssl base64 -A -in "$key")
public_b64=$(openssl pkey -in "$key" -pubout -outform DER | tail -c 32 | openssl base64 -A)
SYQ_RELEASE_SIGNING_KEY_PEM_B64="$key_b64" SYQ_RELEASE_PUBLIC_KEY="$public_b64" \
  "$script_dir/sign-release-manifest.sh" \
  "$first/syq-release-manifest.json" "$canonicalizer"
test "$(find "$first" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 19
embedded_b64=$(jq -er '.signature' "$first/syq-release-manifest.json")
printf '%s' "$embedded_b64" | openssl base64 -d -A > "$work/embedded-signature.raw"
"$canonicalizer" --release-manifest-signing-payload \
  "$first/syq-release-manifest.json" > "$work/manifest.jcs"
openssl pkeyutl -verify -rawin -pubin -inkey "$public" \
  -in "$work/manifest.jcs" -sigfile "$work/embedded-signature.raw" >/dev/null

other_key="$work/other.pem"
openssl genpkey -algorithm ED25519 -out "$other_key" >/dev/null 2>&1
other_public_b64=$(openssl pkey -in "$other_key" -pubout -outform DER | \
  tail -c 32 | openssl base64 -A)
second_sha=$(sha256_file "$second/syq-release-manifest.json")
expect_failure 'does not match SYQ_RELEASE_PUBLIC_KEY' env \
  SYQ_RELEASE_SIGNING_KEY_PEM_B64="$key_b64" SYQ_RELEASE_PUBLIC_KEY="$other_public_b64" \
  "$script_dir/sign-release-manifest.sh" \
  "$second/syq-release-manifest.json" "$canonicalizer"
test "$(sha256_file "$second/syq-release-manifest.json")" = "$second_sha"
jq -e 'has("signature") | not' "$second/syq-release-manifest.json" >/dev/null

# Verify the workflow's GitHub tag checks against controlled API responses.
fakebin="$work/fakebin"
mkdir "$fakebin"
cat > "$fakebin/gh" <<'EOF'
#!/bin/sh
case "$1:$2" in
  api:*/git/ref/tags/*) printf '%s\n' "$SYQ_TEST_REF_JSON" ;;
  api:*/git/tags/*) printf '%s\n' "$SYQ_TEST_TAG_JSON" ;;
  api:*/compare/*) printf '%s\n' "$SYQ_TEST_COMPARE_JSON" ;;
  api:*/check-runs*) printf '%s\n' "$SYQ_TEST_CHECKS_JSON" ;;
  api:*/actions/workflows/*/runs?*) printf '%s\n' "$SYQ_TEST_WORKFLOW_RUNS_JSON" ;;
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
checks_json=$(jq -cn '{check_runs:[
  {id:1,name:"rust",started_at:"2026-01-01T00:00:00Z",status:"completed",conclusion:"failure"},
  {id:2,name:"rust",started_at:"2026-01-01T00:01:00Z",status:"completed",conclusion:"success"},
  {name:"macos",status:"completed",conclusion:"success"},
  {name:"verify signed release tag",status:"in_progress",conclusion:null}]}')
workflow_runs_json=$(jq -cn --arg commit "$commit" '{workflow_runs:[{
  id:701,event:"workflow_dispatch",head_sha:$commit,status:"completed",
  conclusion:"success",run_number:1,run_attempt:1}]}')
SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" \
  SYQ_TEST_COMPARE_JSON="$compare_json" SYQ_TEST_CHECKS_JSON="$checks_json" \
  PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master rust,macos >/dev/null

SYQ_TEST_WORKFLOW_RUNS_JSON="$workflow_runs_json" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-ci.sh" greaber/syq "$commit" >/dev/null
expect_failure 'has no workflow_dispatch run' env \
  SYQ_TEST_WORKFLOW_RUNS_JSON='{"workflow_runs":[]}' PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-ci.sh" greaber/syq "$commit"
failed_workflow_runs=$(jq -cn --arg commit "$commit" '{workflow_runs:[
  {id:701,event:"workflow_dispatch",head_sha:$commit,status:"completed",
   conclusion:"success",run_number:1,run_attempt:1},
  {id:702,event:"workflow_dispatch",head_sha:$commit,status:"completed",
   conclusion:"failure",run_number:2,run_attempt:1}]}')
expect_failure 'is completed/failure' env \
  SYQ_TEST_WORKFLOW_RUNS_JSON="$failed_workflow_runs" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-ci.sh" greaber/syq "$commit"

lightweight=$(jq -cn --arg sha "$commit" '{object:{type:"commit",sha:$sha}}')
expect_failure 'is lightweight' env \
  SYQ_TEST_REF_JSON="$lightweight" SYQ_TEST_TAG_JSON="$tag_json" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master rust,macos
unsigned=$(jq -cn --arg commit "$commit" '
  {tag:"v0.1.0",object:{type:"commit",sha:$commit},
   verification:{verified:false,reason:"unsigned"}}')
expect_failure 'reason: unsigned' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$unsigned" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master rust,macos
expect_failure 'not workflow commit' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa master rust,macos
unmerged_compare=$(jq -cn --arg commit "$commit" \
  '{base_commit:{sha:$commit},merge_base_commit:{sha:("b"*40)}}')
expect_failure 'not reachable from protected branch master' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" \
  SYQ_TEST_COMPARE_JSON="$unmerged_compare" PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master rust,macos
# A red, pending, or absent required check on the tagged commit blocks the
# release even when the tag itself is valid and merged.
failed_checks=$(jq -cn '{check_runs:[
  {name:"rust",status:"completed",conclusion:"failure"},
  {name:"macos",status:"completed",conclusion:"success"}]}')
expect_failure 'required check rust is failure' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" \
  SYQ_TEST_COMPARE_JSON="$compare_json" SYQ_TEST_CHECKS_JSON="$failed_checks" \
  PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master rust,macos
pending_checks=$(jq -cn '{check_runs:[
  {name:"rust",status:"in_progress",conclusion:null},
  {name:"macos",status:"completed",conclusion:"success"}]}')
expect_failure 'required check rust is pending' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" \
  SYQ_TEST_COMPARE_JSON="$compare_json" SYQ_TEST_CHECKS_JSON="$pending_checks" \
  PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master rust,macos
expect_failure 'required check linux-arm64 is missing' env \
  SYQ_TEST_REF_JSON="$ref_json" SYQ_TEST_TAG_JSON="$tag_json" \
  SYQ_TEST_COMPARE_JSON="$compare_json" SYQ_TEST_CHECKS_JSON="$checks_json" \
  PATH="$fakebin:$PATH" \
  "$script_dir/verify-release-tag.sh" greaber/syq v0.1.0 "$commit" master rust,macos,linux-arm64

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
