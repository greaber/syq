#!/usr/bin/env bash
# Sign one release manifest with the protected Ed25519 key and prove that key
# matches the public key embedded in official binaries.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 MANIFEST SYQ_BINARY" >&2
  exit 2
fi
manifest=$1
canonicalizer=$2
if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
  echo "missing regular release manifest: $manifest" >&2
  exit 1
fi
if [ ! -x "$canonicalizer" ]; then
  echo "missing executable syq canonicalizer: $canonicalizer" >&2
  exit 1
fi
test -n "${SYQ_RELEASE_PUBLIC_KEY:-}" || {
  echo 'SYQ_RELEASE_PUBLIC_KEY is not set' >&2
  exit 1
}
test -n "${SYQ_RELEASE_SIGNING_KEY_PEM_B64:-}" || {
  echo 'SYQ_RELEASE_SIGNING_KEY_PEM_B64 is not set' >&2
  exit 1
}
command -v openssl >/dev/null || { echo 'signing needs openssl' >&2; exit 1; }
command -v jq >/dev/null || { echo 'signing needs jq' >&2; exit 1; }
jq -e '
  type == "object"
  and .signature_scheme == "ed25519-jcs-v1"
  and (has("signature") | not)
' "$manifest" >/dev/null || {
  echo 'release manifest is not unsigned ed25519-jcs-v1 metadata' >&2
  exit 1
}

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-sign-release.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
key="$work/signing.pem"
public="$work/public.pem"
payload="$work/manifest.jcs"
verified_payload="$work/verified-manifest.jcs"
embedded_signature="$work/embedded.sig"
signed_manifest="$work/signed-manifest.json"
configured_public="$work/configured-public-key"

printf '%s' "$SYQ_RELEASE_SIGNING_KEY_PEM_B64" | openssl base64 -d -A > "$key"
openssl pkey -in "$key" -pubout -out "$public" >/dev/null
printf '%s' "$SYQ_RELEASE_PUBLIC_KEY" | openssl base64 -d -A > "$configured_public"
test "$(wc -c < "$configured_public" | tr -d '[:space:]')" -eq 32 || {
  echo 'SYQ_RELEASE_PUBLIC_KEY must encode exactly 32 bytes' >&2
  exit 1
}
derived=$(openssl pkey -in "$key" -pubout -outform DER | tail -c 32 | openssl base64 -A)
test "$derived" = "$SYQ_RELEASE_PUBLIC_KEY" || {
  echo 'The signing key does not match SYQ_RELEASE_PUBLIC_KEY.' >&2
  exit 1
}

"$canonicalizer" --release-manifest-signing-payload "$manifest" > "$payload"
openssl pkeyutl -sign -rawin -inkey "$key" -in "$payload" -out "$embedded_signature"
openssl pkeyutl -verify -rawin -pubin -inkey "$public" \
  -in "$payload" -sigfile "$embedded_signature" >/dev/null
embedded_b64=$(openssl base64 -A -in "$embedded_signature")
jq --sort-keys --arg signature "$embedded_b64" \
  '. + {signature:$signature}' "$manifest" > "$signed_manifest"
"$canonicalizer" --release-manifest-signing-payload "$signed_manifest" > "$verified_payload"
cmp -s "$payload" "$verified_payload" || {
  echo 'embedded signature changed the canonical manifest payload' >&2
  exit 1
}
openssl pkeyutl -verify -rawin -pubin -inkey "$public" \
  -in "$verified_payload" -sigfile "$embedded_signature" >/dev/null

chmod 644 "$signed_manifest"
mv -f "$signed_manifest" "$manifest"
