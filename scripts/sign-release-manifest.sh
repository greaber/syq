#!/usr/bin/env bash
# Sign one release manifest with the protected Ed25519 key and prove that key
# matches the public key embedded in official binaries.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 MANIFEST SIGNATURE_OUTPUT" >&2
  exit 2
fi
manifest=$1
output=$2
if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
  echo "missing regular release manifest: $manifest" >&2
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

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-sign-release.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
key="$work/signing.pem"
public="$work/public.pem"
signature="$work/manifest.sig"
encoded="$work/manifest.sig.b64"
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

openssl pkeyutl -sign -rawin -inkey "$key" -in "$manifest" -out "$signature"
openssl pkeyutl -verify -rawin -pubin -inkey "$public" \
  -in "$manifest" -sigfile "$signature" >/dev/null
openssl base64 -A -in "$signature" -out "$encoded"
printf '\n' >> "$encoded"
chmod 644 "$encoded"
mv -f "$encoded" "$output"
