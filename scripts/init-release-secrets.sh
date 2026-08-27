#!/usr/bin/env bash
# Create syq's encrypted release inventory without exposing its durable signing
# key or Homebrew credential to GitHub. Run once, then commit only .env.release.
set -euo pipefail

DOTENVX_VERSION=2.21.0
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE="$ROOT_DIR/.env.release"
KEYS_FILE="$ROOT_DIR/.env.keys"
DOTENVX_BIN=${DOTENVX_BIN:-dotenvx}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

if [ "$#" -ne 0 ]; then
  die "usage: $0"
fi

if [[ "$DOTENVX_BIN" == */* ]]; then
  [ -x "$DOTENVX_BIN" ] || die "dotenvx is not executable: $DOTENVX_BIN"
else
  command -v "$DOTENVX_BIN" >/dev/null || die "dotenvx $DOTENVX_VERSION is required"
fi
command -v openssl >/dev/null || die "openssl is required"
[ "$("$DOTENVX_BIN" --version)" = "$DOTENVX_VERSION" ] \
  || die "dotenvx $DOTENVX_VERSION is required"

[ ! -e "$ENV_FILE" ] || die "$ENV_FILE already exists; refusing to replace the release inventory"
[ ! -e "$KEYS_FILE" ] || die "$KEYS_FILE already exists; refusing to replace its decryption authority"

if [ -t 0 ]; then
  printf 'Fine-grained greaber/homebrew-tap token: ' >&2
  IFS= read -r -s homebrew_token
  printf '\n' >&2
else
  IFS= read -r homebrew_token || die "expected the Homebrew tap token on standard input"
fi
[ -n "$homebrew_token" ] || die "the Homebrew tap token must not be empty"

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-init-release.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

private_key="$work/signing.pem"
staged_env="$work/.env.release"
staged_keys="$work/.env.keys"

openssl genpkey -algorithm ED25519 -out "$private_key"
signing_key_b64=$(openssl base64 -A -in "$private_key")
public_key=$(openssl pkey -in "$private_key" -pubout -outform DER \
  | tail -c 32 | openssl base64 -A)

dotenvx_set() {
  "$DOTENVX_BIN" set "$1" "$2" -f "$staged_env" -fk "$staged_keys" \
    --no-native >/dev/null
}

dotenvx_get() {
  "$DOTENVX_BIN" get "$1" -f "$staged_env" -fk "$staged_keys" \
    --strict --overload --no-native
}

dotenvx_set SYQ_RELEASE_PUBLIC_KEY "$public_key"
dotenvx_set SYQ_RELEASE_SIGNING_KEY_PEM_B64 "$signing_key_b64"
dotenvx_set HOMEBREW_TAP_TOKEN "$homebrew_token"

[ "$(dotenvx_get SYQ_RELEASE_PUBLIC_KEY)" = "$public_key" ] \
  || die "failed to verify the encrypted public key"
[ "$(dotenvx_get SYQ_RELEASE_SIGNING_KEY_PEM_B64)" = "$signing_key_b64" ] \
  || die "failed to verify the encrypted signing key"
[ "$(dotenvx_get HOMEBREW_TAP_TOKEN)" = "$homebrew_token" ] \
  || die "failed to verify the encrypted Homebrew token"

chmod 600 "$staged_keys"
chmod 644 "$staged_env"
mv "$staged_keys" "$KEYS_FILE"
mv "$staged_env" "$ENV_FILE"

unset homebrew_token signing_key_b64
printf '%s\n' \
  "Created $ENV_FILE and local $KEYS_FILE." \
  "Back up .env.keys in protected storage, then commit only .env.release."
