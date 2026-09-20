#!/usr/bin/env bash
# Create syq's encrypted release inventory without exposing its durable signing
# or Homebrew deploy keys to GitHub. Both files stay outside the repository.
set -euo pipefail

DOTENVX_VERSION=2.21.0
ENV_FILE=${SYQ_RELEASE_ENV_FILE:-}
KEYS_FILE=${SYQ_RELEASE_KEYS_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/syq/release/.env.keys}
DOTENVX_BIN=${DOTENVX_BIN:-dotenvx}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

if [ "$#" -ne 0 ]; then
  die "usage: $0"
fi

[ -n "$ENV_FILE" ] || die "set SYQ_RELEASE_ENV_FILE to the private inventory, or invoke through the operations wrapper"

if [[ "$DOTENVX_BIN" == */* ]]; then
  [ -x "$DOTENVX_BIN" ] || die "dotenvx is not executable: $DOTENVX_BIN"
else
  command -v "$DOTENVX_BIN" >/dev/null || die "dotenvx $DOTENVX_VERSION is required"
fi
command -v openssl >/dev/null || die "openssl is required"
command -v ssh-keygen >/dev/null || die "ssh-keygen is required"
[ "$("$DOTENVX_BIN" --version)" = "$DOTENVX_VERSION" ] \
  || die "dotenvx $DOTENVX_VERSION is required"

[ ! -e "$ENV_FILE" ] || die "$ENV_FILE already exists; refusing to replace the release inventory"
[ ! -e "$KEYS_FILE" ] || die "$KEYS_FILE already exists; refusing to replace its decryption authority"

umask 077
mkdir -p "$(dirname -- "$ENV_FILE")" "$(dirname -- "$KEYS_FILE")"
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-init-release.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

private_key="$work/signing.pem"
homebrew_key="$work/homebrew-tap"
staged_env="$work/.env.release"
staged_keys="$work/.env.keys"

openssl genpkey -algorithm ED25519 -out "$private_key"
ssh-keygen -q -t ed25519 -N '' -C 'syq release workflow' -f "$homebrew_key"
signing_key_b64=$(openssl base64 -A -in "$private_key")
public_key=$(openssl pkey -in "$private_key" -pubout -outform DER \
  | tail -c 32 | openssl base64 -A)
homebrew_deploy_key=$(<"$homebrew_key")

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
dotenvx_set HOMEBREW_TAP_DEPLOY_KEY "$homebrew_deploy_key"

[ "$(dotenvx_get SYQ_RELEASE_PUBLIC_KEY)" = "$public_key" ] \
  || die "failed to verify the encrypted public key"
[ "$(dotenvx_get SYQ_RELEASE_SIGNING_KEY_PEM_B64)" = "$signing_key_b64" ] \
  || die "failed to verify the encrypted signing key"
[ "$(dotenvx_get HOMEBREW_TAP_DEPLOY_KEY)" = "$homebrew_deploy_key" ] \
  || die "failed to verify the encrypted Homebrew deploy key"

chmod 600 "$staged_keys"
chmod 600 "$staged_env"
mv "$staged_keys" "$KEYS_FILE"
mv "$staged_env" "$ENV_FILE"

unset homebrew_deploy_key signing_key_b64
printf '%s\n' \
  "Created $ENV_FILE and local $KEYS_FILE." \
  "Back up both files in protected storage. Do not commit either file."
