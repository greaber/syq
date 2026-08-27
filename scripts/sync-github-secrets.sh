#!/usr/bin/env bash
# Materialize the small, allowlisted release inventory into GitHub. The dotenvx
# decryption key remains local and is never forwarded to GitHub or CI.
set -euo pipefail

DOTENVX_VERSION=2.21.0
CANONICAL_HOST=github.com
CANONICAL_REPO=greaber/syq
RELEASE_ENVIRONMENT=release
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE="$ROOT_DIR/.env.release"
KEYS_FILE="$ROOT_DIR/.env.keys"
DOTENVX_BIN=${DOTENVX_BIN:-dotenvx}
EXECUTE=false

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

case "$#:${1:-}" in
  0:) ;;
  1:--execute) EXECUTE=true ;;
  *) die "usage: $0 [--execute]" ;;
esac

redact_remote_url() {
  local url=$1
  if [[ "$url" =~ ^([a-zA-Z][a-zA-Z0-9+.-]*://)([^/]*@)(.*)$ ]]; then
    printf '%s***@%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}"
  elif [[ "$url" =~ ^([^/@]*:[^/@]*)@(.*)$ ]]; then
    printf '***@%s' "${BASH_REMATCH[2]}"
  else
    printf '%s' "$url"
  fi
}

github_slug_from_remote_url() {
  local url=${1%/}
  url=${url%.git}
  if [[ "$url" =~ ^(ssh://)?(git@)?github\.com[:/]+([^/]+)/([^/]+)$ ]]; then
    printf '%s/%s' "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"
    return 0
  fi
  if [[ "$url" =~ ^https?://([^@/]+@)?github\.com/([^/]+)/([^/]+)$ ]]; then
    printf '%s/%s' "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return 0
  fi
  return 1
}

cd "$ROOT_DIR"

# This check precedes every gh invocation. A maintainer running the script in a
# fork must never copy the official release authority into that fork.
origin_url=$(git config --get remote.origin.url 2>/dev/null || true)
[ -n "$origin_url" ] || die "no remote.origin.url; run this from a clone of $CANONICAL_REPO"
origin_url_safe=$(redact_remote_url "$origin_url")
target_repo=$(github_slug_from_remote_url "$origin_url") \
  || die "remote.origin.url is not a $CANONICAL_HOST URL: $origin_url_safe"
[ "$target_repo" = "$CANONICAL_REPO" ] \
  || die "refusing to touch secrets for $target_repo; expected $CANONICAL_REPO"
[ "${GH_HOST:-$CANONICAL_HOST}" = "$CANONICAL_HOST" ] \
  || die "GH_HOST must be $CANONICAL_HOST"

command -v gh >/dev/null || die "the gh CLI is required"
if [[ "$DOTENVX_BIN" == */* ]]; then
  [ -x "$DOTENVX_BIN" ] || die "dotenvx is not executable: $DOTENVX_BIN"
else
  command -v "$DOTENVX_BIN" >/dev/null || die "dotenvx $DOTENVX_VERSION is required"
fi
command -v openssl >/dev/null || die "openssl is required"
[ "$("$DOTENVX_BIN" --version)" = "$DOTENVX_VERSION" ] \
  || die "dotenvx $DOTENVX_VERSION is required"
[ -f "$ENV_FILE" ] || die "$ENV_FILE not found; run scripts/init-release-secrets.sh"
[ -f "$KEYS_FILE" ] || die "$KEYS_FILE not found"

gh auth status --hostname "$CANONICAL_HOST" >/dev/null 2>&1 \
  || die "gh is not authenticated for $CANONICAL_HOST"
repo=$(gh repo view "$CANONICAL_REPO" --json nameWithOwner --jq .nameWithOwner 2>/dev/null) \
  || die "cannot access $CANONICAL_REPO"
[ "$repo" = "$CANONICAL_REPO" ] || die "gh resolved an unexpected repository: $repo"
gh api "repos/$CANONICAL_REPO/environments/$RELEASE_ENVIRONMENT" >/dev/null 2>&1 \
  || die "GitHub environment $RELEASE_ENVIRONMENT does not exist in $CANONICAL_REPO"

dotenvx_get() {
  "$DOTENVX_BIN" get "$1" -f "$ENV_FILE" -fk "$KEYS_FILE" \
    --strict --overload --no-native
}

public_key=$(dotenvx_get SYQ_RELEASE_PUBLIC_KEY) \
  || die "failed to decrypt SYQ_RELEASE_PUBLIC_KEY"
signing_key=$(dotenvx_get SYQ_RELEASE_SIGNING_KEY_PEM_B64) \
  || die "failed to decrypt SYQ_RELEASE_SIGNING_KEY_PEM_B64"
homebrew_token=$(dotenvx_get HOMEBREW_TAP_TOKEN) \
  || die "failed to decrypt HOMEBREW_TAP_TOKEN"
[ -n "$public_key" ] || die "SYQ_RELEASE_PUBLIC_KEY is empty"
[ -n "$signing_key" ] || die "SYQ_RELEASE_SIGNING_KEY_PEM_B64 is empty"
[ -n "$homebrew_token" ] || die "HOMEBREW_TAP_TOKEN is empty"

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-sync-secrets.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
private_key="$work/signing.pem"
configured_public="$work/public-key"
printf '%s' "$signing_key" | openssl base64 -d -A > "$private_key"
openssl pkey -in "$private_key" -noout >/dev/null 2>&1 \
  || die "SYQ_RELEASE_SIGNING_KEY_PEM_B64 is not a valid private key"
printf '%s' "$public_key" | openssl base64 -d -A > "$configured_public"
[ "$(wc -c < "$configured_public" | tr -d '[:space:]')" -eq 32 ] \
  || die "SYQ_RELEASE_PUBLIC_KEY must encode exactly 32 bytes"
derived_public=$(openssl pkey -in "$private_key" -pubout -outform DER \
  | tail -c 32 | openssl base64 -A)
[ "$derived_public" = "$public_key" ] \
  || die "the release signing key does not match SYQ_RELEASE_PUBLIC_KEY"

set_environment_secret() {
  local name=$1 value=$2
  if $EXECUTE; then
    printf '%s' "$value" \
      | gh secret set "$name" --repo "$CANONICAL_REPO" --env "$RELEASE_ENVIRONMENT" >/dev/null
    printf 'set environment secret %s\n' "$name"
  else
    printf '[dry-run] set environment secret %s\n' "$name"
  fi
}

set_repository_variable() {
  local name=$1 value=$2
  if $EXECUTE; then
    gh variable set "$name" --repo "$CANONICAL_REPO" --body "$value" >/dev/null
    printf 'set repository variable %s\n' "$name"
  else
    printf '[dry-run] set repository variable %s\n' "$name"
  fi
}

# The public variable is last. A partial sync therefore leaves release signing
# fail-closed instead of publishing with an unverified key pair.
set_environment_secret SYQ_RELEASE_SIGNING_KEY_PEM_B64 "$signing_key"
set_environment_secret HOMEBREW_TAP_TOKEN "$homebrew_token"
set_repository_variable SYQ_RELEASE_PUBLIC_KEY "$public_key"

unset signing_key homebrew_token
if $EXECUTE; then
  printf 'Synchronized the allowlisted release inventory to %s.\n' "$CANONICAL_REPO"
else
  printf 'Dry run only; rerun with --execute to modify GitHub.\n'
fi
