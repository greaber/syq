#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-test-secrets.XXXXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local output=$1
  shift
  if "$@" > "$output" 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

repo="$work/repo"
fake_bin="$work/bin"
fake_state="$work/state"
mkdir -p "$repo/scripts" "$fake_bin" "$fake_state"
cp "$ROOT_DIR/scripts/init-release-secrets.sh" "$repo/scripts/"
cp "$ROOT_DIR/scripts/sync-github-secrets.sh" "$repo/scripts/"

cat > "$fake_bin/dotenvx" <<'FAKE_DOTENVX'
#!/usr/bin/env bash
set -euo pipefail
state=${FAKE_DOTENVX_STATE:?}
command=${1:-}
case "$command" in
  --version)
    printf '2.21.0\n'
    ;;
  set)
    key=$2
    value=$3
    shift 3
    env_file=
    keys_file=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -f) env_file=$2; shift 2 ;;
        -fk) keys_file=$2; shift 2 ;;
        --no-native) shift ;;
        *) exit 91 ;;
      esac
    done
    [ -n "$env_file" ] && [ -n "$keys_file" ]
    printf '%s' "$value" > "$state/$key"
    printf '%s="encrypted:test-value"\n' "$key" >> "$env_file"
    printf 'DOTENV_PRIVATE_KEY_RELEASE="test-key"\n' > "$keys_file"
    ;;
  get)
    key=$2
    [ -f "$state/$key" ]
    cat "$state/$key"
    ;;
  *)
    exit 92
    ;;
esac
FAKE_DOTENVX

cat > "$fake_bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail
state=${FAKE_GH_STATE:?}
{
  printf 'gh'
  printf ' %q' "$@"
  printf '\n'
} >> "$state/calls"

case "${1:-}:${2:-}" in
  auth:status)
    exit 0
    ;;
  repo:view)
    case "$3" in
      greaber/syq|greaber/homebrew-tap) printf '%s\n' "$3" ;;
      *) exit 94 ;;
    esac
    ;;
  api:*)
    if [[ " $* " == *' --method POST '* ]]; then
      while [ "$#" -gt 0 ]; do
        case "$1" in
          -f)
            case "$2" in
              key=*) printf '%s' "${2#key=}" > "$state/homebrew-deploy-public-key" ;;
            esac
            shift 2
            ;;
          *) shift ;;
        esac
      done
    elif [[ " $* " == *' repos/greaber/homebrew-tap/keys '* ]] \
      && [ -f "$state/homebrew-deploy-public-key" ]; then
      cat "$state/homebrew-deploy-public-key"
      printf '\n'
    fi
    exit 0
    ;;
  secret:set)
    name=$3
    cat > "$state/secret-$name"
    ;;
  variable:set)
    name=$3
    shift 3
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --body) printf '%s' "$2" > "$state/variable-$name"; shift 2 ;;
        *) shift ;;
      esac
    done
    ;;
  *)
    exit 93
    ;;
esac
FAKE_GH

chmod 755 "$fake_bin/dotenvx" "$fake_bin/gh" "$repo/scripts/"*.sh
git -C "$repo" init -q -b master
git -C "$repo" remote add origin https://github.com/greaber/pcp.git

common_env=(
  "PATH=$fake_bin:$PATH"
  "DOTENVX_BIN=$fake_bin/dotenvx"
  "FAKE_DOTENVX_STATE=$fake_state"
  "FAKE_GH_STATE=$fake_state"
)

env "${common_env[@]}" "$repo/scripts/init-release-secrets.sh" \
  > "$work/init-output" 2>&1
[ -f "$repo/.env.release" ] || fail "initializer did not create .env.release"
[ -f "$repo/.env.keys" ] || fail "initializer did not create .env.keys"
[ "$(stat -c '%a' "$repo/.env.keys")" = 600 ] || fail ".env.keys is not mode 0600"
grep -Fq 'BEGIN OPENSSH PRIVATE KEY' "$repo/.env.release" \
  && fail "encrypted inventory contains the plaintext Homebrew key"
grep -Fq 'BEGIN OPENSSH PRIVATE KEY' "$work/init-output" \
  && fail "initializer printed the Homebrew key"
printf '%s\n' "$(cat "$fake_state/HOMEBREW_TAP_DEPLOY_KEY")" > "$work/homebrew-tap"
chmod 600 "$work/homebrew-tap"
homebrew_public=$(ssh-keygen -y -f "$work/homebrew-tap")
[[ "$homebrew_public" == 'ssh-ed25519 '* ]] \
  || fail "initializer did not store an Ed25519 Homebrew key"

openssl base64 -d -A -in "$fake_state/SYQ_RELEASE_SIGNING_KEY_PEM_B64" \
  -out "$work/signing.pem"
derived_public=$(openssl pkey -in "$work/signing.pem" -pubout -outform DER \
  | tail -c 32 | openssl base64 -A)
[ "$derived_public" = "$(cat "$fake_state/SYQ_RELEASE_PUBLIC_KEY")" ] \
  || fail "initializer stored a mismatched signing key pair"

env_hash=$(sha256sum "$repo/.env.release")
keys_hash=$(sha256sum "$repo/.env.keys")
expect_failure "$work/reinit-output" \
  env "${common_env[@]}" "$repo/scripts/init-release-secrets.sh"
[ "$env_hash" = "$(sha256sum "$repo/.env.release")" ] \
  || fail "reinitialization changed .env.release"
[ "$keys_hash" = "$(sha256sum "$repo/.env.keys")" ] \
  || fail "reinitialization changed .env.keys"

: > "$fake_state/calls"
expect_failure "$work/wrong-remote-output" \
  env "${common_env[@]}" "$repo/scripts/sync-github-secrets.sh"
[ ! -s "$fake_state/calls" ] || fail "wrong-remote guard ran gh"

git -C "$repo" remote set-url origin https://github.com/greaber/syq.git
: > "$fake_state/calls"
expect_failure "$work/wrong-host-output" \
  env "${common_env[@]}" GH_HOST=example.com "$repo/scripts/sync-github-secrets.sh"
[ ! -s "$fake_state/calls" ] || fail "wrong-host guard ran gh"

: > "$fake_state/calls"
env "${common_env[@]}" "$repo/scripts/sync-github-secrets.sh" \
  > "$work/dry-run-output" 2>&1
grep -q '^\[dry-run\] set environment secret SYQ_RELEASE_SIGNING_KEY_PEM_B64$' \
  "$work/dry-run-output" || fail "dry run omitted the signing-key action"
grep -q '^\[dry-run\] set environment secret HOMEBREW_TAP_DEPLOY_KEY$' \
  "$work/dry-run-output" || fail "dry run omitted the tap-key action"
grep -q '^\[dry-run\] configure Homebrew tap deploy key$' \
  "$work/dry-run-output" || fail "dry run omitted the public deploy-key action"
grep -q 'secret set\|variable set\|--method POST' "$fake_state/calls" \
  && fail "dry run mutated GitHub"
grep -Fq 'BEGIN OPENSSH PRIVATE KEY' "$work/dry-run-output" \
  && fail "dry run printed the Homebrew key"

: > "$fake_state/calls"
env "${common_env[@]}" "$repo/scripts/sync-github-secrets.sh" --execute \
  > "$work/execute-output" 2>&1
cmp -s "$fake_state/SYQ_RELEASE_SIGNING_KEY_PEM_B64" \
  "$fake_state/secret-SYQ_RELEASE_SIGNING_KEY_PEM_B64" \
  || fail "sync forwarded the wrong signing key"
cmp -s "$fake_state/HOMEBREW_TAP_DEPLOY_KEY" \
  "$fake_state/secret-HOMEBREW_TAP_DEPLOY_KEY" \
  || fail "sync forwarded the wrong Homebrew deploy key"
cmp -s "$fake_state/SYQ_RELEASE_PUBLIC_KEY" "$fake_state/variable-SYQ_RELEASE_PUBLIC_KEY" \
  || fail "sync forwarded the wrong public key"
expected_homebrew_public=$(ssh-keygen -y -f "$work/homebrew-tap")
[ "$expected_homebrew_public" = "$(cat "$fake_state/homebrew-deploy-public-key")" ] \
  || fail "sync installed the wrong Homebrew public deploy key"
grep -Fq 'BEGIN OPENSSH PRIVATE KEY' "$work/execute-output" \
  && fail "sync printed the Homebrew private key"
grep -Fq 'BEGIN OPENSSH PRIVATE KEY' "$fake_state/calls" \
  && fail "sync put the Homebrew private key in a gh argument"

printf '%s' AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  > "$fake_state/SYQ_RELEASE_PUBLIC_KEY"
: > "$fake_state/calls"
expect_failure "$work/mismatch-output" \
  env "${common_env[@]}" "$repo/scripts/sync-github-secrets.sh" --execute
grep -q 'secret set\|variable set' "$fake_state/calls" \
  && fail "mismatched signing keys mutated GitHub"

expect_failure "$work/unknown-argument-output" \
  env "${common_env[@]}" "$repo/scripts/sync-github-secrets.sh" --surprise

printf 'secret tooling tests passed\n'
