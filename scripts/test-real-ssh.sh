#!/usr/bin/env bash
# Local-only real OpenSSH integration tests in an isolated Docker Compose project.
set -euo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[ "${BASH_VERSINFO[0]}" -ge 4 ] || die 'real-SSH tests require Bash 4 or newer'

for command in docker git ssh-keygen; do
  command -v "$command" >/dev/null || die "real-SSH tests need $command"
done
docker compose version >/dev/null 2>&1 || die 'real-SSH tests need Docker Compose'

profile=default
suite=core
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile|--suite)
      [ "$#" -ge 2 ] || die "missing value for $1"
      case "$1" in
        --profile) profile=$2 ;;
        --suite) suite=$2 ;;
      esac
      shift 2
      ;;
    *) die 'usage: scripts/test-real-ssh.sh [--profile max-sessions-1] [--suite core|benchmark|storage|metadata]' ;;
  esac
done
case "$suite" in
  core|benchmark|storage|metadata) ;;
  *) die "unknown real-SSH test suite: $suite" ;;
esac
[ "$suite" != benchmark ] || [ "$profile" = default ] ||
  die 'the benchmark suite requires the default SSH profile'

root=$(git rev-parse --show-toplevel 2>/dev/null) || die 'run this from a syq checkout'
cd "$root"

compose_file=$root/tests/real-ssh/compose.yaml
test -f "$compose_file" || die "missing $compose_file"
compose_files=(--file "$compose_file")
case "$profile" in
  default) ;;
  max-sessions-1)
    compose_files+=(--file "$root/tests/real-ssh/compose.max-sessions-1.yaml")
    ;;
  *) die "unknown real-SSH test profile: $profile" ;;
esac
mkdir -p "$root/target"
state=$(mktemp -d "$root/target/real-ssh.XXXXXXXX")
chmod 0700 "$state"
token=${state##*.}
project="syq-real-ssh-${token,,}"
export SYQ_REAL_SSH_IMAGE="$project-node"
export SYQ_REAL_SSH_STATE=$state
export SYQ_REAL_SSH_SUITE=$suite

compose=(docker compose --project-name "$project" "${compose_files[@]}")
passed=false

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  set +e
  if [ "$passed" != true ]; then
    "${compose[@]}" logs --no-color >"$state/compose.log" 2>&1
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1
  docker image rm "$SYQ_REAL_SSH_IMAGE" >/dev/null 2>&1
  rm -f "$state/id_ed25519"
  if [ "$passed" = true ]; then
    case "$state" in
      "$root"/target/real-ssh.*) rm -rf "$state" ;;
      *) printf 'refusing to remove unexpected state path %s\n' "$state" >&2 ;;
    esac
  else
    printf 'real-SSH diagnostics retained in %s\n' "$state" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ssh-keygen -q -t ed25519 -N '' -C 'syq real-SSH test' -f "$state/id_ed25519"

revision=$(git rev-parse --short=12 HEAD)
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  revision="$revision (dirty)"
fi
printf 'building real-SSH lab for syq %s (profile %s, suite %s)\n' "$revision" "$profile" "$suite"
"${compose[@]}" config --quiet
build_started=$SECONDS
"${compose[@]}" build runner
printf 'real-SSH build: %ss\n' "$((SECONDS - build_started))"
execution_started=$SECONDS
"${compose[@]}" up --detach --wait --wait-timeout 60 source destination
"${compose[@]}" run --rm --no-deps runner

passed=true
printf 'real-SSH integration tests passed for syq %s (profile %s, suite %s) in %ss excluding build\n' \
  "$revision" "$profile" "$suite" "$((SECONDS - execution_started))"
