#!/bin/sh
# Check scripts/dev-tools.lock and exercise scripts/dev-tools.sh against local
# fixture artifacts, without network access.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/syq-dev-tools-test.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

fail() {
  printf 'test-dev-tools: %s\n' "$*" >&2
  exit 1
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

# The real manifest: every tool pins one version for each supported platform,
# from an official download location, with a checksum.
awk '
  /^#/ || !NF { next }
  NF != 6 { printf "line %d: expected 6 fields\n", NR; bad = 1; next }
  $3 !~ /^(linux-x86_64|linux-aarch64|macos-arm64|macos-x86_64)$/ {
    printf "line %d: unknown platform %s\n", NR, $3; bad = 1
  }
  $5 == "uv" && $4 != "-" { printf "line %d: uv installs need no sha256\n", NR; bad = 1 }
  $5 != "uv" && (length($4) != 64 || $4 ~ /[^0-9a-f]/) { printf "line %d: invalid sha256\n", NR; bad = 1 }
  $5 != "uv" && $5 !~ "^https://(github[.]com/(koalaman/shellcheck|jqlang/jq|rust-lang/mdBook|astral-sh/uv)/releases/download/|nodejs[.]org/dist/|go[.]dev/dl/)" {
    printf "line %d: unexpected download location\n", NR; bad = 1
  }
  $5 != "uv" && index($5, $2) == 0 { printf "line %d: URL does not name version %s\n", NR, $2; bad = 1 }
  {
    if (seen[$1, $3]++) { printf "line %d: duplicate %s %s\n", NR, $1, $3; bad = 1 }
    if (($1 in version) && version[$1] != $2) { printf "line %d: %s has two versions\n", NR, $1; bad = 1 }
    version[$1] = $2
    platforms[$1]++
    if ($5 == "uv") uses_uv = 1
  }
  END {
    for (tool in platforms) {
      if (platforms[tool] != 4) { printf "%s does not list all four platforms\n", tool; bad = 1 }
    }
    if (uses_uv && !("uv" in version)) { print "uv installs need a pinned uv"; bad = 1 }
    exit bad
  }
' "$script_dir/dev-tools.lock" || fail 'scripts/dev-tools.lock is malformed'

# A copy of the script reads the fixture manifest beside it.
mkdir -p "$work/scripts" "$work/src" "$work/fakebin"
cp "$script_dir/dev-tools.sh" "$work/scripts/dev-tools.sh"
fixture=$work/scripts/dev-tools.lock
tools="$work/tool cache's"
cat > "$work/fakebin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) echo "$FAKE_UNAME_S" ;;
  -m) echo "$FAKE_UNAME_M" ;;
  *) exit 2 ;;
esac
EOF
chmod 755 "$work/fakebin/uname"

run() {
  PATH="$work/fakebin:$PATH" SYQ_TOOLS_DIR=$tools "$work/scripts/dev-tools.sh" "$@"
}

# One single-file artifact per platform prints the platform it was chosen for.
: > "$fixture"
for platform in linux-x86_64 linux-aarch64 macos-arm64 macos-x86_64; do
  printf '#!/bin/sh\necho %s\n' "$platform" > "$work/src/probe-$platform"
  printf 'probe 1.0 %s %s file://%s bin\n' "$platform" \
    "$(sha256_of "$work/src/probe-$platform")" "$work/src/probe-$platform" >> "$fixture"
done
# An archive, and an artifact whose pinned checksum does not match.
mkdir -p "$work/archive/demo-2.0"
printf '#!/bin/sh\necho demo 2.0\n' > "$work/archive/demo-2.0/demo"
chmod 755 "$work/archive/demo-2.0/demo"
tar -czf "$work/src/demo-2.0.tar.gz" -C "$work/archive" demo-2.0
printf 'not the pinned bytes\n' > "$work/src/bad"
for platform in linux-x86_64 linux-aarch64 macos-arm64 macos-x86_64; do
  printf 'demo 2.0 %s %s file://%s demo-2.0\n' "$platform" \
    "$(sha256_of "$work/src/demo-2.0.tar.gz")" "$work/src/demo-2.0.tar.gz" >> "$fixture"
  printf 'bad 1.0 %s %064d file://%s bin\n' "$platform" 0 "$work/src/bad" >> "$fixture"
done

# Platform detection selects each platform's own artifact.
for case in Linux:x86_64:linux-x86_64 Linux:aarch64:linux-aarch64 \
    Linux:arm64:linux-aarch64 Darwin:arm64:macos-arm64 Darwin:x86_64:macos-x86_64; do
  FAKE_UNAME_S=${case%%:*}
  rest=${case#*:}
  FAKE_UNAME_M=${rest%%:*}
  expected=${rest#*:}
  export FAKE_UNAME_S FAKE_UNAME_M
  rm -rf "$tools"
  run install probe
  actual=$(eval "$(run env probe)" && probe)
  [ "$actual" = "$expected" ] ||
    fail "$FAKE_UNAME_S $FAKE_UNAME_M selected $actual, expected $expected"
done

FAKE_UNAME_S=FreeBSD FAKE_UNAME_M=amd64
if run install probe 2>"$work/stderr"; then fail 'installed on an unsupported platform'; fi
grep -F 'no pinned tools for FreeBSD amd64' "$work/stderr" >/dev/null ||
  fail 'unsupported platform was not reported'

FAKE_UNAME_S=Linux FAKE_UNAME_M=x86_64
rm -rf "$tools"

# A checksum mismatch fails without leaving a visible or partial installation.
if run install bad 2>"$work/stderr"; then fail 'installed an artifact with the wrong checksum'; fi
grep -F 'bad 1.0 checksum mismatch' "$work/stderr" >/dev/null ||
  fail 'checksum mismatch was not reported'
[ -z "$(ls -A "$tools/bad")" ] || fail 'checksum mismatch left files behind'
if run env bad 2>"$work/stderr"; then fail 'env accepted a tool that is not installed'; fi
grep -F 'bad 1.0 is not installed' "$work/stderr" >/dev/null ||
  fail 'missing installation was not reported'

if run install unknown 2>"$work/stderr"; then fail 'installed an unknown tool'; fi
grep -F 'unknown tool: unknown' "$work/stderr" >/dev/null || fail 'unknown tool was not reported'

# Archives unpack into the shared cache; an installed version is reused.
run install demo probe
rm "$work/src/demo-2.0.tar.gz"
run install demo
[ "$(eval "$(run env demo probe)" && demo)" = 'demo 2.0' ] || fail 'demo did not run from PATH'
[ -z "$(find "$tools" -name '.*.*' -prune -print)" ] || fail 'staging files remain'

# GitHub Actions receives each tool's directory.
: > "$work/github-path"
: > "$work/github-env"
GITHUB_PATH=$work/github-path GITHUB_ENV=$work/github-env run github demo probe
[ "$(cat "$work/github-path")" = "$tools/demo/2.0/demo-2.0
$tools/probe/1.0/bin" ] || fail 'unexpected GITHUB_PATH entries'
[ ! -s "$work/github-env" ] || fail 'unexpected GITHUB_ENV entries'

echo 'dev-tools tests passed'
