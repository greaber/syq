#!/bin/sh
# Set up a syq checkout for development: check the prerequisites that cannot
# be pinned, install the Rust toolchain, and install the tools pinned in
# scripts/setup.lock into a cache shared by every checkout.
#
# This is POSIX sh so that it runs on a stock macOS or Linux machine before
# any pinned tool exists.
set -eu

usage() {
  cat >&2 <<'EOF'
usage: scripts/setup.sh
       scripts/setup.sh install [TOOL...]
       scripts/setup.sh env [TOOL...]
       scripts/setup.sh github [TOOL...]

With no command, check prerequisites, install the Rust toolchain from
rust-toolchain.toml, and install every pinned tool.

install  Download, verify, and unpack pinned tools (default: all).
env      Print shell commands that put installed tools first on PATH:
           eval "$(scripts/setup.sh env)"
github   Install, then add the tools to a GitHub Actions job's PATH.

Tools are cached in ${SYQ_TOOLS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/syq/tools}.
EOF
  exit 2
}

die() {
  printf 'setup: %s\n' "$*" >&2
  exit 1
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository=$(dirname -- "$script_dir")
manifest=$script_dir/setup.lock
tools_dir=${SYQ_TOOLS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/syq/tools}

detect_platform() {
  os=$(uname -s)
  architecture=$(uname -m)
  case "$os:$architecture" in
    Linux:x86_64) echo linux-x86_64 ;;
    Linux:aarch64|Linux:arm64) echo linux-aarch64 ;;
    Darwin:arm64) echo macos-arm64 ;;
    Darwin:x86_64) echo macos-x86_64 ;;
    *) die "no pinned tools for $os $architecture" ;;
  esac
}

manifest_tools() {
  awk '!/^#/ && NF { if (!seen[$1]++) print $1 }' "$manifest"
}

# Set version, sha256, url, and bin from the tool's entry for this platform.
read_entry() {
  entry=$(awk -v tool="$1" -v platform="$platform" '
    !/^#/ && NF && $1 == tool && $3 == platform {
      found++; entry = $2 " " $4 " " $5 " " $6
    }
    END { if (found != 1) exit 1; print entry }
  ' "$manifest") || die "scripts/setup.lock has no single $1 entry for $platform"
  set -f
  # shellcheck disable=SC2086 # the manifest's fields contain no spaces
  set -- $entry
  set +f
  version=$1 sha256=$2 url=$3 bin=$4
}

# The main executable, used to check that an installed tool is complete.
executable() {
  case "$1" in
    python) echo python3 ;;
    *) echo "$1" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# Download $1 to $3 and require SHA-256 $2.
fetch() {
  curl --fail --silent --show-error --location --retry 3 \
    --proto '=https,file' --proto-redir '=https' --output "$3" "$1"
  actual=$(sha256_of "$3")
  [ "$actual" = "$2" ] ||
    die "checksum mismatch for $1: expected $2, got $actual"
}

staging=
cleanup() {
  if [ -n "$staging" ]; then
    rm -rf "$staging" "$staging.download"
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

install_tool() {
  read_entry "$1"
  if [ -d "$tools_dir/$1/$version" ]; then
    return
  fi
  if [ "$url" = uv ]; then
    install_tool uv
    read_entry uv
    uv_command=$tools_dir/uv/$version/$bin/uv
    read_entry "$1"
  fi
  destination=$tools_dir/$1/$version
  echo "setup: installing $1 $version" >&2
  mkdir -p "$tools_dir/$1"
  # Unpack beside the destination and rename it into place, so other
  # checkouts never see a partial installation.
  staging=$(mktemp -d "$tools_dir/$1/.$version.XXXXXX")
  chmod 755 "$staging"
  if [ "$url" = uv ]; then
    "$uv_command" --no-config python install --no-bin \
      --install-dir "$staging" "$version" >&2
    # uv also links the minor version to the staging path; nothing uses it.
    for link in "$staging"/*; do
      if [ -L "$link" ]; then rm "$link"; fi
    done
  else
    download=$staging.download
    fetch "$url" "$sha256" "$download"
    case "$url" in
      *.tar.gz) tar -xzf "$download" -C "$staging" ;;
      *)
        mkdir -p "$staging/$bin"
        mv "$download" "$staging/$bin/$1"
        chmod 755 "$staging/$bin/$1"
        ;;
    esac
    rm -f "$download"
  fi
  [ -x "$staging/$bin/$(executable "$1")" ] ||
    die "$1 $version did not provide $bin/$(executable "$1")"
  # If another process installed the same version first, mv places this copy
  # inside the complete directory; remove it from there.
  mv "$staging" "$destination"
  rm -rf "${destination:?}/${staging##*/}"
  staging=
}

bin_directory() {
  read_entry "$1"
  [ -d "$tools_dir/$1/$version" ] ||
    die "$1 $version is not installed; run: scripts/setup.sh install $1"
  case "$bin" in
    .) echo "$tools_dir/$1/$version" ;;
    *) echo "$tools_dir/$1/$version/$bin" ;;
  esac
}

# Prerequisites that the setup cannot pin.
check_prerequisites() {
  missing=
  for prerequisite in git curl tar cc rustup; do
    command -v "$prerequisite" >/dev/null 2>&1 || missing="$missing $prerequisite"
  done
  if command -v cc >/dev/null 2>&1 && ! cc --version >/dev/null 2>&1; then
    missing="$missing cc"
  fi
  if [ -n "$missing" ]; then
    cat >&2 <<EOF
setup: missing prerequisites:$missing
  macOS: run xcode-select --install for Git and a C compiler.
  Debian or Ubuntu: sudo apt-get install git curl build-essential
  Rust: install rustup from https://rustup.rs
EOF
    exit 1
  fi
}

install_rust() {
  channel=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$repository/rust-toolchain.toml")
  [ -n "$channel" ] || die 'rust-toolchain.toml has no channel'
  echo "setup: installing Rust $channel" >&2
  rustup toolchain install "$channel" --no-self-update --profile minimal \
    --component rustfmt --component clippy >&2
}

if [ "$#" -eq 0 ]; then
  action=setup
else
  action=$1
  shift
fi
case "$action" in
  setup|install|env|github) ;;
  *) usage ;;
esac
[ -f "$manifest" ] || die "missing $manifest"
platform=$(detect_platform)
if [ "$action" = setup ]; then
  check_prerequisites
  install_rust
fi
if [ "$#" -eq 0 ]; then
  # shellcheck disable=SC2046 # tool names contain no spaces
  set -- $(manifest_tools)
fi
for tool in "$@"; do
  manifest_tools | grep -Fqx -- "$tool" || die "unknown tool: $tool"
done

if [ "$action" != env ]; then
  for tool in "$@"; do install_tool "$tool"; done
fi

path=
uv_python=
go_toolchain=
for tool in "$@"; do
  directory=$(bin_directory "$tool")
  path=$path$directory:
  case "$tool" in
    python) uv_python=$directory/python3 ;;
    # Fail instead of silently downloading a different Go toolchain.
    go) go_toolchain=local ;;
  esac
done

case "$action" in
  setup)
    cat >&2 <<'EOF'
setup: done. To use the pinned tools in a shell, run:
  eval "$(scripts/setup.sh env)"
EOF
    ;;
  env)
    # shellcheck disable=SC2016 # $PATH expands when the output is evaluated
    printf 'export PATH=%s"$PATH"\n' "$(shell_quote "$path")"
    if [ -n "$uv_python" ]; then
      printf 'export UV_PYTHON=%s\n' "$(shell_quote "$uv_python")"
    fi
    if [ -n "$go_toolchain" ]; then
      printf 'export GOTOOLCHAIN=%s\n' "$go_toolchain"
    fi
    ;;
  github)
    [ -n "${GITHUB_PATH:-}" ] && [ -n "${GITHUB_ENV:-}" ] ||
      die 'github needs GITHUB_PATH and GITHUB_ENV'
    for tool in "$@"; do bin_directory "$tool" >> "$GITHUB_PATH"; done
    if [ -n "$uv_python" ]; then
      printf 'UV_PYTHON=%s\n' "$uv_python" >> "$GITHUB_ENV"
    fi
    if [ -n "$go_toolchain" ]; then
      printf 'GOTOOLCHAIN=%s\n' "$go_toolchain" >> "$GITHUB_ENV"
    fi
    ;;
esac
