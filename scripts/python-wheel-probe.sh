#!/usr/bin/env bash
# Diagnostic branch only: exercise the proposed packaging recipe on macOS.
set -euo pipefail
mkdir -p target/python-repro/results
python3 scripts/stage-python-sdk.py --out target/python-repro/source
for attempt in first second; do
  output=$(nix --extra-experimental-features 'nix-command flakes' build \
    --impure --file scripts/python-wheel-probe.nix --argstr attempt "$attempt" \
    --no-link --print-out-paths -L 2> >(tee "target/python-repro/results/$attempt.log" >&2))
  mkdir -p "target/python-repro/results/$attempt"
  cp "$output"/* "target/python-repro/results/$attempt/"
  python3 -m venv "target/python-repro/venv-$attempt"
  python="target/python-repro/venv-$attempt/bin/python"
  "$python" -m pip install --no-index --no-deps "target/python-repro/results/$attempt/"*.whl
  "$python" scripts/check-python-wheel.py --version 0.6.0 --identity v0.6.0
  binary="target/python-repro/venv-$attempt/bin/syq"
  otool -L "$binary" | tee "target/python-repro/results/$attempt-linkage.txt"
  if otool -L "$binary" | grep '/nix/store/'; then
    echo 'Wheel binary depends on Nix libraries' >&2
    exit 1
  fi
  otool -l "$binary" > "target/python-repro/results/$attempt-load-commands.txt"
  minimum=$(otool -l "$binary" | awk '$1 == "cmd" { command = $2 }
    (command == "LC_BUILD_VERSION" && $1 == "minos") ||
    (command == "LC_VERSION_MIN_MACOSX" && $1 == "version") { print $2 }')
  test "$minimum" = 11.0
  codesign --verify "$binary"
done
python3 scripts/compare-python-wheel-probe.py | tee target/python-repro/results/comparison.txt
