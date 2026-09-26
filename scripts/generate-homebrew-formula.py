#!/usr/bin/env python3
"""Generate the formula published to greaber/homebrew-tap from the same hashes
and immutable assets used by the standalone installer.

Usage: scripts/generate-homebrew-formula.py MANIFEST OUTPUT
"""
import re
import sys

from tooling import captured, exit_on_failure, get, load_file, require

DOWNLOAD_BASE = "https://dl.syq.christmas"

FORMULA = '''class Syq < Formula
  desc "Parallel copy with an rsync-shaped interface"
  homepage "@REPOSITORY@"
  version "@VERSION@"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "@DOWNLOAD_BASE@/@TAG@/@MAC_ARM_ASSET@", using: :nounzip
      sha256 "@MAC_ARM_HASH@"
    else
      url "@DOWNLOAD_BASE@/@TAG@/@MAC_X86_ASSET@", using: :nounzip
      sha256 "@MAC_X86_HASH@"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "@DOWNLOAD_BASE@/@TAG@/@LINUX_ARM_ASSET@", using: :nounzip
      sha256 "@LINUX_ARM_HASH@"
    else
      url "@DOWNLOAD_BASE@/@TAG@/@LINUX_X86_ASSET@", using: :nounzip
      sha256 "@LINUX_X86_HASH@"
    end
  end

  def install
    bin.install Dir["syq-*"].first => "syq"
  end

  test do
    assert_match "syq #{version}", shell_output("#{bin}/syq --version")
  end
end
'''


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} MANIFEST OUTPUT", file=sys.stderr)
        return 2
    manifest_path, output = sys.argv[1:]
    try:
        manifest = load_file(manifest_path)
    except OSError as error:
        print(f"jq: error: Could not open {manifest_path}: {error.strerror}", file=sys.stderr)
        return 2
    values = {
        "VERSION": captured(require(get(manifest, "version"))),
        "TAG": captured(require(get(manifest, "tag"))),
        "REPOSITORY": captured(require(get(manifest, "repository"))),
        "DOWNLOAD_BASE": DOWNLOAD_BASE,
    }
    if values["REPOSITORY"] != "https://github.com/greaber/syq":
        print("unexpected repository", file=sys.stderr)
        return 1
    for name, target in [("LINUX_X86", "linux-x86_64"), ("LINUX_ARM", "linux-aarch64"),
                         ("MAC_X86", "macos-x86_64"), ("MAC_ARM", "macos-arm64")]:
        binary = get(manifest, "artifacts", target, "binary")
        values[f"{name}_ASSET"] = captured(require(get(binary, "name")))
        values[f"{name}_HASH"] = captured(require(get(binary, "sha256")))
    formula = re.sub(r"@([A-Z0-9_]+)@", lambda match: values[match.group(1)], FORMULA)
    with open(output, "w", encoding="utf-8", newline="") as destination:
        destination.write(formula)
    return 0


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
