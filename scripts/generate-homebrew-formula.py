#!/usr/bin/env python3
"""Generate the formula published to greaber/homebrew-tap from the same hashes
and immutable assets used by the standalone installer.

Usage: scripts/generate-homebrew-formula.py MANIFEST OUTPUT
"""
import re
import sys

from tooling import ToolError, load_release_manifest, report_errors

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
    manifest = load_release_manifest(manifest_path)
    values = {"VERSION": manifest["version"], "TAG": manifest["tag"],
              "REPOSITORY": manifest["repository"], "DOWNLOAD_BASE": DOWNLOAD_BASE}
    for name, target in [("LINUX_X86", "linux-x86_64"), ("LINUX_ARM", "linux-aarch64"),
                         ("MAC_X86", "macos-x86_64"), ("MAC_ARM", "macos-arm64")]:
        try:
            binary = manifest["artifacts"][target]["binary"]
            values[f"{name}_ASSET"], values[f"{name}_HASH"] = binary["name"], binary["sha256"]
        except (KeyError, TypeError):
            raise ToolError(f"release manifest has no binary for {target}") from None
        asset, digest = values[f"{name}_ASSET"], values[f"{name}_HASH"]
        if not (isinstance(asset, str) and re.fullmatch(r"[A-Za-z0-9._-]+", asset)
                and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ToolError(f"invalid binary metadata for {target}")
    formula = re.sub(r"@([A-Z0-9_]+)@", lambda match: values[match.group(1)], FORMULA)
    with open(output, "w", encoding="utf-8", newline="") as destination:
        destination.write(formula)
    return 0


if __name__ == "__main__":
    sys.exit(report_errors(main))
