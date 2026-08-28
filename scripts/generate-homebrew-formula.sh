#!/usr/bin/env bash
# Generate the formula published to greaber/homebrew-tap from the same hashes
# and immutable assets used by the standalone installer.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 MANIFEST OUTPUT" >&2
  exit 2
fi
manifest=$1
output=$2
command -v jq >/dev/null || { echo "generate-homebrew-formula needs jq" >&2; exit 1; }

version=$(jq -er '.version' "$manifest")
tag=$(jq -er '.tag' "$manifest")
repository=$(jq -er '.repository' "$manifest")
test "$repository" = 'https://github.com/greaber/syq' || { echo "unexpected repository" >&2; exit 1; }

asset() { jq -er --arg target "$1" '.artifacts[$target].binary.name' "$manifest"; }
hash() { jq -er --arg target "$1" '.artifacts[$target].binary.sha256' "$manifest"; }

linux_x86_asset=$(asset linux-x86_64)
linux_x86_hash=$(hash linux-x86_64)
linux_arm_asset=$(asset linux-aarch64)
linux_arm_hash=$(hash linux-aarch64)
mac_x86_asset=$(asset macos-x86_64)
mac_x86_hash=$(hash macos-x86_64)
mac_arm_asset=$(asset macos-arm64)
mac_arm_hash=$(hash macos-arm64)

cat > "$output" <<EOF
class Syq < Formula
  desc "Parallel copy with an rsync-shaped interface"
  homepage "$repository"
  version "$version"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "$repository/releases/download/$tag/$mac_arm_asset", using: :nounzip
      sha256 "$mac_arm_hash"
    else
      url "$repository/releases/download/$tag/$mac_x86_asset", using: :nounzip
      sha256 "$mac_x86_hash"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$repository/releases/download/$tag/$linux_arm_asset", using: :nounzip
      sha256 "$linux_arm_hash"
    else
      url "$repository/releases/download/$tag/$linux_x86_asset", using: :nounzip
      sha256 "$linux_x86_hash"
    end
  end

  def install
    bin.install Dir["syq-*"].first => "syq"
  end

  test do
    assert_match "syq #{version}", shell_output("#{bin}/syq --version")
  end
end
EOF
