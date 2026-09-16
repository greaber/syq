#!/usr/bin/env bash
# CI-only setup: Nix's official installer embeds hashes of its platform archives.
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] || {
  echo 'This installer is for disposable GitHub runners. Install Nix normally on your own machine.' >&2
  exit 1
}
installer="$RUNNER_TEMP/install-nix"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  https://releases.nixos.org/nix/nix-2.34.5/install --output "$installer"
expected=56aabba6d78b930dc12d9b788263e515b3cd9dbe4dd041a6832d75d6b121b4f3
actual=$(shasum -a 256 "$installer" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo 'Nix installer checksum mismatch.' >&2; exit 1; }
sh "$installer" --daemon --yes --no-channel-add
printf '%s\n' /nix/var/nix/profiles/default/bin >> "$GITHUB_PATH"
