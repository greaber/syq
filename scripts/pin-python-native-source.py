#!/usr/bin/env python3
"""Record the source tree used by the Python release recipe."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(os.path.abspath(__file__)).parent.parent


def output(*args):
    completed = subprocess.run(list(args), stdout=subprocess.PIPE, text=True)
    if completed.returncode:
        sys.exit(completed.returncode)
    return completed.stdout.rstrip("\n")


def main():
    os.chdir(ROOT)
    manifest = json.loads(Path("sdk/python/src/syq/syq-release-manifest.json").read_text())
    tag = manifest.get("tag") if isinstance(manifest, dict) else None
    if not isinstance(tag, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        print(f"the SDK release manifest has no valid syq release tag: {tag!r}", file=sys.stderr)
        return 1
    revision = output("git", "rev-parse", f"refs/tags/{tag}^{{commit}}")
    prefetched = output("nix", "--extra-experimental-features", "nix-command flakes", "flake",
                        "prefetch", "--json", f"github:greaber/syq/{revision}")
    try:
        narhash = json.loads(prefetched)["hash"]
    except (ValueError, KeyError, TypeError):
        narhash = None
    if not isinstance(narhash, str) or not narhash:
        print(f"nix flake prefetch reported no source hash for {revision}", file=sys.stderr)
        return 1
    pin = {"tag": tag, "rev": revision, "narHash": narhash}
    Path("sdk/python/native-source.json").write_text(json.dumps(pin, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
