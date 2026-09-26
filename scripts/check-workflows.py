#!/usr/bin/env python3
"""Run a checksum-pinned actionlint without installing it globally.

Usage: scripts/check-workflows.py [ACTIONLINT_ARGUMENT...]
"""
import hashlib
import os
import platform
import subprocess
import sys
import tempfile

ACTIONLINT_VERSION = "1.7.12"
PLATFORMS = {
    ("Linux", "x86_64"): ("linux_amd64",
                          "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"),
    ("Linux", "aarch64"): ("linux_arm64",
                           "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"),
    ("Linux", "arm64"): ("linux_arm64",
                         "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"),
    ("Darwin", "x86_64"): ("darwin_amd64",
                           "5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644"),
    ("Darwin", "arm64"): ("darwin_arm64",
                          "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"),
}


def main():
    system, machine = platform.system(), platform.machine()
    if (system, machine) not in PLATFORMS:
        print(f"actionlint {ACTIONLINT_VERSION} is not pinned for {system} {machine}",
              file=sys.stderr)
        return 1
    name, sha256 = PLATFORMS[system, machine]
    with tempfile.TemporaryDirectory(prefix="syq-actionlint.") as work:
        archive = os.path.join(work, "actionlint.tar.gz")
        url = (f"https://github.com/rhysd/actionlint/releases/download/v{ACTIONLINT_VERSION}/"
               f"actionlint_{ACTIONLINT_VERSION}_{name}.tar.gz")
        download = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
                                   "--proto", "=https", "--proto-redir", "=https",
                                   "--output", archive, url])
        if download.returncode:
            return download.returncode
        with open(archive, "rb") as source:
            actual_sha256 = hashlib.sha256(source.read()).hexdigest()
        if actual_sha256 != sha256:
            print(f"actionlint archive checksum mismatch: {actual_sha256}", file=sys.stderr)
            return 1
        extract = subprocess.run(["tar", "-xzf", archive, "-C", work, "actionlint"])
        if extract.returncode:
            return extract.returncode
        return subprocess.run([os.path.join(work, "actionlint"), *sys.argv[1:]]).returncode


if __name__ == "__main__":
    sys.exit(main())
