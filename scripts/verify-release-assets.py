#!/usr/bin/env python3
"""Download a GitHub release and require every published asset to be byte-for-
byte identical to the locally assembled release directory.

Usage: scripts/verify-release-assets.py TAG LOCAL_DIST_DIR
"""
import difflib
import filecmp
import os
import shutil
import subprocess
import sys
import tempfile


def fail(message):
    print(message, file=sys.stderr)
    return 1


def regular_files(directory):
    return sorted(name for name in os.listdir(directory)
                  if os.path.isfile(os.path.join(directory, name))
                  and not os.path.islink(os.path.join(directory, name)))


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} TAG LOCAL_DIST_DIR", file=sys.stderr)
        return 2
    tag, local_dist = sys.argv[1:]
    if not os.path.isdir(local_dist):
        return fail(f"missing local release directory: {local_dist}")
    if not shutil.which("gh"):
        return fail("release verification needs gh")

    with tempfile.TemporaryDirectory(prefix="syq-release-assets.") as work:
        published = os.path.join(work, "published")
        os.mkdir(published)
        download = subprocess.run(["gh", "release", "download", tag, "--dir", published])
        if download.returncode:
            return download.returncode
        local_names = regular_files(local_dist)
        published_names = regular_files(published)
        if local_names != published_names:
            sys.stdout.writelines(difflib.unified_diff(
                [name + "\n" for name in local_names], [name + "\n" for name in published_names],
                "local", "published"))
            sys.stdout.flush()
            return fail(f"published release {tag} has a different asset inventory")
        for name in local_names:
            if not filecmp.cmp(os.path.join(local_dist, name), os.path.join(published, name),
                               shallow=False):
                return fail(f"published release asset differs from this build: {name}")
    print(f"published release {tag} is byte-for-byte identical to this build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
