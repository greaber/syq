#!/usr/bin/env python3
"""Require a published crates.io version to be the exact package assembled from
the release tag. Exit 3 means that the version has not been published yet.

Usage: scripts/verify-crates-io-package.py VERSION CRATE_FILE

For tests, SYQ_TEST_CRATES_IO_RESPONSE and SYQ_TEST_CRATES_IO_STATUS replace
the registry request with a response file and HTTP status.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from tooling import sha256_file


def fail(message):
    print(message, file=sys.stderr)
    return 1


def version_field(response, name):
    """A string field of the crates.io response's version, or None."""
    try:
        value = json.loads(response)["version"][name]
    except (ValueError, KeyError, TypeError):
        return None
    return value if isinstance(value, str) and value else None


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} VERSION CRATE_FILE", file=sys.stderr)
        return 2
    version, package = sys.argv[1:]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?", version):
        print(f"invalid crate version: {version}", file=sys.stderr)
        return 2
    if not os.path.isfile(package) or os.path.islink(package):
        return fail(f"missing regular crate package: {package}")

    with tempfile.TemporaryDirectory(prefix="syq-crates-io.") as work:
        response_path = os.path.join(work, "response.json")
        fixture = os.environ.get("SYQ_TEST_CRATES_IO_RESPONSE", "")
        if fixture:
            status = os.environ.get("SYQ_TEST_CRATES_IO_STATUS", "")
            if not status:
                print("SYQ_TEST_CRATES_IO_RESPONSE requires SYQ_TEST_CRATES_IO_STATUS",
                      file=sys.stderr)
                return 2
            try:
                shutil.copyfile(fixture, response_path)
            except OSError as error:
                return fail(f"cp: cannot copy {fixture}: {error.strerror}")
        else:
            if not shutil.which("curl"):
                return fail("crate verification needs curl")
            completed = subprocess.run([
                "curl", "--silent", "--show-error", "--proto", "=https", "--user-agent",
                "syq-release-verifier (https://github.com/greaber/syq)", "--output", response_path,
                "--write-out", "%{http_code}", f"https://crates.io/api/v1/crates/syq/{version}"],
                stdout=subprocess.PIPE, text=True)
            if completed.returncode:
                return completed.returncode
            status = completed.stdout.rstrip("\n")
        with open(response_path, encoding="utf-8", errors="replace") as source:
            response = source.read()

    if status == "404":
        print(f"syq {version} is not published on crates.io")
        return 3
    if status != "200":
        print(f"crates.io returned HTTP {status} for syq {version}", file=sys.stderr)
        try:
            errors = json.loads(response).get("errors") or []
            details = [error.get("detail") for error in errors if isinstance(error, dict)]
        except (ValueError, AttributeError, TypeError):
            details = []
        for detail in details:
            if detail:
                print(detail, file=sys.stderr)
        return 1

    published_version = version_field(response, "num")
    if published_version is None:
        return fail("crates.io response has no version number")
    published_checksum = version_field(response, "checksum")
    if published_checksum is None:
        return fail("crates.io response has no package checksum")
    if published_version != version:
        return fail(f"crates.io returned version {published_version}, expected {version}")
    local_checksum = sha256_file(package)
    if published_checksum != local_checksum:
        print(f"crates.io syq {version} differs from the package assembled from this tag",
              file=sys.stderr)
        print(f"published: {published_checksum}", file=sys.stderr)
        return fail(f"local:     {local_checksum}")
    print(f"crates.io syq {version} is byte-for-byte identical to this package")
    return 0


if __name__ == "__main__":
    sys.exit(main())
