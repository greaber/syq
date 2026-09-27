#!/usr/bin/env python3
"""Disposable, loopback-only S3 integration tests. No cloud credentials needed.

Usage: scripts/test-s3.py [SYQ_BINARY]

Without SYQ_BINARY, builds target/debug/syq first. SYQ_S3_TEST_TIMEOUT raises
the 1800-second overall check deadline for slow hosts.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

from tooling import ForwardSignals

ROOT = Path(os.path.abspath(__file__)).parent.parent
# PGSTY Silo, a maintained community fork of the MinIO server, release
# RELEASE.2026-09-03T13-18-01Z (multi-architecture index digest).
IMAGE = ("docker.io/pgsty/silo@sha256:"
         "b616a0cf8cb281e7e6bb3c9b1fb53875b4016a2878223925541c18f82d6c5ca3")


def wait_for_server(endpoint, children):
    deadline = time.monotonic() + 60
    last = "not checked"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(endpoint + "/minio/health/ready", timeout=2) as response:
                if response.status == 200:
                    return
                last = f"HTTP {response.status}"
        except OSError as error:
            last = str(error)
        print(f"Waiting for the S3 server: {last}", flush=True)
        time.sleep(2)
        children.check()
    raise SystemExit(f"S3 server readiness deadline exceeded; last state: {last}")


def create_bucket(binary):
    # The shared checks read the syq binary from their command line.
    sys.argv[1:] = [binary]
    spec = importlib.util.spec_from_file_location("checks", "tests/object-storage/check.py")
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    checks.request("PUT")


def main():
    os.chdir(ROOT)
    binary = sys.argv[1] if len(sys.argv) > 1 else "target/debug/syq"
    if len(sys.argv) == 1:
        subprocess.run(["cargo", "build", "--locked"], check=True)
    os.environ.update(AWS_ACCESS_KEY_ID="syq-test-user", AWS_SECRET_ACCESS_KEY="syq-test-password",
                      AWS_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true",
                      SYQ_TEST_BUCKET="syq-test")
    for name in ("AWS_SESSION_TOKEN", "AWS_PROFILE", "SYQ_TEST_HEADERS"):
        os.environ.pop(name, None)
    children = ForwardSignals()
    container = None
    try:
        status, output = children.run(
            "docker", "run", "--detach", "--rm", "--tmpfs", "/data:rw,size=2g",
            "-p", "127.0.0.1::9000", "-e", f"MINIO_ROOT_USER={os.environ['AWS_ACCESS_KEY_ID']}",
            "-e", f"MINIO_ROOT_PASSWORD={os.environ['AWS_SECRET_ACCESS_KEY']}", IMAGE,
            "server", "/data", capture=True, stop=False)
        if status == 0:
            container = output.strip()
        children.check()
        if status:
            return status
        status, port = children.run(
            "docker", "inspect", "--format",
            '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}', container,
            capture=True)
        if status:
            return status
        os.environ["AWS_ENDPOINT_URL_S3"] = f"http://127.0.0.1:{port.strip()}"
        wait_for_server(os.environ["AWS_ENDPOINT_URL_S3"], children)
        create_bucket(binary)
        # The fault server owns its endpoint and cache; overlap it with the server checks.
        status, _ = children.run(sys.executable, "tests/object-storage/run.py", binary)
        return status
    finally:
        children.shield()
        if container:
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    sys.exit(main())
