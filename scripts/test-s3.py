#!/usr/bin/env python3
"""Disposable, loopback-only S3 integration tests. No cloud credentials needed.

Usage: scripts/test-s3.py [SYQ_BINARY]

Without SYQ_BINARY, builds target/debug/syq first. SYQ_S3_TEST_TIMEOUT raises
the 1800-second overall check deadline for slow hosts.
"""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = Path(os.path.abspath(__file__)).parent.parent
IMAGE = ("quay.io/minio/minio@sha256:"
         "14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e")


def interrupted(status):
    def handler(signum, frame):
        raise SystemExit(status)
    return handler


def output(*args):
    completed = subprocess.run(list(args), stdout=subprocess.PIPE, text=True)
    if completed.returncode:
        raise SystemExit(completed.returncode)
    return completed.stdout.rstrip("\n")


def wait_for_minio(endpoint):
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
        print(f"Waiting for MinIO: {last}", flush=True)
        time.sleep(2)
    raise SystemExit(f"MinIO readiness deadline exceeded; last state: {last}")


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
    container = runner = None
    signal.signal(signal.SIGINT, interrupted(130))
    signal.signal(signal.SIGTERM, interrupted(143))
    try:
        container = output(
            "docker", "run", "--detach", "--rm", "--tmpfs", "/data:rw,size=2g",
            "-p", "127.0.0.1::9000", "-e", f"MINIO_ROOT_USER={os.environ['AWS_ACCESS_KEY_ID']}",
            "-e", f"MINIO_ROOT_PASSWORD={os.environ['AWS_SECRET_ACCESS_KEY']}", IMAGE,
            "server", "/data")
        port = output("docker", "inspect", "--format",
                      '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}', container)
        os.environ["AWS_ENDPOINT_URL_S3"] = f"http://127.0.0.1:{port}"
        wait_for_minio(os.environ["AWS_ENDPOINT_URL_S3"])
        create_bucket(binary)
        # The fault server owns its endpoint and cache; overlap it with MinIO checks.
        runner = subprocess.Popen([sys.executable, "tests/object-storage/run.py", binary])
        status = runner.wait()
        runner = None
        return status
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if runner is not None:
            runner.terminate()
            runner.wait()
        if container:
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    sys.exit(main())
