#!/usr/bin/env python3
"""Local-only real OpenSSH integration tests in an isolated Docker Compose project.

Usage: scripts/test-real-ssh.py [--profile max-sessions-1]
       [--suite core|benchmark|storage|metadata] [--image NAME]

--image uses an already loaded lab image built from this checkout instead of
building one, and leaves it in place afterwards. CI builds the image once and
runs the suites in parallel jobs.
"""
import os
import secrets
import shutil
import subprocess
import sys
import time

from tooling import ForwardSignals

USAGE = ("usage: scripts/test-real-ssh.py [--profile max-sessions-1] "
         "[--suite core|benchmark|storage|metadata] [--image NAME]")


class Die(Exception):
    pass


def main():
    try:
        return lab()
    except Die as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def lab():
    for command in ("docker", "git", "ssh-keygen"):
        if not shutil.which(command):
            raise Die(f"real-SSH tests need {command}")
    if subprocess.run(["docker", "compose", "version"], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode:
        raise Die("real-SSH tests need Docker Compose")

    profile = "default"
    suite = "core"
    image = None
    arguments = sys.argv[1:]
    while arguments:
        if arguments[0] not in ("--profile", "--suite", "--image"):
            raise Die(USAGE)
        if len(arguments) < 2:
            raise Die(f"missing value for {arguments[0]}")
        if arguments[0] == "--profile":
            profile = arguments[1]
        elif arguments[0] == "--suite":
            suite = arguments[1]
        else:
            image = arguments[1]
        arguments = arguments[2:]
    if suite not in ("core", "benchmark", "storage", "metadata"):
        raise Die(f"unknown real-SSH test suite: {suite}")
    if suite == "benchmark" and profile != "default":
        raise Die("the benchmark suite requires the default SSH profile")
    if image is not None and subprocess.run(
            ["docker", "image", "inspect", image], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL).returncode:
        raise Die(f"no loaded Docker image named {image}")

    toplevel = subprocess.run(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True)
    if toplevel.returncode:
        raise Die("run this from a syq checkout")
    root = toplevel.stdout.rstrip("\n")
    os.chdir(root)

    compose_file = f"{root}/tests/real-ssh/compose.yaml"
    if not os.path.isfile(compose_file):
        raise Die(f"missing {compose_file}")
    compose_files = ["--file", compose_file]
    if profile == "max-sessions-1":
        compose_files += ["--file", f"{root}/tests/real-ssh/compose.max-sessions-1.yaml"]
    elif profile != "default":
        raise Die(f"unknown real-SSH test profile: {profile}")
    os.makedirs(f"{root}/target", exist_ok=True)
    # Docker Compose project names allow only lowercase letters, digits,
    # hyphens, and underscores; a hexadecimal token keeps the name valid.
    token = secrets.token_hex(4)
    state = f"{root}/target/real-ssh.{token}"
    os.mkdir(state, 0o700)
    project = f"syq-real-ssh-{token}"
    os.environ["SYQ_REAL_SSH_IMAGE"] = image or f"{project}-node"
    os.environ["SYQ_REAL_SSH_STATE"] = state
    os.environ["SYQ_REAL_SSH_SUITE"] = suite
    compose = ["docker", "compose", "--project-name", project, *compose_files]

    children = ForwardSignals()

    def run(*args):
        status, _ = children.run(*args)
        if status:
            raise SystemExit(status)

    passed = False
    try:
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "syq real-SSH test", "-f",
            f"{state}/id_ed25519")
        revision = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"],
                                  stdout=subprocess.PIPE, text=True, check=True).stdout.strip()
        if subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"],
                          stdout=subprocess.PIPE, text=True, check=True).stdout.strip():
            revision += " (dirty)"
        print(f"real-SSH lab for syq {revision} (profile {profile}, suite {suite})")
        run(*compose, "config", "--quiet")
        if image is None:
            build_started = time.monotonic()
            run(*compose, "build", "runner")
            print(f"real-SSH build: {time.monotonic() - build_started:.0f}s")
        else:
            print(f"real-SSH lab image: {image}")
        execution_started = time.monotonic()
        run(*compose, "up", "--detach", "--wait", "--wait-timeout", "60", "source", "destination")
        run(*compose, "run", "--rm", "--no-deps", "runner")
        passed = True
        print(f"real-SSH integration tests passed for syq {revision} (profile {profile}, suite "
              f"{suite}) in {time.monotonic() - execution_started:.0f}s excluding build")
    finally:
        children.shield()
        sys.stdout.flush()
        cleanup(compose, state, root, passed, remove_image=image is None)
    return 0


def cleanup(compose, state, root, passed, remove_image):
    if not passed:
        with open(f"{state}/compose.log", "w") as log:
            subprocess.run([*compose, "logs", "--no-color"], stdout=log, stderr=subprocess.STDOUT)
    subprocess.run([*compose, "down", "--volumes", "--remove-orphans"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if remove_image:
        subprocess.run(["docker", "image", "rm", os.environ["SYQ_REAL_SSH_IMAGE"]],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        os.remove(f"{state}/id_ed25519")
    except FileNotFoundError:
        pass
    if passed:
        if os.path.dirname(state) == f"{root}/target" and os.path.basename(state).startswith("real-ssh."):
            shutil.rmtree(state)
        else:
            print(f"refusing to remove unexpected state path {state}", file=sys.stderr)
    else:
        print(f"real-SSH diagnostics retained in {state}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
