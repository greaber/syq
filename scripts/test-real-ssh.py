#!/usr/bin/env python3
"""Local-only real OpenSSH integration tests in an isolated Docker Compose project.

Usage: scripts/test-real-ssh.py [--profile max-sessions-1]
       [--suite core|benchmark|storage|metadata]
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

USAGE = ("usage: scripts/test-real-ssh.py [--profile max-sessions-1] "
         "[--suite core|benchmark|storage|metadata]")


class Die(Exception):
    pass


def interrupted(status):
    def handler(signum, frame):
        raise SystemExit(status)
    return handler


def run(*args, **kwargs):
    sys.stdout.flush()
    completed = subprocess.run(list(args), **kwargs)
    if completed.returncode:
        raise SystemExit(completed.returncode)


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
    arguments = sys.argv[1:]
    while arguments:
        if arguments[0] not in ("--profile", "--suite"):
            raise Die(USAGE)
        if len(arguments) < 2:
            raise Die(f"missing value for {arguments[0]}")
        if arguments[0] == "--profile":
            profile = arguments[1]
        else:
            suite = arguments[1]
        arguments = arguments[2:]
    if suite not in ("core", "benchmark", "storage", "metadata"):
        raise Die(f"unknown real-SSH test suite: {suite}")
    if suite == "benchmark" and profile != "default":
        raise Die("the benchmark suite requires the default SSH profile")

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
    state = tempfile.mkdtemp(prefix="real-ssh.", dir=f"{root}/target")
    os.chmod(state, 0o700)
    token = state.rsplit(".", 1)[-1]
    project = f"syq-real-ssh-{token.lower()}"
    os.environ["SYQ_REAL_SSH_IMAGE"] = f"{project}-node"
    os.environ["SYQ_REAL_SSH_STATE"] = state
    os.environ["SYQ_REAL_SSH_SUITE"] = suite
    compose = ["docker", "compose", "--project-name", project, *compose_files]

    passed = False
    signal.signal(signal.SIGINT, interrupted(130))
    signal.signal(signal.SIGTERM, interrupted(143))
    try:
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "syq real-SSH test", "-f",
            f"{state}/id_ed25519")
        revision = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"],
                                  stdout=subprocess.PIPE, text=True, check=True).stdout.rstrip("\n")
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"],
                               stdout=subprocess.PIPE, text=True, check=True).stdout.rstrip("\n")
        if dirty:
            revision += " (dirty)"
        print(f"building real-SSH lab for syq {revision} (profile {profile}, suite {suite})")
        run(*compose, "config", "--quiet")
        build_started = int(time.time())
        run(*compose, "build", "runner")
        print(f"real-SSH build: {int(time.time()) - build_started}s")
        execution_started = int(time.time())
        run(*compose, "up", "--detach", "--wait", "--wait-timeout", "60", "source", "destination")
        run(*compose, "run", "--rm", "--no-deps", "runner")
        passed = True
        print(f"real-SSH integration tests passed for syq {revision} (profile {profile}, suite "
              f"{suite}) in {int(time.time()) - execution_started}s excluding build")
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        sys.stdout.flush()
        cleanup(compose, state, root, passed)
    return 0


def cleanup(compose, state, root, passed):
    if not passed:
        with open(f"{state}/compose.log", "w") as log:
            subprocess.run([*compose, "logs", "--no-color"], stdout=log, stderr=subprocess.STDOUT)
    subprocess.run([*compose, "down", "--volumes", "--remove-orphans"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
