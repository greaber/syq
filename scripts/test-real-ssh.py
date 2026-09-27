#!/usr/bin/env python3
"""Local-only real OpenSSH integration tests in an isolated Docker Compose project.

Usage: scripts/test-real-ssh.py [--profile max-sessions-1]
       [--suite core|benchmark|storage|metadata] [--image NAME]
       [--case TEXT]... [--cases-from FILE]
       scripts/test-real-ssh.py --list-cases

--image uses an already loaded lab image built from this checkout instead of
building one, and leaves it in place afterwards. CI builds the image once and
runs the suites in parallel jobs.

--case runs the core suite's shared setup and final checks with only the cases
whose names contain TEXT (ignoring case); repeat it to add cases. --cases-from
reads one TEXT per line, ignoring blank lines and lines starting with #.
--list-cases prints the core suite's case names. Subsets are for iteration:
cases share lab state, so run the whole suite when it is relevant to a change.
"""
import re
import os
import secrets
import shutil
import subprocess
import sys
import time

from tooling import ForwardSignals

USAGE = ("usage: scripts/test-real-ssh.py [--profile max-sessions-1] "
         "[--suite core|benchmark|storage|metadata] [--image NAME] "
         "[--case TEXT]... [--cases-from FILE] | --list-cases")
SCENARIOS = "tests/real-ssh/scenarios.sh"
CASE_HEADER = re.compile(r"^printf 'case: (.*)\\n'$")
FINAL_CHECKS = "# Final checks after every selected case."
# The entrypoint runs these checks as root before the scenarios.
ROOT_SECURITY = "privileged copies keep root security checks"


class Die(Exception):
    pass


def scenario_parts(text):
    """Split the core scenarios into setup, named cases and final checks."""
    lines = text.splitlines(keepends=True)
    setup, cases, final = [], [], None
    for line in lines:
        header = CASE_HEADER.match(line.rstrip("\n"))
        if final is not None:
            final.append(line)
        elif line.rstrip("\n") == FINAL_CHECKS:
            final = [line]
        elif header:
            cases.append((header.group(1), [line]))
        elif cases:
            cases[-1][1].append(line)
        else:
            setup.append(line)
    if not cases or final is None:
        raise Die(f"cannot find the cases and final checks in {SCENARIOS}")
    return setup, cases, final


def select_cases(names, patterns):
    selected = set()
    for pattern in patterns:
        matches = [name for name in names if pattern.casefold() in name.casefold()]
        if not matches:
            raise Die(f"no real-SSH case name contains: {pattern}")
        selected.update(matches)
    return selected


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
    patterns = []
    arguments = sys.argv[1:]
    if arguments == ["--list-cases"]:
        return list_cases()
    while arguments:
        if arguments[0] not in ("--profile", "--suite", "--image", "--case", "--cases-from"):
            raise Die(USAGE)
        if len(arguments) < 2:
            raise Die(f"missing value for {arguments[0]}")
        if arguments[0] == "--profile":
            profile = arguments[1]
        elif arguments[0] == "--suite":
            suite = arguments[1]
        elif arguments[0] == "--image":
            image = arguments[1]
        elif arguments[0] == "--case":
            patterns.append(arguments[1])
        else:
            try:
                with open(arguments[1]) as listed:
                    patterns += [line.strip() for line in listed
                                 if line.strip() and not line.lstrip().startswith("#")]
            except OSError as error:
                raise Die(f"cannot read {arguments[1]}: {error}")
        arguments = arguments[2:]
    if suite not in ("core", "benchmark", "storage", "metadata"):
        raise Die(f"unknown real-SSH test suite: {suite}")
    if suite == "benchmark" and profile != "default":
        raise Die("the benchmark suite requires the default SSH profile")
    if patterns and suite != "core":
        raise Die("--case and --cases-from select cases of the core suite")
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
    if patterns:
        setup, cases, final = scenario_parts(open(f"{root}/{SCENARIOS}").read())
        selected = select_cases([ROOT_SECURITY, *(name for name, _ in cases)], patterns)
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
    subset = []
    if patterns:
        os.environ["SYQ_REAL_SSH_ROOT_SECURITY"] = "1" if ROOT_SECURITY in selected else "0"
        script = f"{state}/scenarios.sh"
        with open(script, "w") as filtered:
            filtered.writelines(setup)
            for name, lines in cases:
                if name in selected:
                    filtered.writelines(lines)
            filtered.writelines(final)
        os.chmod(script, 0o755)
        subset = ["--volume", f"{script}:/usr/local/libexec/syq-real-ssh-scenarios:ro"]
        print(f"selected {len(selected)} real-SSH cases:")
        for name in [ROOT_SECURITY, *(name for name, _ in cases)]:
            if name in selected:
                print(f"  {name}")

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
        run(*compose, "run", "--rm", "--no-deps", *subset, "runner")
        passed = True
        print(f"real-SSH integration tests passed for syq {revision} (profile {profile}, suite "
              f"{suite}) in {time.monotonic() - execution_started:.0f}s excluding build")
    finally:
        children.shield()
        sys.stdout.flush()
        cleanup(compose, state, root, passed, remove_image=image is None)
    return 0


def list_cases():
    toplevel = subprocess.run(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True)
    if toplevel.returncode:
        raise Die("run this from a syq checkout")
    _, cases, _ = scenario_parts(open(f"{toplevel.stdout.rstrip()}/{SCENARIOS}").read())
    print(ROOT_SECURITY)
    for name, _ in cases:
        print(name)
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
