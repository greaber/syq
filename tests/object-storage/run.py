#!/usr/bin/env python3
"""Overlap the independent fault server with the sequential MinIO checks."""
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def stop(children):
    # SIGINT lets each script's finally blocks stop its independently grouped
    # interruption-test children and remove its objects before MinIO goes away.
    for child, _, _ in children:
        try:
            os.killpg(child.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 20
    for child, _, _ in children:
        try:
            child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
    for child, _, _ in children:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise RuntimeError(f'S3 worker process group {child.pid} survived cleanup')


def main():
    binary = str(Path(sys.argv[1]).resolve())
    # A suite-level ceiling only guards the scheduler; individual commands keep
    # their existing timeouts. Slow hosts can raise it without changing tests.
    timeout = float(os.environ.get('SYQ_S3_TEST_TIMEOUT', '1800'))
    if timeout <= 0 or not math.isfinite(timeout):
        raise ValueError('SYQ_S3_TEST_TIMEOUT must be positive and finite')
    groups = [['fast'], ['check', 'selection', 'remove', 'prune',
                         'fast-provider', 'streams', 'server-copy']]
    children = []
    started = time.monotonic()
    next_progress = started + 10
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    with tempfile.TemporaryDirectory(prefix='syq-s3-suite-') as cache:
        env = {**os.environ, 'XDG_CACHE_HOME': cache}
        try:
            while children or any(groups):
                for group in groups:
                    if group and not any(active is group for _, active, _ in children):
                        name = group.pop(0)
                        print(f'Starting S3 {name}', flush=True)
                        child = subprocess.Popen(
                            [sys.executable, str(Path(__file__).with_name(name + '.py')), binary],
                            env=env, start_new_session=True)
                        children.append((child, group, time.monotonic()))
                for child, group, begin in children[:]:
                    status = child.poll()
                    if status is not None:
                        if status:
                            raise subprocess.CalledProcessError(status, child.args)
                        print(f'S3 {Path(child.args[1]).stem} passed in {time.monotonic() - begin:.2f}s', flush=True)
                        children.remove((child, group, begin))
                    elif time.monotonic() - started >= timeout:
                        raise subprocess.TimeoutExpired(child.args, timeout)
                if time.monotonic() >= next_progress:
                    names = ", ".join(Path(child.args[1]).stem for child, _, _ in children)
                    print(f"Waiting for S3 checks: {names}", flush=True)
                    next_progress = time.monotonic() + 10
                time.sleep(.1)
        finally:
            # Finish cleanup even if the caller repeats Ctrl-C.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            stop(children)
    print(f'S3 checks passed in {time.monotonic() - started:.2f}s', flush=True)


if __name__ == '__main__':
    main()
