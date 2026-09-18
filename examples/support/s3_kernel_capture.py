"""Bounded privileged collector for the S3 spike's explicitly gated clients.

Run with sudo and --run-dir pointing at a fresh task target directory. The
benchmark itself is launched separately as the normal user. Captures only
announced Docker client PIDs, never all processes or all CPUs. No host settings
are modified. /proc stack snapshots identify wait sites, not exact off-CPU time.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import subprocess
import time


def identity(pid):
    text = Path(f'/proc/{pid}/stat').read_text()
    return text[text.rfind(')') + 2:].split()[19]  # field22: process start ticks


def owned_target(request, uid):
    pid = request['pid']
    assert isinstance(pid, int) and pid > 1
    assert re.fullmatch('[0-9a-f]{64}', request['container'])
    status = Path(f'/proc/{pid}/status').read_text()
    ids = next(line.split()[1:] for line in status.splitlines() if line.startswith('Uid:'))
    assert all(int(value) == uid for value in ids), 'target UID differs from invoking user'
    assert identity(pid) == request['start_ticks'], 'PID was reused'
    assert request['container'] in Path(f'/proc/{pid}/cgroup').read_text(), 'wrong container'
    return pid


def stacks(pid):
    rows = []
    for task in Path(f'/proc/{pid}/task').iterdir():
        try:
            status = (task / 'status').read_text()
            state = next(line.split()[1] for line in status.splitlines() if line.startswith('State:'))
            rows.append(dict(tid=int(task.name), state=state,
                             wchan=(task / 'wchan').read_text().strip(),
                             stack=(task / 'stack').read_text().splitlines(),
                             schedstat=(task / 'schedstat').read_text().strip()))
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.ESRCH):
                raise
    return rows


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGINT)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        raise
    for fd in getattr(process, 'capture_fds', ()):
        os.close(fd)
    process.capture_fds = ()
    assert process.returncode in (0, -signal.SIGINT), f'perf exit {process.returncode}'


def record(pid, path, kernel=True):
    control_read, control_write = os.pipe()
    ack_read, ack_write = os.pipe()
    log = path.with_suffix('.log').open('x')
    args = ['/usr/bin/perf', 'record', '-e', 'cycles:k' if kernel else 'cycles:u',
            '-F', '99', '--call-graph', 'fp', '--clockid', 'mono', '--no-buildid-cache',
            '-D', '-1', '--control', f'fd:{control_read},{ack_write}',
            '-o', str(path), '-p', str(pid)]
    process = None
    try:
        process = subprocess.Popen(args, pass_fds=(control_read, ack_write),
                                   stdout=log, stderr=log, start_new_session=True)
        os.close(control_read)
        control_read = None
        os.close(ack_write)
        ack_write = None
        os.write(control_write, b'enable\n')
        ready, _, _ = select.select([ack_read], [], [], 8)
        assert ready and os.read(ack_read, 64).rstrip(b'\0') == b'ack\n', 'perf attach failed; see log'
        process.capture_fds = (control_write, ack_read)
        control_write = ack_read = None
        return process
    except BaseException:
        if process is not None:
            stop(process)
        raise
    finally:
        for fd in (control_read, control_write, ack_read, ack_write):
            if fd is not None:
                os.close(fd)
        log.close()


def save(path, value, uid, gid):
    # Publish atomically so the unprivileged gate never reads partial JSON.
    temporary = path.with_suffix('.tmp')
    with temporary.open('x') as out:
        os.fchmod(out.fileno(), 0o600)
        os.fchown(out.fileno(), uid, gid)
        json.dump(value, out)
    temporary.rename(path)


def capture(directory, request_path, uid, gid, deadline):
    request = json.loads(request_path.read_text())
    tag = request_path.name.removesuffix('.kernel-request.json')
    assert re.fullmatch('[A-Za-z0-9_-]+', tag)
    pid = owned_target(request, uid)
    output = directory / (tag + '.kernel.data')
    assert not output.exists(), 'refuse to overwrite capture'
    process = None
    outcome = {'pid': pid, 'tag': tag, 'status': 'failed'}
    began = time.monotonic()
    deadline = min(deadline, began + 90)
    try:
        process = record(pid, output)
        save(directory / (tag + '.kernel-ready.json'), dict(pid=pid, monotonic_ns=time.monotonic_ns()), uid, gid)
        with (directory / (tag + '.kernel-stacks.jsonl')).open('x') as trace:
            os.fchmod(trace.fileno(), 0o600)
            os.fchown(trace.fileno(), uid, gid)
            samples = 0
            next_progress = began + 10
            while time.monotonic() < deadline:
                if (directory / (tag + '.kernel-stop')).exists():
                    break
                try:
                    if identity(pid) != request['start_ticks']:
                        break
                    sample = dict(monotonic_ns=time.monotonic_ns(), threads=stacks(pid))
                except FileNotFoundError:
                    break
                trace.write(json.dumps(sample) + '\n')
                trace.flush()
                samples += 1
                if time.monotonic() >= next_progress:
                    print(f'{tag}: kernel capture {time.monotonic()-began:.0f}s, {samples} stack snapshots', flush=True)
                    next_progress = time.monotonic() + 10
                time.sleep(.1)
            else:
                raise TimeoutError(f'{tag}: capture deadline exceeded; last PID {pid}, samples {samples}')
        stop(process)
        process = None
        outcome.update(status='complete', samples=samples, elapsed=time.monotonic()-began)
    finally:
        try:
            if process is not None:
                stop(process)
        finally:
            for artifact in (output, output.with_suffix('.log')):
                if artifact.exists():
                    os.chmod(artifact, 0o600)
                    os.chown(artifact, uid, gid)
            save(directory / (tag + '.kernel-done.json'), outcome, uid, gid)
    print(f'{tag}: capture complete', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', required=True, type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and 'SUDO_UID' in os.environ, 'run using sudo as the repository owner'
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    assert uid != 0
    root = Path(__file__).resolve().parents[2]
    assert '.worktrees' in root.parts
    top = subprocess.check_output(['/usr/sbin/runuser', '-u', pwd.getpwuid(uid).pw_name, '--',
                                   'git', '-C', str(root), 'rev-parse', '--show-toplevel'], text=True).strip()
    assert top == str(root)
    directory = args.run_dir.resolve(strict=True)
    assert directory.parent == root / 'target' and directory.stat().st_uid == uid
    assert not (directory / 'kernel-collector.json').exists(), 'use a fresh run directory'
    def interrupted(signum, _frame):
        raise SystemExit(f"collector interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    os.umask(0o077)
    subprocess.run(['/usr/bin/perf', 'stat', '-e', 'cycles:k', '--', 'true'], check=True)
    stacks(os.getpid())  # Fail before opening the gate if stack access is denied.
    # Kernel addresses are retained locally for accurate offline symbolization.
    with (directory / 'kernel.kallsyms').open('x') as symbols:
        symbols.write(Path('/proc/kallsyms').read_text())
        os.fchown(symbols.fileno(), uid, gid)
    save(directory / 'kernel-collector.json', dict(status='ready', pid=os.getpid(), uid=uid,
         monotonic_ns=time.monotonic_ns(), deadline_seconds=300, max_captures=3), uid, gid)
    print('Collector ready: waiting for three owned client requests, deadline300s.', flush=True)
    deadline = time.monotonic() + 300
    next_progress = time.monotonic() + 10
    handled = set()
    while time.monotonic() < deadline and len(handled) < 3:
        for request in sorted(directory.glob('*.kernel-request.json')):
            if request not in handled:
                capture(directory, request, uid, gid, deadline)
                handled.add(request)
                if len(handled) == 3:
                    break
        if time.monotonic() >= next_progress:
            print(f'Collector waiting: {len(handled)}/3 completed, {max(0, deadline-time.monotonic()):.0f}s remaining.', flush=True)
            next_progress = time.monotonic() + 10
        time.sleep(.1)
    outcome = 'complete' if len(handled) == 3 else 'timeout'
    save(directory / 'kernel-collector-done.json', dict(status=outcome, captures=len(handled)), uid, gid)
    assert outcome == 'complete', f'collector timed out: {len(handled)}/3 captures'


if __name__ == '__main__':
    main()
