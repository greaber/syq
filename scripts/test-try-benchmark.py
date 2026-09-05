#!/usr/bin/env python3
"""Exercise the standalone script, including piped prompts and failure cleanup.

Remote tests here fake only SSH and syq; rsync still runs its real client/server
protocol. tests/real-ssh additionally exercises real syq over real OpenSSH.
"""
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().with_name('try-benchmark.sh')
FAKE_SYQ = r'''#!/usr/bin/env python3
import os, pathlib, shutil, subprocess, sys, time
args=sys.argv[1:]
if args == ['--version']:
    print('syq test double'); sys.exit(0)
src=pathlib.Path(args[args.index('--srcs-in')+1])
dst=pathlib.Path(args[args.index('--into')+1])
if src.name == 'probe' and os.environ.get('BENCH_TEST_ASK'):
    print('Credentials:', flush=True)
    with open('/dev/tty') as terminal:
        if terminal.readline().strip() != 'test': sys.exit(4)
mode=os.environ.get('BENCH_TEST_FAILURE', '') if src.name != 'probe' else ''
if mode == 'fail': sys.exit(23)
if mode == 'hang':
    child=subprocess.Popen(['sleep','300'])
    pathlib.Path(os.environ['BENCH_TEST_PID']).write_text(str(child.pid))
    child.wait(); sys.exit(1)
shutil.copytree(src,dst,dirs_exist_ok=True)
if mode == 'corrupt':
    next(dst.iterdir()).write_bytes(b'bad')
'''
FAKE_SSH = '''#!/usr/bin/env bash
set -eu
while [[ $1 == -o ]]; do shift 2; done
shift
exec /bin/sh -c "$*"
'''


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='syq-benchmark-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name, content in [('syq', FAKE_SYQ), ('ssh', FAKE_SSH)]:
            path = self.bin / name
            path.write_text(content)
            path.chmod(0o755)
        self.scratch = self.root / "scratch with 'quotes' and $dollar"
        self.scratch.mkdir()
        self.sentinel = self.scratch / 'keep-me'
        self.sentinel.write_text('existing user data')
        # Do not accidentally discover a developer's installed syq during the
        # missing-install test. All other commands use the host's real tools.
        for name in ['bash', 'rsync', 'openssl', 'dd', 'split', 'cksum', 'cmp',
                     'awk', 'mktemp', 'mkdir', 'rm', 'cat', 'ps', 'sleep', 'sed',
                     'cp', 'python3', 'sh']:
            executable = shutil.which(name)
            if executable is None:
                self.fail(f'Missing test prerequisite: {name}')
            (self.bin / name).symlink_to(executable)
        self.env = dict(os.environ, PATH=str(self.bin))

    def invoke(self, *args, env=None):
        return subprocess.run(
            ['/bin/bash', str(SCRIPT), '--yes', '--source-dir', str(self.scratch),
             '--dest-dir', str(self.scratch), '--rounds', '1', '--workload', 'large', *args],
            env=env or self.env, capture_output=True, text=True, timeout=60,
        )

    def assert_clean(self):
        self.assertEqual(self.sentinel.read_text(), 'existing user data')
        self.assertEqual(list(self.scratch.iterdir()), [self.sentinel])

    def test_local_both_and_rotation(self):
        result = self.invoke('--workload', 'both', '--rounds', '3')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = [line for line in result.stdout.splitlines() if line.startswith('large: ')]
        self.assertEqual([line.split()[1].rstrip(',') for line in lines],
                         ['syq', 'rsync', 'cp', 'rsync', 'cp', 'syq', 'cp', 'syq', 'rsync'])
        self.assertIn('small cp', result.stdout)
        self.assert_clean()

    def test_push_and_pull_quoted_paths(self):
        for mode in ['push', 'pull']:
            with self.subTest(mode=mode):
                result = self.invoke('--mode', mode, '--host', 'test-host')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('large cp', result.stdout)
                self.assert_clean()

    def test_failures_do_not_report_success(self):
        for failure in ['fail', 'corrupt']:
            with self.subTest(failure=failure):
                result = self.invoke(env=dict(self.env, BENCH_TEST_FAILURE=failure))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Results (mean', result.stdout)
                self.assert_clean()

    def test_remote_failure_retains_only_owned_scratch(self):
        result = self.invoke('--mode', 'push', '--host', 'test-host',
                             env=dict(self.env, BENCH_TEST_FAILURE='fail'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Remote scratch preserved', result.stderr)
        self.assertEqual(len(list(self.scratch.glob('syq-bench.*'))), 1)
        self.assertEqual(self.sentinel.read_text(), 'existing user data')

    def test_install_is_opt_in_and_uses_official_installer(self):
        template = self.bin / 'syq-template'
        (self.bin / 'syq').rename(template)
        home = self.root / 'home'
        env = dict(self.env, HOME=str(home))
        result = self.invoke(env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(home.exists())
        self.assert_clean()
        installer = '#!/bin/sh\nset -eu\nmkdir -p "$HOME/.local/bin"\ncp ' + shlex.quote(str(template)) + ' "$HOME/.local/bin/syq"\n'
        curl = self.bin / 'curl'
        curl.write_text('#!/usr/bin/env python3\nimport pathlib, sys\n'
                        'assert "https://github.com/greaber/syq/releases/latest/download/install.sh" in sys.argv\n'
                        'pathlib.Path(sys.argv[sys.argv.index("-o")+1]).write_text(' + repr(installer) + ')\n')
        curl.chmod(0o755)
        result = self.invoke('--install', env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((home / '.local/bin/syq').is_file())
        self.assert_clean()

    def test_bad_options_before_scratch(self):
        for args in [('--mode', 'invalid'), ('--rounds', '0'), ('--size', 'huge'),
                     ('--mode', 'push', '--host', '-oProxyCommand=bad')]:
            result = self.invoke(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assert_clean()

    def test_interruption_stops_child_and_cleans(self):
        pidfile = self.root / 'child.pid'
        proc = subprocess.Popen(
            ['/bin/bash', str(SCRIPT), '--yes', '--source-dir', str(self.scratch),
             '--dest-dir', str(self.scratch), '--workload', 'large', '--rounds', '1'],
            env=dict(self.env, BENCH_TEST_FAILURE='hang', BENCH_TEST_PID=str(pidfile)),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            deadline = time.monotonic() + 15
            while not pidfile.exists() and time.monotonic() < deadline:
                if proc.poll() is not None:
                    self.fail(f'Exited before hang: {proc.stderr.read()}')
                time.sleep(0.05)
            self.assertTrue(pidfile.exists(), 'No child PID within 15 seconds')
            proc.send_signal(signal.SIGTERM)
            _, errors = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 143, errors)
            pid = int(pidfile.read_text())
            # A reparented zombie is stopped; do not mistake it for a live worker.
            state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True)
            self.assertTrue(not state.stdout.strip() or state.stdout.strip().startswith('Z'), state.stdout)
            self.assert_clean()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_piped_script_reads_answers_from_terminal(self):
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(self.scratch)
            os.execvpe('/bin/bash', ['/bin/bash', '-c', f'cat {shlex.quote(str(SCRIPT))} | /bin/bash'], dict(self.env, BENCH_TEST_ASK='1'))
        output = b''
        prompts_answered = 0
        # All five default answers are read from /dev/tty, not the script pipe.
        os.write(fd, b'\n' * 5)
        deadline = time.monotonic() + 45
        try:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.2)[0]:
                    try:
                        data = os.read(fd, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output += data
                    if output.count(b'Credentials:') > prompts_answered:
                        os.write(fd, b'test\n')
                        prompts_answered += 1
            else:
                self.fail(f'Interactive run timed out; last output: {output[-2000:]!r}')
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode())
            self.assertIn(b'Results (mean', output)
            self.assert_clean()
        finally:
            os.close(fd)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


if __name__ == '__main__':
    unittest.main()
