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
if args in (['--version'], ['--build-identity']):
    print('syq test double'); sys.exit(0)
src=pathlib.Path(args[args.index('--srcs-in')+1])
dst=pathlib.Path(args[args.index('--into-existing')+1])
if src.name == 'probe' and os.environ.get('BENCH_TEST_ASK'):
    print('Credentials:', flush=True)
    with open('/dev/tty') as terminal:
        if terminal.readline().strip() != 'test': sys.exit(4)
if not dst.is_dir(): sys.exit(24)
mode=os.environ.get('BENCH_TEST_FAILURE', '') if src.name != 'probe' else ''
if mode == 'fail': sys.exit(23)
if mode == 'hang':
    child=subprocess.Popen(['sleep','300'])
    pathlib.Path(os.environ['BENCH_TEST_PID']).write_text(str(child.pid))
    child.wait(); sys.exit(1)
shutil.copytree(src,dst,dirs_exist_ok=True)
if '--quiet' not in args: print('test double: copy statistics')
if mode == 'corrupt':
    next(dst.iterdir()).write_bytes(b'bad')
'''
FAKE_SSH = '''#!/usr/bin/env bash
set -eu
while [[ $1 == -o ]]; do shift 2; done
shift
if [[ ${BENCH_TEST_CLEANUP_FAIL:-} == 1 && $* == *cleanup_dir=* ]]; then exit 255; fi
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
                     'cp', 'mv', 'python3', 'sh', 'perl']:
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
        self.assertIn('syq: syq test double', result.stdout)
        self.assertEqual(result.stdout.count('Command:'), 18)
        self.assertIn('Command: syq cp --preserve=permissions', result.stdout)
        # Each reported mean must agree with the untimed per-trial records;
        # range columns show the variability hidden by a mean alone.
        import re
        trials = {}
        current = None
        for line in result.stdout.splitlines():
            match = re.match(r'(large|small): (syq|rsync|cp), trial', line)
            if match:
                current = tuple(match.groups())
            match = re.match(r'Verified contents; elapsed ([0-9.]+) seconds', line)
            if match:
                trials.setdefault(current, []).append(float(match[1]))
        summaries = 0
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) == 6 and tuple(fields[:2]) in trials:
                summaries += 1
                values = trials[tuple(fields[:2])]
                self.assertAlmostEqual(float(fields[2]), sum(values)/len(values), delta=0.00051)
                self.assertEqual(float(fields[3]), min(values))
                self.assertEqual(float(fields[4]), max(values))
                self.assertEqual(int(fields[5]), len(values))
        self.assertEqual(summaries, 6)

        self.assertEqual(result.stdout.count('Preparing syq with a 14-byte setup copy'), 1)
        self.assertEqual(result.stdout.count('test double: copy statistics'), 6)
        self.assertIn('Setup complete.', result.stdout)
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

    def test_remote_failure_cleans_owned_scratch(self):
        result = self.invoke('--mode', 'push', '--host', 'test-host',
                             env=dict(self.env, BENCH_TEST_FAILURE='fail'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Cleaning up remote benchmark files', result.stdout)
        self.assert_clean()

    def test_unreachable_cleanup_reports_leftovers(self):
        result = self.invoke('--mode', 'push', '--host', 'test-host',
                             env=dict(self.env, BENCH_TEST_CLEANUP_FAIL='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Could not finish remote cleanup:', result.stderr)
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
        self.check_interruption('local')

    def test_remote_interruption_stops_child_and_cleans(self):
        self.check_interruption('push')
        self.check_interruption('pull')

    def check_interruption(self, mode):
        pidfile = self.root / f'child-{mode}.pid'
        proc = subprocess.Popen(
            ['/bin/bash', str(SCRIPT), '--yes', '--source-dir', str(self.scratch),
             '--dest-dir', str(self.scratch), '--workload', 'large', '--rounds', '1',
             '--mode', mode, '--host', 'test-host'],
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

    def test_keyboard_ctrl_c_cleans_remote_scratch(self):
        self.check_terminal_interruption(keyboard=True)

    def test_terminal_sigterm_cleans_remote_scratch(self):
        self.check_terminal_interruption(keyboard=False)

    def check_terminal_interruption(self, *, keyboard):
        pidfile = self.root / 'ctrl-c-child.pid'
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe('/bin/bash', ['/bin/bash', str(SCRIPT), '--yes', '--mode', 'push',
                       '--host', 'test-host', '--workload', 'large', '--rounds', '1',
                       '--source-dir', str(self.scratch), '--dest-dir', str(self.scratch)],
                       dict(self.env, BENCH_TEST_FAILURE='hang', BENCH_TEST_PID=str(pidfile)))
        output = b''
        interrupted = False
        deadline = time.monotonic() + 20
        try:
            while time.monotonic() < deadline:
                if pidfile.exists() and not interrupted:
                    if keyboard:
                        os.write(fd, b'\x03')
                    else:
                        os.kill(pid, signal.SIGTERM)
                    interrupted = True
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        data = os.read(fd, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output += data
            else:
                self.fail(f'Terminal cancellation timed out; last output: {output[-2000:]!r}')
            _, status = os.waitpid(pid, 0)
            self.assertTrue(interrupted)
            self.assertEqual(os.waitstatus_to_exitcode(status), 130 if keyboard else 143, output.decode())
            child = int(pidfile.read_text())
            state = subprocess.run(['ps', '-o', 'stat=', '-p', str(child)], capture_output=True, text=True)
            self.assertTrue(not state.stdout.strip() or state.stdout.strip().startswith('Z'), state.stdout)
            self.assertIn(b'Cleaning up remote benchmark files', output)
            self.assert_clean()
        finally:
            os.close(fd)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
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
        deadline = time.monotonic() + 90
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
