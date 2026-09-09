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
import json, os, pathlib, shutil, subprocess, sys, time
args=sys.argv[1:]
if args in (['--version'], ['--build-identity']):
    print('syq test double'); sys.exit(0)
config=pathlib.Path(os.environ['XDG_CONFIG_HOME'])/'syq'/'persistence.json'
if args == ['persist', 'off']:
    if os.environ.get('BENCH_TEST_PERSIST_FAIL'): sys.exit(25)
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('{"enabled": false}')
    print('SSH connection persistence is off'); sys.exit(0)
assert json.loads(config.read_text()) == {'enabled': False}
assert '--pscope' not in args
if os.environ.get('BENCH_TEST_ENV_LOG'):
    with open(os.environ['BENCH_TEST_ENV_LOG'], 'a') as log:
        log.write(json.dumps({'config': str(config), 'runtime': os.environ['XDG_RUNTIME_DIR']})+'\n')
src=pathlib.Path(args[args.index('--srcs-in')+1])
dst=pathlib.Path(args[args.index('--into-existing')+1])
if src.name == 'probe' and os.environ.get('BENCH_TEST_ASK'):
    print('Credentials:', flush=True)
    with open('/dev/tty') as terminal:
        if terminal.readline().strip() != 'test': sys.exit(4)
if not dst.is_dir(): sys.exit(24)
if src.name == 'probe' and os.environ.get('BENCH_TEST_SETUP_FAIL'):
    print('helper installation failed', file=sys.stderr); sys.exit(23)
mode=os.environ.get('BENCH_TEST_FAILURE', '') if src.name != 'probe' else ''
if mode == 'fail': sys.exit(23)
if mode == 'hang':
    child=subprocess.Popen(['sleep','300'])
    pathlib.Path(os.environ['BENCH_TEST_PID']).write_text(str(child.pid))
    child.wait(); sys.exit(1)
shutil.copytree(src,dst,dirs_exist_ok=True)
if '--results' in args:
    result={'type': 'result', 'status': 'success'}
    if not os.environ.get('BENCH_TEST_OLD'):
        result['copying_elapsed_ms']=2500 if os.environ.get('BENCH_TEST_GROW') and len(list(src.iterdir())) == 1024 else 5000
    pathlib.Path(args[args.index('--results')+1]).write_text(json.dumps(result)+'\n')
if '--quiet' not in args and src.name == 'probe':
    print('test double: preparing matching remote helper', flush=True)
if '--quiet' not in args and '--suppress-summary' not in args:
    print('test double: copy statistics')
if mode == 'corrupt':
    next(dst.iterdir()).write_bytes(b'bad')
'''
FAKE_SSH = '''#!/usr/bin/env bash
set -eu
if [[ ${BENCH_TEST_SSH_LOG:-} != '' ]]; then
    { printf '%q ' "$@"; printf '\n'; } >> "$BENCH_TEST_SSH_LOG"
fi
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
                     'cp', 'mv', 'python3', 'sh', 'perl', 'df']:
            executable = shutil.which(name)
            if executable is None:
                self.fail(f'Missing test prerequisite: {name}')
            (self.bin / name).symlink_to(executable)
        self.env = dict(os.environ, PATH=str(self.bin),
                        SYQ_BENCHMARK_TEST_SMALL_FIXTURES='1')

    def invoke(self, *args, env=None):
        return subprocess.run(
            ['/bin/bash', str(SCRIPT), '--yes', '--mode', 'local', '--source-dir', str(self.scratch),
             '--dest-dir', str(self.scratch), '--rounds', '1', '--workload', 'large', '--size', 'quick', *args],
            env=env or self.env, capture_output=True, text=True, timeout=60,
        )

    def assert_clean(self):
        self.assertEqual(self.sentinel.read_text(), 'existing user data')
        self.assertEqual(list(self.scratch.iterdir()), [self.sentinel])

    def test_default_noninteractive_requires_host_before_creating_scratch(self):
        result = subprocess.run(
            ['/bin/bash', str(SCRIPT), '--yes', '--source-dir', str(self.scratch)],
            env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Pass --host USER@HOST', result.stderr)
        self.assert_clean()

    def test_generation_and_checks_keep_launch_directory(self):
        log = self.root / 'working-directories'
        for name in ['cksum', 'split']:
            executable = shutil.which(name)
            path = self.bin / name
            path.unlink()
            path.write_text('#!/bin/bash\npwd -P >> ' + shlex.quote(str(log)) +
                            '\nexec ' + shlex.quote(executable) + ' "$@"\n')
            path.chmod(0o755)
        result = self.invoke('--workload', 'small')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(log.read_text().splitlines())
        self.assertEqual(set(log.read_text().splitlines()), {str(Path.cwd().resolve())})
        self.assert_clean()

    def test_checksum_command_failure_is_not_hidden_by_path_normalization(self):
        executable = shutil.which('cksum')
        path = self.bin / 'cksum'
        path.unlink()
        path.write_text('#!/bin/bash\nif [[ $* == */trial/* ]]; then exit 23; fi\nexec ' +
                        shlex.quote(executable) + ' "$@"\n')
        path.chmod(0o755)
        for mode in ['local', 'push']:
            with self.subTest(mode=mode):
                result = self.invoke('--mode', mode, '--host', 'test-host')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Results (', result.stdout)
                self.assert_clean()

    def test_local_summary_reports_seconds_even_for_a_fast_clone(self):
        records = self.root / 'results'
        records.write_text('large cp 0.002 6710886400\nlarge cp 0.004 6710886400\n')
        definitions = SCRIPT.read_text().removesuffix('main "$@"\n')
        result = subprocess.run(['/bin/bash', '-c', definitions +
                                 '\nsummarize_results "$1" seconds', 'summary-test', str(records)],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['large', 'cp', '0.003', '0.002', '0.004', '2'],
                      [line.split() for line in result.stdout.splitlines()])

    def test_auto_sizes_with_syq_for_each_direction(self):
        for mode in ['local', 'push', 'pull']:
            with self.subTest(mode=mode):
                result = self.invoke('--mode', mode, '--host', 'test-host',
                                     '--workload', 'small', '--size', 'auto',
                                     env=dict(self.env, BENCH_TEST_GROW='1',
                                              SYQ_BENCHMARK_TEST_SMALL_FIXTURES='0'))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Generating 2048 files', result.stdout)
                self.assertEqual(result.stdout.count('Verified sizing copy'), 2)
                self.assertIn('small: 16777216 bytes per trial', result.stdout)
                self.assertEqual(result.stdout.count('trial 1/1'), 3 if mode == 'local' else 2)
                self.assert_clean()

    def test_auto_rejects_missing_timing_with_fixed_size_recovery(self):
        result = self.invoke('--size', 'auto', '--workload', 'small',
                             env=dict(self.env, BENCH_TEST_OLD='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--size quick', result.stderr)
        self.assertNotIn('Results (', result.stdout)
        self.assert_clean()

    def test_auto_stops_at_available_space(self):
        (self.bin / 'df').unlink()
        (self.bin / 'df').write_text('#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted"\necho "test 36409 0 36409 0% /"\n')
        (self.bin / 'df').chmod(0o755)
        result = self.invoke('--size', 'auto', '--workload', 'small',
                             env=dict(self.env, BENCH_TEST_GROW='1',
                                              SYQ_BENCHMARK_TEST_SMALL_FIXTURES='0'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('WARNING: available scratch space', result.stderr)
        self.assertEqual(result.stdout.count('Verified sizing copy'), 1)
        self.assert_clean()

    def test_sizing_math_caps_growth_and_handles_timer_resolution(self):
        definitions = SCRIPT.read_text().removesuffix('main "$@"\n')
        for current, ms, capacity, expected in [(64, 0, 10000, 640),
                (64, 2500, 10000, 128), (64, 2500, 100, 100),
                (64, 4999, 10000, 80), (64, 1, 32, 32)]:
            result = subprocess.run(['/bin/bash', '-c', definitions +
                                     '\nnext_amount "$1" "$2" "$3"', 'sizing-test',
                                     str(current), str(ms), str(capacity)],
                                    env=self.env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(int(result.stdout), expected)

    def test_auto_corruption_is_not_used_for_sizing(self):
        result = self.invoke('--size', 'auto', '--workload', 'small',
                             env=dict(self.env, BENCH_TEST_FAILURE='corrupt'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Sizing copy content check failed', result.stderr)
        self.assertNotIn('Increasing', result.stdout)
        self.assert_clean()

    def test_speed_summary_uses_decimal_bytes_and_mean_trial_speeds(self):
        records = self.root / 'results'
        records.write_text('large syq 1.000 1000000\nlarge syq 2.000 1000000\n'
                           'small cp 0.000 1000000\nsmall cp 1.000 1000000\n')
        # Load the real functions without starting the interactive main.
        definitions = SCRIPT.read_text().removesuffix('main "$@"\n')
        result = subprocess.run(['/bin/bash', '-c', definitions + '\nsummarize_results "$1"',
                                 'summary-test', str(records)],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split() for line in result.stdout.splitlines()]
        self.assertIn(['large', 'syq', '0.750', '0.500', '1.000', '2'], rows)
        self.assertIn(['small', 'cp', 'n/a', 'n/a', 'n/a', '2'], rows)
        self.assertIn('below timer resolution', result.stdout)

    def test_local_both_and_rotation(self):
        result = self.invoke('--workload', 'both', '--rounds', '3')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = [line for line in result.stdout.splitlines() if line.startswith('large: ') and ', trial ' in line]
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
                self.assertAlmostEqual(float(fields[2]), sum(values)/len(values), delta=0.00101)
                self.assertEqual(float(fields[3]), min(values))
                self.assertEqual(float(fields[4]), max(values))
                self.assertEqual(int(fields[5]), len(values))
        self.assertEqual(summaries, 6)

        self.assertEqual(result.stdout.count('Preparing the benchmark'), 1)
        self.assertEqual(result.stdout.count('test double: copy statistics'), 6)
        self.assertIn('Setup complete.', result.stdout)
        self.assertIn('test double: preparing matching remote helper', result.stdout)
        for detail in ['14-byte', 'tiny setup copy', 'Caches are NOT flushed', 'twice the selected', 'permissions preserved']:
            self.assertNotIn(detail, result.stdout)
        self.assert_clean()

    def test_push_and_pull_quoted_paths(self):
        for mode in ['push', 'pull']:
            with self.subTest(mode=mode):
                result = self.invoke('--mode', mode, '--host', 'test-host')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('large cp', result.stdout)
                self.assertIn('Preparing syq syq test double on test-host', result.stdout)
                self.assertIn('test double: preparing matching remote helper', result.stdout)
                self.assertIn('Setup complete: syq syq test double is ready on test-host', result.stdout)
                self.assert_clean()

    def test_persistence_off_ignores_and_preserves_user_policy_and_runtime(self):
        import json
        config = self.root / 'user-config' / 'syq' / 'persistence.json'
        config.parent.mkdir(parents=True)
        config.write_text('{"enabled": true}')
        runtime = self.root / 'user-runtime'
        runtime.mkdir()
        live = runtime / 'existing-connection'
        live.write_text('user-owned connection')
        env_log = self.root / 'copy-env.jsonl'
        ssh_log = self.root / 'ssh.log'
        env = dict(self.env, XDG_CONFIG_HOME=str(config.parent.parent),
                   XDG_RUNTIME_DIR=str(runtime), BENCH_TEST_ENV_LOG=str(env_log),
                   BENCH_TEST_SSH_LOG=str(ssh_log))
        for mode in ['push', 'pull']:
            with self.subTest(mode=mode):
                result = self.invoke('--mode', mode, '--host', 'test-host', env=env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('syq persistence OFF; rsync fresh SSH', result.stdout)
                self.assertEqual(json.loads(config.read_text()), {'enabled': True})
                self.assertEqual(live.read_text(), 'user-owned connection')
                for line in env_log.read_text().splitlines():
                    copy_env = json.loads(line)
                    self.assertNotEqual(Path(copy_env['config']), config)
                    self.assertNotEqual(Path(copy_env['runtime']), runtime)
                    self.assertFalse(Path(copy_env['config']).exists())
                    self.assertFalse(Path(copy_env['runtime']).exists())
                for line in ssh_log.read_text().splitlines():
                    self.assertIn('-o ControlMaster=no -o ControlPath=none -o ControlPersist=no', line)
                self.assert_clean()

    def test_persistence_configuration_failure_stops_before_copy(self):
        result = self.invoke(env=dict(self.env, BENCH_TEST_PERSIST_FAIL='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Could not disable syq persistence', result.stderr)
        self.assertNotIn('Preparing syq', result.stdout)
        self.assertNotIn('Results (MB/s', result.stdout)
        self.assert_clean()

    def test_setup_errors_stay_visible_and_stop_trials(self):
        result = self.invoke('--mode', 'push', '--host', 'test-host',
                             env=dict(self.env, BENCH_TEST_SETUP_FAIL='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('helper installation failed', result.stderr)
        self.assertNotIn('Setup complete', result.stdout)
        self.assertNotIn('trial 1/', result.stdout)
        self.assert_clean()

    def test_failures_do_not_report_success(self):
        for failure in ['fail', 'corrupt']:
            with self.subTest(failure=failure):
                result = self.invoke(env=dict(self.env, BENCH_TEST_FAILURE=failure))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Results (MB/s', result.stdout)
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
        # Accept push and small, supply a host and remote scratch parent.
        os.write(fd, b'\ntest-host\n\n\n' + str(self.scratch).encode() + b'\n')
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
            self.assertIn(b'Results (MB/s', output)
            self.assertIn(b'Mode: push; workloads: small; size: quick', output)
            self.assertNotIn(b'Generating one ', output)
            self.assert_clean()
        finally:
            os.close(fd)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


if __name__ == '__main__':
    unittest.main()
