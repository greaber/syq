#!/usr/bin/env python3
"""Manually dispatched experiment, not a CI policy. All writes stay in this checkout."""
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

root = pathlib.Path.cwd().resolve()
assert pathlib.Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()).resolve() == root
level = int(sys.argv[1])
assert level in range(4)
out = root / 'target/profile-results'
out.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env['CARGO_TARGET_DIR'] = str(root / 'target/profile-build')
cargo = ['cargo', '--config', f'profile.dev.opt-level={level}']
# Test inherits dev; retain the existing BLAKE3 level-3 exception throughout.
summary = {'level': level, 'sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
           'platform': os.uname().sysname, 'arch': os.uname().machine, 'cpus': os.cpu_count(),
           'commands': [], 'operations': {}, 'failures': []}

def save():
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')

def run(label, args, timeout=1800, extra_env=None, required=True):
    print('START', label, flush=True)
    start = time.monotonic()
    process = subprocess.Popen(args, env=extra_env or env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, start_new_session=True)
    expired = threading.Event()
    def kill():
        expired.set()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    timer = threading.Timer(timeout, kill)
    timer.start()
    lines = []
    try:
        with (out / (label + '.log')).open('w') as log:
            for line in process.stdout:
                log.write(line)
                log.flush()
                lines.append(line)
                # Cargo's machine-readable artifacts are saved, but not sprayed into CI logs.
                if not line.startswith('{'):
                    print(line, end='', flush=True)
        code = process.wait()
    finally:
        timer.cancel()
    row = {'label': label, 'seconds': time.monotonic() - start, 'exit_code': code,
           'timeout': expired.is_set()}
    text = ''.join(lines)
    row['test_results'] = re.findall(r'test result: .*', text)
    summary['commands'].append(row)
    if code or expired.is_set():
        summary['failures'].append(label)
    save()
    print('MEASUREMENT ' + json.dumps(row), flush=True)
    if required and (code or expired.is_set()):
        raise RuntimeError(f'{label} failed, see {out}')
    return text

run('toolchain', ['rustc', '-Vv'])
run('fetch', ['cargo', 'fetch', '--locked'])  # Network downloads excluded from compilation timing.
artifacts = {}
for trial in range(2):
    builddir = pathlib.Path(env['CARGO_TARGET_DIR'])
    assert builddir == root / 'target/profile-build'
    if builddir.exists():
        shutil.rmtree(builddir)
    output = run(f'fresh_test_build_{trial}', cargo + ['test', '--locked', '--all-targets', '--no-run', '--message-format=json'])
    artifacts = {}
    for line in output.splitlines():
        if not line.startswith('{'):
            continue
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact' and item.get('executable') and item['profile']['test']:
            artifacts[item['target']['name']] = item['executable']
    assert 'syq' in artifacts and 'local' in artifacts, artifacts
    # Invoke precisely the compiled test executables, preserving libtest's default
    # parallelism, so suite timing excludes Cargo/build-script work.
    for name, executable in sorted(artifacts.items()):
        if name == 'profile-probe':
            continue
        run(f'suite_{name}_{trial}', [executable], required=False)
    if trial == 0:
        continue

local_tests = [
    'hash_policy_independent_compare_and_payload_hashes_cross_transports',
    'hash_policy_independent_hashes_reuse_unchanged_blocks',
    'large_file_parallel_chunks',
    'resume_from_partial',
    'concurrent_identical_and_different_copies_publish_complete_files',
    'concurrent_default_tree_copies_keep_every_file_whole',
    'source_read_ahead_runs_for_tcp_and_ssh_ranges_and_streams',
]
listing = run('local_test_inventory', [artifacts['local'], '--list'])
for name in local_tests:
    assert name + ': test' in listing, name
    for trial in range(3):
        output = run(f'test_{name}_{trial}', [artifacts['local'], name, '--exact'], required=False)
        assert 'running 1 test' in output and '0 ignored' in output, name

bindir = pathlib.Path(env['CARGO_TARGET_DIR']) / 'debug'
run('build_probe', cargo + ['build', '--locked', '--bin', 'profile-probe'])
output = run('primitives', [str(bindir / 'profile-probe')])
for line in output.splitlines():
    if line.startswith('PROBE '):
        row = json.loads(line[6:])
        summary['operations'][row['name']] = row['seconds']
save()
with tempfile.TemporaryDirectory(prefix='syq-profile-study-') as tmp:
    tmp = pathlib.Path(tmp).resolve()
    source = tmp / 'source'
    source.write_bytes(bytes(range(256)) * 65536)
    isolated = env | {'HOME': str(tmp/'home'), 'XDG_CACHE_HOME': str(tmp/'cache'), 'XDG_CONFIG_HOME': str(tmp/'config')}
    for label, options in [('pipes', ['--no-tcp']), ('tcp_encrypted', []), ('tcp_plain', ['--tcp-plain'])]:
        for trial in range(3):
            destination = tmp / f'{label}-{trial}'
            run(f'copy_{label}_{trial}', [str(bindir/'syq'), 'cp', '--no-progress', '--no-compress', '--tcp-ports', '0-0',
                '--performance-tuning', 'workers=2,copy-path=ranges', *options, str(source), '--as', str(destination)], extra_env=isolated)
            assert destination.read_bytes() == source.read_bytes()
for trial in range(3):
    run(f'unchanged_build_{trial}', cargo + ['build', '--locked', '--bin', 'syq'])
path = root / 'src/main.rs'
original = path.read_bytes()
try:
    for trial in range(2):
        path.write_bytes(original + f'\n// Profile experiment rebuild {trial}.\n'.encode())
        run(f'source_edit_build_{trial}', cargo + ['build', '--locked', '--bin', 'syq'])
finally:
    path.write_bytes(original)
summary['binary_bytes'] = (bindir / 'syq').stat().st_size
save()
print('SUMMARY ' + json.dumps(summary), flush=True)
sys.exit(bool(summary['failures']))
