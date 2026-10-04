#!/usr/bin/env python3
"""Exercise receiver key protection with real OpenSSH in the disposable lab."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=90, **kwargs)


def remote(command, **kwargs):
    return run('ssh', 'destination', command, **kwargs)


def main():
    config = Path.home() / '.ssh/config'
    original = config.read_bytes()
    provider = '/usr/local/lib/syq-test-sk.so'
    original_agent = os.environ['SSH_AUTH_SOCK']
    with tempfile.TemporaryDirectory(prefix='receiver-keys-') as temporary:
        root = Path(temporary)
        unavailable = root / 'unavailable'
        os.environ.update(SSH_SK_PROVIDER=provider, SYQ_TEST_SK_UNAVAILABLE=str(unavailable),
                          SSH_AUTH_SOCK=str(root / 'agent.sock'))
        agent = subprocess.Popen(['ssh-agent', '-D', '-P', provider, '-a', os.environ['SSH_AUTH_SOCK']],
                                 start_new_session=True, stdout=subprocess.DEVNULL)
        askpass = root / 'askpass'
        askpass.write_text("#!/bin/sh\nprintf '%s\\n' fixture-unlock\n")
        askpass.chmod(0o700)
        os.environ.update(SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY='fixture')
        try:
            deadline = time.monotonic() + 5
            while not Path(os.environ['SSH_AUTH_SOCK']).exists():
                assert time.monotonic() < deadline and agent.poll() is None, 'test agent failed to start'
                time.sleep(.05)
            run('ssh-add', str(Path.home() / '.ssh/id_ed25519'))
            run('ssh', 'source', "printf 'matching-key-copy\\n' >/tmp/syq-real-ssh-key-source")
            for index, (kind, bits, protected, flags) in enumerate([
                ('ed25519', None, False, None), ('ed25519', None, True, None),
                ('rsa', 2048, True, None), ('rsa', 4096, False, None),
                ('ecdsa', 256, True, None), ('ed25519-sk', None, False, 0),
                ('ed25519-sk', None, False, 1), ('ecdsa-sk', None, False, 0),
                ('ed25519-sk', None, False, 5),
            ]):
                print(f'Checking {kind}, bits={bits}, encrypted={protected}, flags={flags}', flush=True)
                key = root / f'login-{index}'
                args = ['ssh-keygen', '-q', '-t', kind, '-C', 'syq-test-login', '-f', str(key),
                        '-N', 'fixture-unlock' if protected else '']
                if bits:
                    args += ['-b', str(bits)]
                if flags is not None:
                    args += ['-w', provider]
                    if not flags & 1:
                        args += ['-O', 'no-touch-required']
                    if flags & 4:
                        args += ['-O', 'verify-required']
                run(*args)
                public = key.with_suffix('.pub').read_text().strip()
                options = []
                if flags is not None and not flags & 1:
                    options += ['no-touch-required']
                if flags is not None and flags & 4:
                    options += ['verify-required']
                entry = (','.join(options) + ' ' if options else '') + public
                config.write_bytes(original)
                remote('cat >> ~/.ssh/authorized_keys', input=(entry + '\n').encode())
                config.write_text(f'''Host destination
    User syq
    IdentitiesOnly yes
    IdentityFile {key}
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /home/syq/.ssh/known_hosts
    GlobalKnownHostsFile /dev/null
Host source
    User syq
    IdentitiesOnly yes
    IdentityFile /home/syq/.ssh/id_ed25519
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /home/syq/.ssh/known_hosts
    GlobalKnownHostsFile /dev/null
''')
                run('ssh-add', str(key))
                parent = f'/tmp/syq-real-ssh/key-protection-{index}'
                remote('mkdir -p ' + shlex.quote(parent))
                enrolled = subprocess.run(['syq', 'receiver', 'enroll', f'destination:{parent}/copy'],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                if kind == 'ecdsa' and protected:
                    assert enrolled.returncode and b'ECDSA is unsupported' in enrolled.stderr, enrolled.stderr
                    continue
                assert enrolled.returncode == 0, enrolled.stderr.decode(errors='replace')
                records = [(p, json.loads(p.read_bytes())) for p in
                           (Path.home() / '.local/state/syq/restricted').glob('*/metadata.json')]
                metadata_path, metadata = next((p, r) for p, r in records if r['requested_parent'] == parent)
                identifier = bytes(metadata['id']).hex()
                stored = (metadata_path.parent / 'enrollment-key').read_bytes()
                assert stored.startswith(b'SYQ-RECEIVER-KEY-1\n') == protected
                assert metadata.get('security_key_flags') == flags
                auth = remote('cat ~/.ssh/authorized_keys', stdout=subprocess.PIPE).stdout.decode()
                installed = next(line for line in auth.splitlines() if f'syq-enrollment:{identifier}' in line)
                if flags is not None:
                    assert ('no-touch-required' in installed) == (not flags & 1), installed
                    assert ('verify-required' in installed) == bool(flags & 4), installed
                elif kind == 'rsa':
                    if protected:
                        encoded = json.loads(stored.split(b'\n', 1)[1])['header']['public_key']
                    else:
                        encoded = run('ssh-keygen', '-y', '-f', str(metadata_path.parent / 'enrollment-key'),
                                      stdout=subprocess.PIPE).stdout.decode()
                    size = int(run('ssh-keygen', '-lf', '-', input=encoded.encode(), stdout=subprocess.PIPE).stdout.split()[0])
                    assert size == max(3072, bits), size
                copy = ['syq', 'cp', '--from', 'source', '/tmp/syq-real-ssh-key-source',
                        '--to', 'destination', '--as', parent + '/copy', '--no-tcp', '--no-progress']
                run(*copy)
                assert remote('cat ' + shlex.quote(parent + '/copy'), stdout=subprocess.PIPE).stdout == b'matching-key-copy\n'
                if flags is not None:
                    unavailable.touch()
                    failed = subprocess.run(copy, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                    assert failed.returncode != 0, 'copy succeeded with the test device unavailable'
                    unavailable.unlink()
                if protected:
                    before = stored
                    run('syq', 'receiver', 'enroll', f'destination:{parent}/another')
                    assert (metadata_path.parent / 'enrollment-key').read_bytes() == before
                    # Losing access to the protecting key does not prevent revoke
                    # through another authorized login identity.
                    run('ssh-add', '-d', str(key.with_suffix('.pub')))
                    key.unlink()
                    config.write_bytes(original)
                run('syq', 'receiver', 'revoke', identifier)
            print('Receiver key protection passed', flush=True)
        finally:
            config.write_bytes(original)
            os.environ['SSH_AUTH_SOCK'] = original_agent
            os.killpg(agent.pid, signal.SIGKILL)
            agent.wait(timeout=10)


if __name__ == '__main__':
    main()
