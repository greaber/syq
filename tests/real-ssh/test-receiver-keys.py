#!/usr/bin/env python3
"""Exercise receiver key protection with real OpenSSH in the disposable lab."""
import json
import os
import pty
import select
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


def enroll_interactively(arguments, environment, prompt=b'Enter passphrase for '):
    """Exercise OpenSSH's terminal passphrase or PIN prompt without askpass."""
    pid, terminal = pty.fork()
    if pid == 0:
        for variable in ('SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', 'DISPLAY'):
            environment.pop(variable, None)
        os.execvpe(arguments[0], arguments, environment)
    output = bytearray()
    answered = 0
    deadline = time.monotonic() + 45
    progress = time.monotonic() + 5
    status = None
    try:
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], .1)[0]:
                try:
                    data = os.read(terminal, 4096)
                except OSError:
                    data = b''
                output.extend(data)
                prompts = output.count(prompt)
                if prompts > answered:
                    os.write(terminal, b'fixture-unlock\n')
                    answered = prompts
            waited, observed = os.waitpid(pid, os.WNOHANG)
            if waited:
                status = observed
                break
            if time.monotonic() >= progress:
                print(f'Waiting for terminal enrollment; prompts answered: {answered}', flush=True)
                progress = time.monotonic() + 5
        assert status is not None, ('terminal enrollment timed out', output.decode(errors='replace'))
        assert answered >= 1, f'normal SSH prompt was not exercised: {prompt!r}'
        return subprocess.CompletedProcess(arguments, os.waitstatus_to_exitcode(status), b'', bytes(output))
    finally:
        if status is None:
            os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(terminal)


def main():
    config = Path.home() / '.ssh/config'
    original = config.read_bytes()
    provider = '/usr/local/lib/syq-test-sk.so'
    original_agent = os.environ['SSH_AUTH_SOCK']
    with tempfile.TemporaryDirectory(prefix='receiver-keys-') as temporary:
        root = Path(temporary)
        unavailable = root / 'unavailable'
        os.environ.update(SSH_SK_PROVIDER=provider, SYQ_TEST_SK_UNAVAILABLE=str(unavailable),
                          SSH_AUTH_SOCK=str(root / 'agent.sock'),
                          SYQ_TEST_IDENTITY_AGENT=str(root / 'agent.sock'))
        agents = []
        # This agent deliberately has no PIN prompt helper, even if the lab
        # was started from an environment that configured one.
        agent_environment = dict(os.environ)
        for variable in ('SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', 'DISPLAY'):
            agent_environment.pop(variable, None)
        agent = subprocess.Popen(['ssh-agent', '-D', '-P', provider, '-a', os.environ['SSH_AUTH_SOCK']],
                                 start_new_session=True, stdout=subprocess.DEVNULL, env=agent_environment)
        agents.append(agent)
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
                key.chmod(0o400)
                public = key.with_suffix('.pub').read_text().strip()
                options = []
                if flags is not None and not flags & 1:
                    options += ['no-touch-required']
                if flags is not None and flags & 4:
                    options += ['verify-required']
                entry = (','.join(options) + ' ' if options else '') + public
                config.write_bytes(original)
                remote('cat >> ~/.ssh/authorized_keys', input=(entry + '\n').encode())
                parent = f'/tmp/syq-real-ssh/key-protection-{index}'
                remote('mkdir -p ' + shlex.quote(parent))
                config.write_text(f'''Host destination
    User syq
    IdentitiesOnly yes
    IdentityFile {key}
    IdentityAgent $SYQ_TEST_IDENTITY_AGENT
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /home/syq/.ssh/known_hosts
    GlobalKnownHostsFile /dev/null
Host source
    User syq
    IdentitiesOnly yes
    IdentityFile /home/syq/.ssh/id_ed25519
    IdentityAgent {root / 'agent.sock'}
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /home/syq/.ssh/known_hosts
    GlobalKnownHostsFile /dev/null
''')
                arguments = ['syq', 'receiver', 'enroll', f'destination:{parent}/copy']
                # The selected per-host agent must work both without the
                # environment default and when that default points elsewhere.
                environment = dict(os.environ)
                if index % 2:
                    environment.pop('SSH_AUTH_SOCK', None)
                else:
                    environment['SSH_AUTH_SOCK'] = str(root / 'wrong-agent.sock')
                if flags is not None and flags & 4:
                    # Direct SSH can ask in the terminal; the already-running
                    # agent cannot. Reject before writing authorization/state.
                    config.write_text(config.read_text().replace('BatchMode yes', 'BatchMode no'))
                    before_auth = remote('cat ~/.ssh/authorized_keys', stdout=subprocess.PIPE).stdout
                    state = Path.home() / '.local/state/syq/restricted'
                    before_state = set(state.iterdir())
                    before_keys = run('ssh-add', '-L', stdout=subprocess.PIPE).stdout
                    rejected = enroll_interactively(arguments, environment, b'Enter PIN for ')
                    assert rejected.returncode and b'SSH agent cannot sign with the new hardware receiver key' in rejected.stderr, rejected.stderr
                    assert remote('cat ~/.ssh/authorized_keys', stdout=subprocess.PIPE).stdout == before_auth
                    assert set(state.iterdir()) == before_state, 'failed probe left enrollment state'
                    assert run('ssh-add', '-L', stdout=subprocess.PIPE).stdout == before_keys, 'failed probe left an agent identity'
                    print('PIN enrollment without agent askpass rejected before installation', flush=True)

                    # An agent started with a working PIN helper supports both
                    # enrollment and copying with the same PIN-required handle.
                    pin_socket = root / 'pin-agent.sock'
                    pin_agent = subprocess.Popen(['ssh-agent', '-D', '-P', provider, '-a', str(pin_socket)],
                                                 start_new_session=True, stdout=subprocess.DEVNULL)
                    agents.append(pin_agent)
                    deadline = time.monotonic() + 5
                    while not pin_socket.exists():
                        assert time.monotonic() < deadline and pin_agent.poll() is None, 'PIN agent failed to start'
                        time.sleep(.05)
                    os.environ['SYQ_TEST_IDENTITY_AGENT'] = str(pin_socket)
                    environment['SYQ_TEST_IDENTITY_AGENT'] = str(pin_socket)
                    run('ssh-add', '-S', provider, str(key), env=dict(os.environ, SSH_AUTH_SOCK=str(pin_socket)))
                    enrolled = subprocess.run(arguments, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                elif kind == 'ed25519' and protected:
                    config.write_text(config.read_text().replace('BatchMode yes', 'BatchMode no'))
                    enrolled = enroll_interactively(arguments, environment)
                else:
                    run('ssh-add', '-S', provider, str(key))
                    enrolled = subprocess.run(arguments, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
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
                run(*copy, env=environment)
                assert remote('cat ' + shlex.quote(parent + '/copy'), stdout=subprocess.PIPE).stdout == b'matching-key-copy\n'
                if flags is not None:
                    unavailable.touch()
                    failed = subprocess.run(copy, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                    assert failed.returncode != 0, 'copy succeeded with the test device unavailable'
                    unavailable.unlink()
                if protected:
                    selected_config = config.read_text()
                    config.write_text(selected_config.replace('IdentityAgent $SYQ_TEST_IDENTITY_AGENT', 'IdentityAgent none'))
                    disabled = subprocess.run(copy, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                    assert disabled.returncode and b'an SSH agent is required' in disabled.stderr, disabled.stderr
                    config.write_text(selected_config)
                    before = stored
                    run('syq', 'receiver', 'enroll', f'destination:{parent}/another')
                    assert (metadata_path.parent / 'enrollment-key').read_bytes() == before
                    # Losing access to the protecting key does not prevent revoke
                    # through another authorized login identity.
                    run('ssh-add', '-d', str(key.with_suffix('.pub')))
                    key.unlink()
                    config.write_bytes(original)
                run('syq', 'receiver', 'revoke', identifier)
                os.environ['SYQ_TEST_IDENTITY_AGENT'] = str(root / 'agent.sock')
            print('Receiver key protection passed', flush=True)
        finally:
            config.write_bytes(original)
            os.environ['SSH_AUTH_SOCK'] = original_agent
            for agent in agents:
                os.killpg(agent.pid, signal.SIGKILL)
                agent.wait(timeout=10)


if __name__ == '__main__':
    main()
