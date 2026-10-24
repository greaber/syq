#!/usr/bin/env python3
"""Enrollment and restricted copies with pre-8.9 clients, agent, and sshd."""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
import uuid

OLD = '/opt/openssh-8.8'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=90, **kwargs)


def remote(host, command, **kwargs):
    return run('/usr/bin/ssh', host, command, **kwargs)


def remote_python(host, program):
    return remote(host, 'python3 -c ' + shlex.quote(program), stdout=subprocess.PIPE).stdout


def wait_for(label, probe):
    deadline = time.monotonic() + 20
    progress = 0
    last = None
    while time.monotonic() < deadline:
        done, last = probe()
        if done:
            return
        if time.monotonic() >= progress:
            print(f'Waiting for {label}: {last}', flush=True)
            progress = time.monotonic() + 2
        time.sleep(.1)
    raise AssertionError(f'{label} timed out; last state: {last}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rsa-only', action='store_true')
    options = parser.parse_args()
    config = Path.home() / '.ssh/config'
    saved_config = config.read_bytes()
    root = '/tmp/syq-real-ssh/old-openssh-' + uuid.uuid4().hex
    marker = '/tmp/syq-real-ssh-legacy-client'
    agent = None
    with tempfile.TemporaryDirectory(prefix='syq-old-ssh-') as temporary:
        local = Path(temporary)
        try:
            remote('destination', f'mkdir -p {root}; ssh-keygen -q -t ed25519 -N "" -f {root}/host')
            public = remote('destination', f'cat {root}/host.pub', stdout=subprocess.PIPE).stdout.decode().strip()
            login = Path.home() / '.ssh/id_ed25519'
            if options.rsa_only:
                login = local / 'rsa-login'
                run('ssh-keygen', '-q', '-t', 'rsa', '-b', '3072', '-N', '', '-f', str(login))
                remote('destination', 'cat >> ~/.ssh/authorized_keys', input=login.with_suffix('.pub').read_bytes())
            server_config = f'''Port 22222
ListenAddress 0.0.0.0
HostKey {root}/host
PidFile {root}/server.pid
AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/lab_authorized_keys
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
UseDNS no
AllowAgentForwarding yes
StrictModes yes
LogLevel VERBOSE
'''
            if options.rsa_only:
                server_config += 'PubkeyAcceptedAlgorithms rsa-sha2-512,rsa-sha2-256\n'
            remote('destination', f'cat > {root}/sshd_config', input=server_config.encode())
            remote('destination', f'setsid {OLD}/sbin/sshd -D -e -f {root}/sshd_config '
                   f'< /dev/null > {root}/server.log 2>&1 & echo $! > {root}/process.pid')
            known_hosts = local / 'known_hosts'
            known_hosts.write_text(f'[destination]:22222 {public}\n')
            config.write_bytes(f'''Host destination-legacy
    HostName destination
    Port 22222
    User syq
    IdentityFile {login}
    IdentitiesOnly yes
    UserKnownHostsFile {known_hosts}
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    BatchMode yes
'''.encode() + saved_config)

            def server_ready():
                result = subprocess.run(['/usr/bin/ssh', '-o', 'ConnectTimeout=1', 'destination-legacy', 'true'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
                return result.returncode == 0, result.stderr.decode(errors='replace')
            wait_for('OpenSSH 8.8 server', server_ready)
            environment = dict(os.environ, PATH=f'{OLD}/bin:' + os.environ['PATH'],
                               SSH_AUTH_SOCK=str(local / 'agent.sock'))
            agent = subprocess.Popen([f'{OLD}/bin/ssh-agent', '-D', '-a', environment['SSH_AUTH_SOCK']],
                                     stdout=subprocess.DEVNULL, start_new_session=True)
            wait_for('OpenSSH 8.8 agent', lambda: (Path(environment['SSH_AUTH_SOCK']).exists(), agent.poll()))
            run(f'{OLD}/bin/ssh-add', str(Path.home() / '.ssh/id_ed25519'), env=environment)
            if options.rsa_only:
                run(f'{OLD}/bin/ssh-add', str(login), env=environment)
                # Verify the fixture really refuses the normal Ed25519 login.
                refused = subprocess.run([f'{OLD}/bin/ssh', '-F', '/dev/null', '-p', '22222',
                                          '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes',
                                          '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                          '-o', f'UserKnownHostsFile={known_hosts}',
                                          '-i', str(Path.home() / '.ssh/id_ed25519'),
                                          'syq@destination', 'true'],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
                assert refused.returncode and b'Permission denied (publickey)' in refused.stderr, refused.stderr
            remote('source', f'touch {marker}; printf old-openssh > /tmp/syq-old-openssh-source')
            version = remote('source', 'ssh -V', stderr=subprocess.PIPE).stderr
            assert b'OpenSSH_8.8' in version, version
            print('Using OpenSSH 8.8 clients, agent, and destination server', flush=True)
            copy = ['syq', 'cp', '--from', 'source', '/tmp/syq-old-openssh-source',
                    '--to', 'destination-legacy', '--no-progress']
            state = Path.home() / '.local/state/syq/enrollments'

            def legacy():
                records = [(p.parent, json.loads(p.read_bytes())) for p in state.glob('*/enrollment.json')]
                return [(d, r) for d, r in records if r['host'] == 'destination-legacy']

            # A dry run never enrolls.
            preview = subprocess.run(copy + ['--as', root + '/preview', '--dry-run'], env=environment,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            assert preview.returncode and b'a dry run does not set up restricted copying' in preview.stderr, preview.stderr
            assert not legacy()
            assert b'syq-enrollment:' not in remote('destination', 'cat ~/.ssh/authorized_keys 2>/dev/null || true',
                                                     stdout=subprocess.PIPE).stdout

            run(*copy, '--as', root + '/first', '--no-tcp', env=environment)
            [(directory, metadata)] = legacy()
            identifier = bytes(metadata['id']).hex()
            server_state = '/home/syq/.local/share/syq/enrollments/' + identifier
            entry = directory / 'entry-key'
            entry_bytes = entry.read_bytes()
            entry_public = run('ssh-keygen', '-y', '-f', str(entry), stdout=subprocess.PIPE).stdout.decode().strip()
            login_public = ' '.join(run('ssh-keygen', '-y', '-f', str(login), stdout=subprocess.PIPE)
                                    .stdout.decode().split()[:2])
            assert ' '.join(metadata['signer']['public_key'].split()[:2]) == login_public, metadata
            if options.rsa_only:
                # The entry key follows the RSA login, so the server accepts it.
                assert entry_public.startswith('ssh-rsa '), entry_public
            line = next(line for line in remote('destination', 'cat ~/.ssh/authorized_keys', stdout=subprocess.PIPE)
                        .stdout.decode().splitlines() if f'syq-enrollment:{identifier}' in line.split())
            assert line.endswith(' signer ' + login_public), line
            assert ' '.join(entry_public.split()[:2]) in line, line
            protected = remote_python('destination', f'''
import hashlib, json
from pathlib import Path
s = Path({server_state!r})
print(json.dumps({{str(p.relative_to(s)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in s.rglob('*') if p.is_file() and (p.name == 'results-key' or 'replay' in p.parts)}}))
''')
            # The entry key cannot run a shell, even through ordinary SSH.
            refused = subprocess.run([f'{OLD}/bin/ssh', '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes',
                                      '-i', str(entry), 'destination-legacy', 'echo escaped'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            assert refused.returncode and b'escaped' not in refused.stdout, refused

            # A repeated enrollment with the same login and build changes
            # nothing, and later copies keep the receiver's state.
            run('syq', 'receiver', 'enroll', 'destination-legacy', env=environment)
            [(_, again)] = legacy()
            assert again['generation'] == metadata['generation'] == 1, again
            assert entry.read_bytes() == entry_bytes
            run(*copy, '--as', root + '/second', env=environment)
            snapshots = json.loads(protected)
            remote_python('destination', f'''
import hashlib
from pathlib import Path
s = Path({server_state!r})
for name, digest in {snapshots!r}.items():
    assert hashlib.sha256((s / name).read_bytes()).hexdigest() == digest, name
''')
            for name in ('first', 'second'):
                assert remote('destination', f'cat {root}/{name}', stdout=subprocess.PIPE).stdout == b'old-openssh'

            # The coordinator trusts only the host keys this machine pinned.
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(local / 'wrong-host'))
            known_hosts.write_text('[destination]:22222 ' + (local / 'wrong-host.pub').read_text())
            refused = subprocess.run(copy + ['--as', root + '/untrusted', '--no-tcp'], env=environment,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
            assert refused.returncode and b'Host key verification failed' in refused.stderr, refused.stderr
            remote('destination', f'test ! -e {root}/untrusted')
            known_hosts.write_text(f'[destination]:22222 {public}\n')
            run('syq', 'receiver', 'revoke', identifier, env=environment)
            remote('destination', f'test ! -e {server_state}')
            assert not legacy()
            print('Enrollment with OpenSSH 8.8 passed' + (' (RSA-only)' if options.rsa_only else ''), flush=True)
        finally:
            config.write_bytes(saved_config)
            remote('source', f'rm -f {marker}')
            if agent is not None:
                if agent.poll() is None:
                    os.killpg(agent.pid, signal.SIGTERM)
                agent.wait(timeout=10)
            # The daemon and any SSH children belong to this one process group.
            remote_python('destination', f'''
import os, signal
from pathlib import Path
p = Path({root!r}) / 'process.pid'
if p.exists():
    group = int(p.read_text())
    try: os.killpg(group, signal.SIGKILL)
    except ProcessLookupError: pass
''')


if __name__ == '__main__':
    main()
