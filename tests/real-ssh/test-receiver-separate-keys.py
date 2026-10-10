#!/usr/bin/env python3
"""Separate admission/signing keys with pre-8.9 clients, agent, and sshd."""
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
    config = Path.home() / '.ssh/config'
    saved_config = config.read_bytes()
    root = '/tmp/syq-real-ssh/separate-keys-' + uuid.uuid4().hex
    marker = '/tmp/syq-real-ssh-legacy-client'
    agent = None
    with tempfile.TemporaryDirectory(prefix='syq-old-ssh-') as temporary:
        local = Path(temporary)
        try:
            remote('destination', f'mkdir -p {root}; ssh-keygen -q -t ed25519 -N "" -f {root}/host')
            public = remote('destination', f'cat {root}/host.pub', stdout=subprocess.PIPE).stdout.decode().strip()
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
            remote('destination', f'cat > {root}/sshd_config', input=server_config.encode())
            remote('destination', f'setsid {OLD}/sbin/sshd -D -e -f {root}/sshd_config '
                   f'< /dev/null > {root}/server.log 2>&1 & echo $! > {root}/process.pid')
            known_hosts = local / 'known_hosts'
            known_hosts.write_text(f'[destination]:22222 {public}\n')
            config.write_bytes(f'''Host destination-legacy
    HostName destination
    Port 22222
    User syq
    IdentityFile /home/syq/.ssh/id_ed25519
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
            remote('source', f'touch {marker}; printf separate-keys > /tmp/syq-separate-key-source')
            version = remote('source', 'ssh -V', stderr=subprocess.PIPE).stderr
            assert b'OpenSSH_8.8' in version, version
            print('Using OpenSSH 8.8 clients, agent, and destination server', flush=True)
            copy = ['syq', 'cp', '--from', 'source', '/tmp/syq-separate-key-source',
                    '--to', 'destination-legacy', '--no-progress']
            run(*copy, '--as', root + '/first', '--no-tcp', env=environment)
            records = [(p, json.loads(p.read_bytes())) for p in
                       (Path.home() / '.local/state/syq/restricted').glob('*/metadata.json')]
            metadata_path, metadata = next((p, r) for p, r in records if r['requested_parent'] == root)
            identifier = bytes(metadata['id']).hex()
            state = '/home/syq/.local/share/syq/restricted/' + identifier
            signer = metadata_path.parent / 'enrollment-key'
            signer_bytes = signer.read_bytes()
            signer_public = run('ssh-keygen', '-y', '-f', str(signer), stdout=subprocess.PIPE).stdout.decode().strip()
            signer_public = ' '.join(signer_public.split()[:2])
            ssh_key = metadata_path.parent / 'ssh-key'
            ssh_public = run('ssh-keygen', '-y', '-f', str(ssh_key), stdout=subprocess.PIPE).stdout.decode().strip()
            ssh_public = ' '.join(ssh_public.split()[:2])
            assert signer_public != ssh_public
            protected = remote_python('destination', f'''
import hashlib, json
from pathlib import Path
s = Path({state!r})
print(json.dumps({{str(p.relative_to(s)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in s.rglob('*') if p.is_file() and (p.name in ('allowed-signers', 'receipt-key') or 'replay' in p.parts)}}))
''')
            # The admission key cannot run a shell, even through ordinary SSH.
            refused = subprocess.run([f'{OLD}/bin/ssh', '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes',
                                      '-i', str(ssh_key), 'destination-legacy', 'echo escaped'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            assert refused.returncode and b'escaped' not in refused.stdout, refused

            # Restore the exact old single-key arrangement and generation. The
            # protected key and all recorded grants remain unchanged.
            remote_python('destination', f'''
import json
from pathlib import Path
s = Path({state!r})
p = s / 'config.json'
c = json.loads(p.read_bytes()); c['version'] = 5; p.write_text(json.dumps(c))
p = Path.home() / '.ssh/authorized_keys'
p.write_text(p.read_text().replace({ssh_public!r}, {signer_public!r}))
''')
            metadata['version'] = 5
            metadata_path.write_text(json.dumps(metadata))
            ssh_key.unlink()
            run(*copy, '--as', root + '/migrated', env=environment)
            updated = json.loads(metadata_path.read_bytes())
            assert updated['version'] == 6 and updated['id'] == metadata['id']
            assert updated['receipt_public_key'] == metadata['receipt_public_key']
            assert signer.read_bytes() == signer_bytes
            snapshots = json.loads(protected)
            remote_python('destination', f'''
import hashlib
from pathlib import Path
s = Path({state!r})
for name, digest in {snapshots!r}.items():
    assert hashlib.sha256((s / name).read_bytes()).hexdigest() == digest, name
''')
            for name in ('first', 'migrated'):
                assert remote('destination', f'cat {root}/{name}', stdout=subprocess.PIPE).stdout == b'separate-keys'
            before_retry = ssh_key.read_bytes()
            run('syq', 'receiver', 'enroll', f'destination-legacy:{root}/another', env=environment)
            assert ssh_key.read_bytes() == before_retry and signer.read_bytes() == signer_bytes

            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(local / 'wrong-host'))
            known_hosts.write_text('[destination]:22222 ' + (local / 'wrong-host.pub').read_text())
            refused = subprocess.run(copy + ['--as', root + '/untrusted', '--no-tcp'], env=environment,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
            assert refused.returncode and b'Host key verification failed' in refused.stderr, refused.stderr
            remote('destination', f'test ! -e {root}/untrusted')
            known_hosts.write_text(f'[destination]:22222 {public}\n')
            run('syq', 'receiver', 'revoke', identifier, env=environment)
            remote('destination', f'test ! -e {state}')
            print('Separate receiver keys, migration, and OpenSSH 8.8 passed', flush=True)
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
