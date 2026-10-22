#!/usr/bin/env python3
"""The user's login key signs restricted copies, with real OpenSSH in the lab.

Each kind of login key enrolls the destination account and signs a copy:
key files, encrypted keys in the agent, agent-only keys, FIDO keys through
the agent with the lab's provider, and a certificate login. Keys that cannot
sign are refused before anything is installed. A new login key replaces only
the trusted signer, a connection started before a refresh cannot start a new
copy, and a copy running through a refresh finishes.
"""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time

PROVIDER = '/usr/local/lib/syq-test-sk.so'
SOURCE_FILE = '/tmp/syq-real-ssh-key-source'
STATE = Path.home() / '.local/state/syq/enrollments'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=90, **kwargs)


def attempt(*args, **kwargs):
    return subprocess.run(args, timeout=90, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def remote(command, **kwargs):
    # The lab's own login, whatever this test does to the SSH configuration.
    return run('ssh', '-F', '/dev/null', '-i', str(Path.home() / '.ssh/id_ed25519'),
               '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes',
               '-o', 'UserKnownHostsFile=/home/syq/.ssh/known_hosts', 'syq@destination', command, **kwargs)


def remote_text(command):
    return remote(command, stdout=subprocess.PIPE).stdout.decode()


def wait_for(label, probe, seconds=30):
    deadline = time.monotonic() + seconds
    progress = 0
    last = None
    while time.monotonic() < deadline:
        done, last = probe()
        if done:
            return last
        if time.monotonic() >= progress:
            print(f'Waiting for {label}: {last}', flush=True)
            progress = time.monotonic() + 2
        time.sleep(.1)
    raise AssertionError(f'{label} timed out; last state: {last}')


def enrollment():
    """The enrolling machine's record for syq@destination, if any."""
    records = [(path.parent, json.loads(path.read_bytes()))
               for path in STATE.glob('*/enrollment.json')]
    matches = [(directory, record) for directory, record in records if record['host'] == 'destination']
    assert len(matches) <= 1, matches
    return matches[0] if matches else (None, None)


def revoke_destination():
    _, record = enrollment()
    if record is not None:
        run('syq', 'receiver', 'revoke', bytes(record['id']).hex())


def local_state():
    return sorted(str(path.relative_to(STATE)) for path in STATE.rglob('*')) if STATE.exists() else []


def line_for(record):
    identifier = bytes(record['id']).hex()
    lines = [line for line in remote_text('cat ~/.ssh/authorized_keys').splitlines()
             if f'syq-enrollment:{identifier}' in line.split()]
    assert len(lines) == 1, lines
    return lines[0]


def key_words(public):
    return ' '.join(public.split()[:2])


def key_bits(public):
    return int(run('ssh-keygen', '-lf', '-', input=public.encode(), stdout=subprocess.PIPE).stdout.split()[0])


class Lab:
    def __init__(self, root):
        self.root = root
        self.config = Path.home() / '.ssh/config'
        self.original_config = self.config.read_bytes()
        self.original_authorized = remote('cat ~/.ssh/authorized_keys 2>/dev/null || true',
                                          stdout=subprocess.PIPE).stdout
        self.agents = []
        self.askpass = root / 'askpass'
        self.askpass.write_text("#!/bin/sh\nprintf '%s\\n' fixture-unlock\n")
        self.askpass.chmod(0o700)

    def agent(self, name, askpass=False):
        socket = self.root / f'{name}.sock'
        environment = dict(os.environ)
        for variable in ('SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', 'DISPLAY'):
            environment.pop(variable, None)
        if askpass:
            environment.update(SSH_ASKPASS=str(self.askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY='fixture')
        process = subprocess.Popen(['ssh-agent', '-D', '-P', PROVIDER, '-a', str(socket)],
                                   start_new_session=True, stdout=subprocess.DEVNULL, env=environment)
        self.agents.append(process)
        wait_for(f'agent {name}', lambda: (socket.exists(), process.poll()))
        return socket

    def add(self, socket, *arguments):
        environment = dict(os.environ, SSH_AUTH_SOCK=str(socket), SSH_ASKPASS=str(self.askpass),
                           SSH_ASKPASS_REQUIRE='force', DISPLAY='fixture')
        run('ssh-add', *arguments, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def use(self, key, socket, certificate=None):
        """Log in to the destination with `key`, through the agent at `socket`."""
        certificate_line = f'    CertificateFile {certificate}\n' if certificate else ''
        self.config.write_text(f'''Host destination
    User syq
    IdentitiesOnly yes
    IdentityFile {key}
{certificate_line}    SecurityKeyProvider {PROVIDER}
    IdentityAgent {socket}
    # Passphrases and PINs come from the askpass program, never a terminal.
    BatchMode no
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    StrictHostKeyChecking yes
    UserKnownHostsFile /home/syq/.ssh/known_hosts
    GlobalKnownHostsFile /dev/null
Host source
    User syq
    IdentitiesOnly yes
    IdentityFile /home/syq/.ssh/id_ed25519
    IdentityAgent {self.main}
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /home/syq/.ssh/known_hosts
    GlobalKnownHostsFile /dev/null
''')

    def authorize(self, line):
        remote('cat >> ~/.ssh/authorized_keys', input=(line + '\n').encode())

    def restore(self):
        self.config.write_bytes(self.original_config)
        remote('cat > ~/.ssh/authorized_keys', input=self.original_authorized)
        for process in self.agents:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)


def keygen(path, kind, bits=None, passphrase='', flags=None):
    arguments = ['ssh-keygen', '-q', '-t', kind, '-C', 'syq-test-login', '-f', str(path), '-N', passphrase]
    if bits:
        arguments += ['-b', str(bits)]
    if flags is not None:
        arguments += ['-w', PROVIDER]
        if not flags & 1:
            arguments += ['-O', 'no-touch-required']
        if flags & 4:
            arguments += ['-O', 'verify-required']
    run(*arguments)
    path.chmod(0o400)
    return path.with_suffix('.pub').read_text().strip()


def copy(destination, *extra, check=True):
    arguments = ['syq', 'cp', '--from', 'source', SOURCE_FILE, '--to', 'destination',
                 '--as', destination, '--no-tcp', '--no-progress', *extra]
    if not check:
        return attempt(*arguments)
    run(*arguments)
    assert remote_text('cat ' + shlex.quote(destination)) == 'login-key-copy\n'


def refused_before_installation(label, arguments, expected):
    """Enrollment fails with `expected` and leaves both machines unchanged."""
    authorized = remote('cat ~/.ssh/authorized_keys', stdout=subprocess.PIPE).stdout
    before = local_state()
    result = attempt(*arguments)
    assert result.returncode, f'{label}: enrollment succeeded'
    assert expected in result.stderr, (label, result.stderr.decode(errors='replace'))
    assert remote('cat ~/.ssh/authorized_keys', stdout=subprocess.PIPE).stdout == authorized, label
    assert local_state() == before, (label, before, local_state())
    print(f'{label}: refused before installation', flush=True)


def login_kinds(lab, parent):
    # (label, kind, bits, encrypted, FIDO flags, in the agent, entry key, entry bits)
    for label, kind, bits, encrypted, flags, in_agent, entry, entry_bits in [
        ('Ed25519 key file', 'ed25519', None, False, None, False, 'ssh-ed25519', None),
        ('encrypted Ed25519 in the agent', 'ed25519', None, True, None, True, 'ssh-ed25519', None),
        ('encrypted RSA 2048 in the agent', 'rsa', 2048, True, None, True, 'ssh-rsa', 3072),
        ('RSA 4096 key file', 'rsa', 4096, False, None, False, 'ssh-rsa', 4096),
        ('encrypted ECDSA P-256 in the agent', 'ecdsa', 256, True, None, True, 'ecdsa-sha2-nistp256', None),
        ('ECDSA P-384 key file', 'ecdsa', 384, False, None, False, 'ecdsa-sha2-nistp384', None),
        ('FIDO Ed25519 without touch', 'ed25519-sk', None, False, 0, True, 'ssh-ed25519', None),
        ('FIDO Ed25519 with touch', 'ed25519-sk', None, False, 1, True, 'ssh-ed25519', None),
        ('FIDO ECDSA without touch', 'ecdsa-sk', None, False, 0, True, 'ecdsa-sha2-nistp256', None),
        ('FIDO Ed25519 with touch and PIN', 'ed25519-sk', None, False, 5, True, 'ssh-ed25519', None),
    ]:
        print(f'Checking {label}', flush=True)
        revoke_destination()
        key = lab.root / ('login-' + label.replace(' ', '-'))
        public = keygen(key, kind, bits, 'fixture-unlock' if encrypted else '', flags)
        options = []
        if flags is not None and not flags & 1:
            options.append('no-touch-required')
        if flags is not None and flags & 4:
            options.append('verify-required')
        lab.authorize((','.join(options) + ' ' if options else '') + public)
        socket = lab.agent(label.replace(' ', '-'), askpass=False)
        lab.use(key, socket)
        enroll = ['syq', 'receiver', 'enroll', 'destination']
        if encrypted:
            # Without the agent, syq does not ask for the passphrase.
            refused_before_installation(label, enroll, b'ssh-add')
        if flags is not None and flags & 4:
            # Only OpenSSH's own helper reaches the authenticator, so a FIDO
            # key must be in the agent, even when the login used its handle.
            refused_before_installation(label, enroll, b'only through your SSH agent')
            # An agent that cannot ask for the PIN cannot sign, not even the
            # login.
            lab.add(socket, '-S', PROVIDER, str(key))
            refused_before_installation(label, enroll, b'restricted enrollment SSH')
            socket = lab.agent(label.replace(' ', '-') + '-pin', askpass=True)
            lab.use(key, socket)
        if in_agent:
            lab.add(socket, *(['-S', PROVIDER] if flags is not None else []), str(key))
        run(*enroll)
        directory, record = enrollment()
        assert key_words(record['signer']['public_key']) == key_words(public), record
        if flags is not None:
            assert record['signer']['security_key_flags'] == flags, record
        else:
            assert 'security_key_flags' not in record['signer'], record
        assert (record.get('identity_file') is not None) == (not encrypted and flags is None), record
        line = line_for(record)
        assert line.endswith(' signer ' + key_words(public)), line
        assert 'no-touch-required' not in line and 'verify-required' not in line, line
        entry_public = run('ssh-keygen', '-y', '-f', str(directory / 'entry-key'),
                           stdout=subprocess.PIPE).stdout.decode()
        assert key_words(entry_public) in line, line
        assert entry_public.split()[0] == entry, (label, entry_public)
        if entry_bits:
            assert key_bits(entry_public) == entry_bits, (label, entry_public)
        assert '.local/lib/syq/' in line and '--generation=1"' in line, line
        copy(f'{parent}/{label.replace(" ", "-")}')
        if flags is not None:
            # The authenticator signs every copy's grant.
            unavailable = Path(os.environ['SYQ_TEST_SK_UNAVAILABLE'])
            unavailable.touch()
            failed = copy(f'{parent}/unavailable', check=False)
            unavailable.unlink()
            assert failed.returncode, 'copy succeeded with the test device unavailable'


def refused_keys(lab):
    revoke_destination()
    socket = lab.agent('limited', askpass=True)
    # A key added with `ssh-add -h` signs only logins at named hosts.
    key = lab.root / 'limited'
    public = keygen(key, 'ed25519')
    lab.authorize(public)
    lab.add(socket, '-H', str(Path.home() / '.ssh/known_hosts'), '-h', 'syq@destination', str(key))
    lab.use(key, socket)
    run('ssh', 'destination', 'true')
    refused_before_installation('ssh-add -h key', ['syq', 'receiver', 'enroll', 'destination'], b'ssh-add -h')

    # An agent-only key: no file, as with PIV or PKCS#11 keys.
    key = lab.root / 'agent-only'
    public = keygen(key, 'ed25519')
    lab.authorize(public)
    socket = lab.agent('agent-only', askpass=True)
    lab.add(socket, str(key))
    # Only the public key remains, which selects the agent's key.
    key.unlink()
    lab.use(key, socket)
    run('syq', 'receiver', 'enroll', 'destination')
    _, record = enrollment()
    assert key_words(record['signer']['public_key']) == key_words(public)
    assert record.get('identity_file') is None
    print('agent-only key enrolled', flush=True)
    untrusted_stored_build()


def untrusted_stored_build():
    """A stored build others could change is never started: setup refuses it."""
    identity = run('syq', '--build-identity', stdout=subprocess.PIPE).stdout.decode().strip()
    stored = remote_text(f'ls -d ~/.local/lib/syq/{shlex.quote(identity)}/*/syq').split()
    assert len(stored) == 1, stored
    stored = stored[0]
    marker = '/tmp/syq-real-ssh-untrusted-build-started'
    saved = '/tmp/syq-real-ssh-stored-build'
    # The stored syq may be running, so it is replaced by renaming a new
    # file over it, never rewritten in place.
    replace = f'mv -f {stored}.new {stored}'
    remote(f'rm -f {marker} && cp -p {stored} {saved} && '
           f"printf '#!/bin/sh\\ntouch {marker}\\nexit 1\\n' > {stored}.new && "
           f'chmod 770 {stored}.new && {replace}')
    try:
        result = attempt('syq', 'receiver', 'enroll', 'destination')
        assert result.returncode, 'enrollment used a group-writable stored build'
        assert b'writable by group or others' in result.stderr, result.stderr.decode(errors='replace')
        assert remote_text(f'test -e {marker} && echo started || echo absent').strip() == 'absent'
        # A private stored build that is not exactly this build, as any
        # build looks on a filesystem that fixes owners and modes, is not
        # started either: setup uploads this build, which replaces it.
        remote(f'chmod 700 {stored}')
        run('syq', 'receiver', 'enroll', 'destination')
        assert remote_text(f'test -e {marker} && echo started || echo absent').strip() == 'absent'
        remote(f'cmp {stored} {saved}')
    finally:
        remote(f'cp -p {saved} {stored}.new && chmod 700 {stored}.new && {replace} && rm -f {saved} {marker}')
    run('syq', 'receiver', 'enroll', 'destination')
    print('stored builds that are not exactly this one were never started', flush=True)


def certificate_login(lab, parent):
    revoke_destination()
    ca = lab.root / 'ca'
    ca_public = keygen(ca, 'ed25519')
    lab.authorize('cert-authority ' + ca_public)
    key = lab.root / 'certified'
    keygen(key, 'ed25519')
    run('ssh-keygen', '-q', '-s', str(ca), '-I', 'syq-test', '-n', 'syq', '-V', '-1m:+1h',
        str(key.with_suffix('.pub')))
    certificate = Path(str(key) + '-cert.pub')
    details = run('ssh-keygen', '-L', '-f', str(certificate), stdout=subprocess.PIPE).stdout.decode()
    assert 'Valid: from' in details, details
    socket = lab.agent('certificate', askpass=True)
    lab.add(socket, str(key))
    lab.use(key, socket, certificate)
    run('syq', 'receiver', 'enroll', 'destination')
    _, record = enrollment()
    expiry = record['signer'].get('valid_before')
    assert expiry and expiry > time.time(), record
    copy(f'{parent}/certificate')
    print('certificate login enrolled and copied', flush=True)


def rotation_and_generations(lab, parent):
    revoke_destination()
    first = lab.root / 'rotation-first'
    second = lab.root / 'rotation-second'
    third = lab.root / 'rotation-third'
    publics = {path: keygen(path, 'ed25519') for path in (first, second, third)}
    for public in publics.values():
        lab.authorize(public)
    socket = lab.agent('rotation', askpass=True)
    lab.add(socket, str(first))
    lab.use(first, socket)
    copy(f'{parent}/rotation-one')
    directory, record = enrollment()
    entry_key = (directory / 'entry-key').read_bytes()
    assert record['generation'] == 1

    # The recorded login key can no longer sign: the next copy enrolls the
    # current login's key, in place of only the trusted signer.
    lab.add(socket, '-d', str(first.with_suffix('.pub')))
    first.rename(first.with_suffix('.hidden'))
    lab.add(socket, str(second))
    lab.use(second, socket)
    copy(f'{parent}/rotation-two')
    rotated_directory, rotated = enrollment()
    assert rotated['id'] == record['id'] and rotated_directory == directory
    assert (directory / 'entry-key').read_bytes() == entry_key
    assert rotated['generation'] == 2, rotated
    line = line_for(rotated)
    assert line.endswith(' signer ' + key_words(publics[second])), line
    assert key_words(publics[first]) not in line
    print('a new login key replaced only the trusted signer', flush=True)

    # A connection started before a refresh still runs its old forced
    # command, and cannot start a new copy.
    entry = directory / 'entry-key'
    control = lab.root / 'old-connection'
    entry_ssh = ['ssh', '-F', '/dev/null', '-i', str(entry), '-o', 'IdentitiesOnly=yes',
                 '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes',
                 '-o', 'UserKnownHostsFile=/home/syq/.ssh/known_hosts', '-o', 'StrictHostKeyChecking=yes']
    run(*entry_ssh, '-o', 'ControlMaster=yes', '-o', f'ControlPath={control}', '-o', 'ControlPersist=60',
        '-N', '-f', 'syq@destination')
    try:
        lab.add(socket, str(third))
        lab.use(third, socket)
        run('syq', 'receiver', 'enroll', 'destination')
        _, refreshed = enrollment()
        assert refreshed['generation'] == 3, refreshed
        command = 'syq --server --restricted-grant=AAAA'
        old = attempt(*entry_ssh, '-o', f'ControlPath={control}', '-o', 'ControlMaster=no',
                      'syq@destination', command)
        assert old.returncode and b'outdated receiver' in old.stderr, old.stderr
        new = attempt(*entry_ssh, '-o', 'ControlPath=none', 'syq@destination', command)
        assert new.returncode and b'outdated receiver' not in new.stderr, new.stderr
        print('a connection from before a refresh cannot start a new copy', flush=True)
    finally:
        subprocess.run([*entry_ssh, '-o', f'ControlPath={control}', '-O', 'exit', 'syq@destination'],
                       timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # A copy running through a refresh finishes.
    run('ssh', 'source', 'head -c 32M /dev/zero > /tmp/syq-real-ssh-rotation-large')
    destination = f'{parent}/rotation-large'
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(
            ['syq', 'cp', '--from', 'source', '/tmp/syq-real-ssh-rotation-large', '--to', 'destination',
             '--as', destination, '--no-tcp', '--no-progress', '--no-compress',
             '--resource-limits', 'bandwidth=4M', '--performance-tuning', 'workers=2'],
            stdout=output, stderr=output, start_new_session=True)
        try:
            probe = 'python3 -c ' + shlex.quote(f'''
from pathlib import Path
print(any(p.stat().st_size > 0 for p in Path({parent!r}).glob('.rotation-large.syq-tmp.*')))
''')
            wait_for('the large copy to start writing',
                     lambda: (remote_text(probe).strip() == 'True', process.poll()))
            lab.add(socket, '-d', str(third.with_suffix('.pub')))
            lab.add(socket, str(second))
            lab.use(second, socket)
            run('syq', 'receiver', 'enroll', 'destination')
            _, again = enrollment()
            assert again['generation'] == 4, again
            # Drop the copy's worker connections: the workers that replace
            # them start from the refreshed line, at the new generation, and
            # join the running copy.
            dropped = remote_text('python3 -c ' + shlex.quote('''
import os, signal
dropped = 0
for pid in filter(str.isdigit, os.listdir('/proc')):
    try:
        environment = open(f'/proc/{pid}/environ', 'rb').read()
        status = open(f'/proc/{pid}/status').read()
    except OSError:
        continue
    if b'--restricted-worker=' in environment:
        os.kill(int(status.split('PPid:')[1].split()[0]), signal.SIGKILL)
        dropped += 1
print(dropped)
''')).strip()
            assert int(dropped) >= 1, dropped
            assert process.wait(timeout=90) == 0
            output.seek(0)
            log = output.read().decode(errors='replace')
            assert 'reopening' in log, log
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            output.seek(0)
            print(output.read().decode(errors='replace'), flush=True)
            raise
    size = remote_text('stat -c %s ' + shlex.quote(destination)).strip()
    assert size == str(32 << 20), size
    print('a worker joined a copy running through a refresh', flush=True)


def remount(parent):
    # Each copy resolves its destination when it starts: replacing the
    # directory, as a remount does, needs no new enrollment.
    mount = f'{parent}/mounted'
    remote(f'mkdir -p {mount}')
    copy(f'{mount}/before')
    _, before = enrollment()
    remote(f'mv {mount} {parent}/unmounted && mkdir {mount}')
    copy(f'{mount}/after')
    _, after = enrollment()
    assert after['id'] == before['id'] and after['generation'] == before['generation']
    print('a replaced destination directory kept the enrollment working', flush=True)


def main():
    original_agent = os.environ['SSH_AUTH_SOCK']
    original_environment = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='receiver-keys-') as temporary:
        root = Path(temporary)
        os.environ.update(SSH_SK_PROVIDER=PROVIDER, SYQ_TEST_SK_UNAVAILABLE=str(root / 'unavailable'))
        lab = Lab(root)
        os.environ.update(SSH_ASKPASS=str(lab.askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY='fixture')
        parent = '/tmp/syq-real-ssh/login-keys'
        try:
            lab.main = lab.agent('main', askpass=True)
            lab.add(lab.main, str(Path.home() / '.ssh/id_ed25519'))
            os.environ['SSH_AUTH_SOCK'] = str(lab.main)
            remote(f'rm -rf {parent} && mkdir -p {parent}')
            run('ssh', 'source', f"printf 'login-key-copy\\n' > {SOURCE_FILE}")
            login_kinds(lab, parent)
            refused_keys(lab)
            certificate_login(lab, parent)
            rotation_and_generations(lab, parent)
            remount(parent)
            print('Login keys sign restricted copies', flush=True)
        finally:
            try:
                revoke_destination()
            finally:
                lab.restore()
                os.environ.clear()
                os.environ.update(original_environment)
                os.environ['SSH_AUTH_SOCK'] = original_agent


if __name__ == '__main__':
    main()
