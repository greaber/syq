#!/usr/bin/env python3
"""Metadata reconciliation and recovery in the disposable OpenSSH lab."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile


def successful_copies():
    acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in [(1,7,0xffffffff),(2,6,12345),(4,5,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)])
    with tempfile.TemporaryDirectory(prefix='syq-inode-metadata-') as scratch:
        root = Path(scratch)
        source = root / 'source'
        source.mkdir()
        payload = bytearray(8 * 1024 * 1024 + 79)
        payload[17:9001] = b'x' * (9001 - 17)
        payload[4 * 1024 * 1024:4 * 1024 * 1024 + 31] = b'y' * 31
        with (source / 'file').open('wb') as file:
            file.write(payload[:9001])
            file.seek(4 * 1024 * 1024)
            file.write(b'y' * 31)
            file.truncate(len(payload))
        os.link(source / 'file', source / 'alias')
        os.setxattr(source / 'file', 'user.binary', b'\x00\xffbytes')
        os.setxattr(source / 'file', 'user.empty', b'')
        os.setxattr(source / 'file', 'system.posix_acl_access', acl)
        os.setxattr(source, 'system.posix_acl_default', acl)
        expected_atime = 1_000_000_000_123456789
        os.utime(source / 'file', ns=(expected_atime, (source / 'file').stat().st_mtime_ns))
        for label, transport in [('ssh', ['--no-tcp']), ('tcp', [])]:
            env = dict(os.environ, SYQ_TEST_REQUIRE_TCP='1') if label == 'tcp' else None
            destination = '/tmp/syq-real-ssh/inode-metadata-' + label
            push = ['syq', 'cp', '--preserve=hardlinks,acls,xattrs,atimes', '--open-noatime', '--sparse', '--srcs-in', str(source), '--to', 'destination', '--into', destination, *transport]
            subprocess.run(push, check=True, timeout=30, env=env)
            subprocess.run(push, check=True, timeout=30, env=env)
            pull = root / label
            subprocess.run(['syq', 'cp', '--preserve=hardlinks,acls,xattrs,atimes', '--open-noatime', '--sparse', '--from', 'destination', '--srcs-in', destination, '--into', str(pull), *transport], check=True, timeout=30, env=env)
            assert (source / 'file').stat().st_atime_ns == expected_atime
            assert (pull / 'file').stat().st_atime_ns == expected_atime
            copied = (pull / 'file').stat()
            assert copied.st_size == len(payload)
            assert copied.st_blocks * 512 < copied.st_size // 4
            fd = os.open(pull / 'file', os.O_RDONLY | os.O_NOATIME)
            with os.fdopen(fd, 'rb') as file:
                assert file.read() == payload
            for name in ['user.binary','user.empty','system.posix_acl_access']:
                assert os.getxattr(source / 'file',name) == os.getxattr(pull / 'file',name), name
            assert os.getxattr(source,'system.posix_acl_default') == os.getxattr(pull,'system.posix_acl_default')
            assert (pull / 'file').stat().st_ino == (pull / 'alias').stat().st_ino
            os.removexattr(pull / 'file','user.empty')
            os.removexattr(pull / 'file','system.posix_acl_access')
            os.removexattr(pull,'system.posix_acl_default')
            subprocess.run(['syq','cp','--preserve=hardlinks,acls,xattrs,atimes', '--open-noatime', '--sparse','--srcs-in',str(pull),'--to','destination','--into',destination,*transport],check=True,timeout=30,env=env)
            verify = root / (label + '-reconciled')
            subprocess.run(['syq','cp','--preserve=hardlinks,acls,xattrs,atimes', '--open-noatime', '--sparse','--from','destination','--srcs-in',destination,'--into',str(verify),*transport],check=True,timeout=30,env=env)
            assert (verify / 'file').stat().st_atime_ns == expected_atime
            assert 'user.empty' not in os.listxattr(verify / 'file')
            assert 'system.posix_acl_access' not in os.listxattr(verify / 'file')
            assert 'system.posix_acl_default' not in os.listxattr(verify)
        # Each full scan/stat batch exceeds the control frame budget. The remote
        # helper must fragment metadata without dropping entries or losing framing.
        rich = root / 'rich'
        rich.mkdir()
        value = b'\x00\xff' * 1536
        for index in range(5000):
            file = rich / str(index)
            file.write_bytes(b'data')
            os.setxattr(file, 'user.rich', value)
        remote = '/tmp/syq-real-ssh/rich-metadata'
        command = ['syq', 'cp', '--preserve=xattrs', '--srcs-in', str(rich), '--to', 'destination', '--into', remote, '--no-tcp']
        subprocess.run(command, check=True, timeout=90)
        subprocess.run(command, check=True, timeout=90)
        copied = root / 'rich-copy'
        subprocess.run(['syq', 'cp', '--preserve=xattrs', '--from', 'destination', '--srcs-in', remote, '--into', str(copied), '--no-tcp'], check=True, timeout=90)
        for index in range(5000):
            assert os.getxattr(copied / str(index), 'user.rich') == value


def remote(code):
    import shlex
    return subprocess.run(['ssh', 'destination', 'python3 -c ' + shlex.quote(code)],
                          check=True, text=True, stdout=subprocess.PIPE, timeout=20).stdout


def snapshot(directory):
    import json
    return json.loads(remote(f'''
import hashlib, json, os
from pathlib import Path
root = Path({str(directory)!r})
result = {{}}
for file in root.iterdir():
    s = file.stat()
    result[file.name] = {{'sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
        'size': s.st_size, 'mode': s.st_mode & 0o7777, 'uid': s.st_uid, 'gid': s.st_gid,
        'mtime': s.st_mtime_ns, 'inode': s.st_ino,
        'xattrs': {{n: os.getxattr(file,n).hex() for n in os.listxattr(file)}}}}
print(json.dumps(result))
'''))


def metadata(file, value):
    file.chmod(0o640)
    os.setxattr(file, 'user.binary', value)
    os.setxattr(file, 'user.empty', b'')
    acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in
        [(1,4,0xffffffff),(2,4,12345),(4,4,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)])
    os.setxattr(file, 'system.posix_acl_access', acl)
    os.utime(file, ns=(1_000_000_000_000000000, 1_000_000_000_123456789))


def verify(source, destination):
    import hashlib
    actual = snapshot(destination)
    # Earlier invocations' sidecars are read-only donors and remain available
    # to other concurrent copies; clean-partials owns their eventual removal.
    assert {'file', 'alias'} <= actual.keys(), actual
    assert all(n in ('file', 'alias') or '.syq-tmp.' in n for n in actual), actual
    for name in ('file', 'alias'):
        file = source / name
        s = file.stat()
        expected = {'sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
            'size': s.st_size, 'mode': s.st_mode & 0o7777, 'uid': s.st_uid, 'gid': s.st_gid,
            'mtime': s.st_mtime_ns, 'xattrs': {n: os.getxattr(file,n).hex() for n in os.listxattr(file)}}
        assert {k: v for k,v in actual[name].items() if k != 'inode'} == expected, actual
    assert actual['file']['inode'] == actual['alias']['inode'], actual


def failed_copies():
    import hashlib
    import json
    import shlex
    import signal
    import time
    import uuid
    root = '/tmp/syq-real-ssh/recovery-' + uuid.uuid4().hex
    remote(f'from pathlib import Path; Path({root!r}).mkdir()')
    with tempfile.TemporaryDirectory(prefix='syq-metadata-recovery-') as temporary:
        source = Path(temporary) / 'source'
        source.mkdir()
        data = bytes(range(256)) * (128 * 1024)
        (source / 'file').write_bytes(data)
        os.link(source / 'file', source / 'alias')
        for label, transport in [('ssh', ['--no-tcp']), ('tcp', [])]:
            env = dict(os.environ, SYQ_TEST_REQUIRE_TCP='1') if label == 'tcp' else None
            for inplace in (False, True):
                for attribute in ('system.posix_acl_access', 'user.binary'):
                    print(f'case: {label} metadata failure after writing ({inplace=}, {attribute})', flush=True)
                    destination = root + '/' + uuid.uuid4().hex
                    metadata(source / 'file', b'before failure')
                    # A persistent control pool may start the helper before the
                    # next invocation. Give each fault an immutable command,
                    # then resume with the ordinary helper below.
                    wrapper = destination + '-helper'
                    script = '#!/bin/sh\nexport SYQ_TEST_FAIL_XATTR=' + shlex.quote(attribute) + \
                        '\nexec /usr/local/bin/syq "$@"\n'
                    remote(f'from pathlib import Path; w=Path({wrapper!r}); w.write_text({script!r}); w.chmod(0o755)')
                    command = ['syq', 'cp', '--preserve=permissions,ownership,hardlinks,acls,xattrs',
                        '--srcs-in', str(source), '--to', 'destination', '--into', destination,
                        '--syq-path', wrapper, '--performance-tuning=workers=1', '--no-progress', *transport]
                    if inplace:
                        command.append('--inplace')
                    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60, env=env)
                    assert result.returncode != 0, result.stdout
                    assert 'injected attribute reconciliation failure' in result.stdout, result.stdout
                    staged = snapshot(destination)
                    assert staged, result.stdout
                    assert all(f['sha256'] == hashlib.sha256(data).hexdigest() for f in staged.values()), staged
                    if not inplace:
                        assert not {'file', 'alias'} & staged.keys(), staged
                    if attribute == 'user.binary':
                        assert all(f['mode'] == 0o440 for f in staged.values()), staged
                    metadata(source / 'file', b'after failure')
                    retry = command.copy()
                    retry[retry.index('--syq-path') + 1] = '/usr/local/bin/syq'
                    subprocess.run(retry, check=True, timeout=60, env=env)
                    verify(source, destination)
            print(f'case: {label} interrupted metadata copy resumes', flush=True)
            metadata(source / 'file', b'before interruption')
            destination = root + '/interrupted-' + label
            command = ['syq', 'cp', '--preserve=permissions,ownership,hardlinks,acls,xattrs',
                '--srcs-in', str(source), '--to', 'destination', '--into', destination,
                '--performance-tuning=workers=1,comparison-block-size=1M', '--no-progress', *transport]
            with tempfile.TemporaryFile() as log:
                process = subprocess.Popen([*command, '--resource-limits=bandwidth=2M'],
                    stdout=log, stderr=log, start_new_session=True, env=env)
                try:
                    deadline = time.monotonic() + 30
                    next_report = 0
                    last = None
                    while time.monotonic() < deadline:
                        assert process.poll() is None, 'copy finished before interruption'
                        last = remote(f'''from pathlib import Path
p=Path({destination!r})
print(any(f.open('rb').read(4 << 20) == {data[:256]!r} * (4 * 4096) for f in p.glob('.*.syq-tmp.*')))
''').strip()
                        if last == 'True':
                            break
                        if time.monotonic() >= next_report:
                            print(f'Waiting for {label} partial contents: {last}', flush=True)
                            next_report = time.monotonic() + 2
                        time.sleep(.1)
                    else:
                        raise AssertionError(f'partial contents timed out: {last}')
                    process.send_signal(signal.SIGINT)
                    assert process.wait(timeout=20) != 0, 'interrupted copy reported success'
                finally:
                    # Reap the coordinator and terminate any surviving local SSH children.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
                    log.seek(0)
                    print(log.read().decode(errors='replace'), end='', flush=True)
            assert not {'file', 'alias'} & snapshot(destination).keys()
            metadata(source / 'file', b'after interruption')
            results = Path(temporary) / (label + '.ndjson')
            subprocess.run([*command, '--results', str(results)], check=True, timeout=60, env=env)
            terminal = json.loads(results.read_text().splitlines()[-1])
            assert terminal['status'] == 'success', terminal
            assert 0 < terminal['bytes_transferred'] < len(data), terminal
            verify(source, destination)


if __name__ == '__main__':
    successful_copies()
    failed_copies()
    print('Metadata reconciliation, failures, and recovery passed', flush=True)
