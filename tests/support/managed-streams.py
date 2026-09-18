#!/usr/bin/env python3
"""The process-local SDK commit channel must gate native publication."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

syq = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp).resolve()
    target = root / 'target'
    target.write_bytes(b'old')
    env = {k: v for k, v in os.environ.items() if not k.startswith('SYQ_')}
    env['HOME'] = temp
    for payload in (b'', bytes(range(256)) * 80000):
        for commit in (b'', b'X', b'CC', b'C'):
            target.write_bytes(b'old')
            read_fd, write_fd = os.pipe()
            os.write(write_fd, commit)
            os.close(write_fd)
            try:
                result = subprocess.run([syq, 'cp', '--src-fd', '0', '--as', str(target),
                                         '--stream-commit-fd', str(read_fd)], input=payload,
                                        pass_fds=(read_fd,), env=env, timeout=15,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            finally:
                os.close(read_fd)
            assert (result.returncode == 0) == (commit == b'C'), result.stderr
            assert target.read_bytes() == (payload if commit == b'C' else b'old')
            assert not list(root.glob('.syq-stream-*'))
print('managed stream publication checks passed')
