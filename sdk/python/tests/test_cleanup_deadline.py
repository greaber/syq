"""The operation deadline includes pipes held by an exited leader's children."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import syq
from syq._streams import _Process


class CleanupDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.pid = root / 'leader'
        self.fake = root / 'syq'
        fixture = (Path(__file__).parent / 'fixtures/automation-v2-progress.ndjson').read_bytes()
        self.fake.write_text(f'''#!{sys.executable}
import os, sys, time
from pathlib import Path
Path({str(self.pid)!r}).write_text(str(os.getpid()))
args = sys.argv
fd = int(next(a.split('=', 1)[1] for a in args if a.startswith('--results-fd='))) if any(a.startswith('--results-fd=') for a in args) else int(args[args.index('--results-fd') + 1])
os.write(fd, {fixture!r})
if '--hold-results' not in args:
    os.close(fd)
if os.fork() == 0:
    os.close(1)
    if '--hold-results' in args:
        os.close(2)
    # A hard cap keeps a broken implementation from hanging the test runner.
    time.sleep(2)
os._exit(0)
''')
        self.fake.chmod(0o700)
        self.addCleanup(self.kill_fixture)

    def kill_fixture(self):
        if self.pid.exists():
            try:
                os.killpg(int(self.pid.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_copy_deadline_covers_stderr_after_leader_exits(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            syq.Client(executable=self.fake, timeout=.2).cp('unused', as_='unused')

    def test_stream_deadline_stays_active_until_output_closes(self):
        for extra in ([], ['--hold-results']):
            with self.subTest(extra=extra):
                process = _Process([str(self.fake), *extra], writing=False,
                                   cwd=None, env=None, timeout=.2)
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        process.finish()
                    self.assertEqual(process.process.returncode, 0)
                    self.assertTrue(process.expired)
                    self.assertFalse(process.drain.is_alive())
                    self.assertFalse(process.results_drain.is_alive())
                finally:
                    process.abort()

    def test_reader_deadline_covers_payload_after_leader_exits(self):
        records = [json.loads(line) for line in
                   (Path(__file__).parent / 'fixtures/automation-v2-progress.ndjson').read_bytes().splitlines()]
        records.insert(1, dict(type='stream_ready', schema='syq.automation', schema_version=2))
        for seq, record in enumerate(records):
            record['seq'] = seq
        fixture = ''.join(json.dumps(record) + '\n' for record in records).encode()
        self.fake.write_text(f'''#!{sys.executable}
import os, sys, time
from pathlib import Path
Path({str(self.pid)!r}).write_text(str(os.getpid()))
fd = int(sys.argv[sys.argv.index('--results-fd') + 1])
os.write(fd, {fixture!r})
os.close(fd)
if os.fork() == 0:
    os.close(2)
    time.sleep(2)
os._exit(0)
''')
        started = time.monotonic()
        with syq.Client(executable=self.fake, timeout=.2).open_reader('unused') as reader:
            with self.assertRaises(subprocess.TimeoutExpired):
                reader.read()
            self.assertEqual(reader._process.process.returncode, 0)
            self.assertFalse(reader._process.drain.is_alive())
            self.assertFalse(reader._process.results_drain.is_alive())
        self.assertLess(time.monotonic() - started, 1.5)
