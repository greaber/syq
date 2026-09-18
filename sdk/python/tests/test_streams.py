from __future__ import annotations

import asyncio
from array import array
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import tempfile
import unittest

import syq

SYQ = Path(os.environ.get('SYQ_CANDIDATE_EXECUTABLE', Path(__file__).resolve().parents[3] / 'target/debug/syq'))


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('SYQ_')}
        self.env['HOME'] = str(self.root)
        self.client = syq.Client(executable=SYQ, env=self.env, timeout=10)

    def test_streaming_tar_round_trip_and_early_archive_eof(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'data').write_bytes(bytes(range(256)) * 80000)
        (source / 'link').symlink_to('data')
        (source / 'empty').mkdir()
        target = self.root / 'archive.tar'
        with self.client.open_writer(as_=target) as output:
            with tarfile.open(fileobj=output, mode='w|') as archive:
                archive.add(source, arcname='tree')
            self.assertFalse(target.exists(), 'EOF is not producer commit')
        with self.client.open_reader(target) as input:
            with tarfile.open(fileobj=input, mode='r|') as archive:
                archive.extractall(self.root / 'restored', filter='data')
        self.assertEqual((self.root / 'restored/tree/data').read_bytes(), (source / 'data').read_bytes())
        self.assertEqual(os.readlink(self.root / 'restored/tree/link'), 'data')
        self.assertTrue((self.root / 'restored/tree/empty').is_dir())

    def test_exception_aborts_without_replacing_destination(self):
        target = self.root / 'target'
        target.write_bytes(b'old')
        error = ValueError('producer failed')
        with self.assertRaises(ValueError) as caught:
            with self.client.open_writer(as_=target) as output:
                output.write(b'partial' * 1000000)
                raise error
        self.assertIs(caught.exception, error)
        self.assertEqual(target.read_bytes(), b'old')
        self.assertFalse(list(self.root.glob('.syq-stream-*')))

    def test_empty_commit_abort_and_repeated_eof(self):
        target = self.root / 'target'
        with self.client.open_writer(as_=target):
            pass
        self.assertEqual(target.read_bytes(), b'')
        with self.client.open_reader(target) as input:
            self.assertEqual(input.read(), b'')
            self.assertEqual(input.read(), b'')
        output = self.client.open_writer(as_=target)
        output.abort()
        output.abort()
        self.assertEqual(target.read_bytes(), b'')

    def test_readinto_accepts_typed_buffers_and_rejects_readonly_before_reading(self):
        target = self.root / 'bytes'
        target.write_bytes(bytes(range(16)))
        buffer = array('I', [0] * 4)
        with self.client.open_reader(target) as source:
            with self.assertRaises(TypeError):
                source.readinto(b'not writable')
            self.assertEqual(source.readinto(buffer), 16)
        self.assertEqual(buffer.tobytes(), bytes(range(16)))

    def test_remote_helper_and_failure_propagation(self):
        rsh = self.root / 'rsh'
        rsh.write_text('#!/bin/sh\nshift\nexec /bin/sh -c "$1"\n')
        rsh.chmod(0o700)
        target = self.root / 'remote file'
        options = dict(rsh=str(rsh), syq_path=str(SYQ))
        with self.client.open_writer(to='fixture', as_=target, **options) as output:
            output.write(b'remote bytes')
        with self.client.open_reader(target, from_='fixture', **options) as input:
            self.assertEqual(input.read(), b'remote bytes')
        with self.assertRaises(syq.SyqProcessError) as caught:
            with self.client.open_reader(self.root / 'missing') as input:
                input.read()
        self.assertTrue(caught.exception.result.stderr)

    def test_completion_eof_aborts_even_after_payload_eof(self):
        target = self.root / 'uncommitted'
        for message in (b'', b'X', b'CC', b'C'):
            control, sender = os.pipe()
            os.write(sender, message)
            os.close(sender)
            try:
                result = subprocess.run([str(SYQ), 'cp', '--src-fd', '0', '--as', str(target),
                                         '--stream-commit-fd', str(control)], input=b'payload',
                                        pass_fds=(control,), env=self.env, timeout=10,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            finally:
                os.close(control)
            if message == b'C':
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(target.read_bytes(), b'payload')
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(target.exists())

    def test_timeout_interrupts_blocking_write_and_reaps_child(self):
        fake = self.root / 'slow-syq'
        fake.write_text('#!/bin/sh\nexec sleep 60\n')
        fake.chmod(0o700)
        client = syq.Client(executable=fake, timeout=.1)
        with self.assertRaises(subprocess.TimeoutExpired):
            with client.open_writer(as_='ignored') as output:
                output.write(b'x' * (1 << 20))
        self.assertIsNotNone(output._process.process.poll())


class AsyncStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_round_trip_and_cancelled_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            client = syq.AsyncClient(executable=SYQ, timeout=10)
            async with client.open_writer(as_=root / 'file') as output:
                await output.write(b'async bytes')
            async with client.open_reader(root / 'file') as input:
                self.assertEqual(await input.read(), b'async bytes')
            fake = root / 'slow-syq'
            fake.write_text('#!/bin/sh\nexec sleep 60\n')
            fake.chmod(0o700)
            client = syq.AsyncClient(executable=fake)
            input = client.open_reader('ignored')
            await input.__aenter__()
            task = asyncio.create_task(input.read(1))
            await asyncio.sleep(.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 10)
            self.assertIsNotNone(input._stream._process.process.poll())

    async def test_cancelled_close_reaps_process(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / 'slow-syq'
            fake.write_text('#!/bin/sh\nexec sleep 60\n')
            fake.chmod(0o700)
            output = syq.AsyncClient(executable=fake).open_writer(as_='ignored')
            await output.__aenter__()
            task = asyncio.create_task(output.close())
            await asyncio.sleep(.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 10)
            self.assertIsNotNone(output._stream._process.process.poll())
