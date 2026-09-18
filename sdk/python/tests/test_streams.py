from __future__ import annotations

import asyncio
from array import array
import io
import json
import os
from pathlib import Path
import sys
import threading
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
        self.root = Path(self.temp.name).resolve()
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

    def test_wrappers_close_payload_without_committing_on_success_or_exception(self):
        for remote in (False, True):
            rsh = self.root / 'wrapper-rsh'
            rsh.write_text('#!/bin/sh\nshift\nexec /bin/sh -c "$1"\n')
            rsh.chmod(0o700)
            options = dict(to='fixture', rsh=str(rsh), syq_path=str(SYQ)) if remote else {}
            for text in (False, True):
                for fail in (False, True):
                    with self.subTest(remote=remote, text=text, fail=fail):
                        target = self.root / 'wrapped'
                        target.write_bytes(b'old')
                        error = ValueError('producer failed')
                        try:
                            with self.client.open_writer(as_=target, **options) as output:
                                wrapper = (io.TextIOWrapper(output, encoding='utf-8') if text
                                           else io.BufferedWriter(output))
                                with wrapper:
                                    wrapper.write('partial' if text else b'partial')
                                    if fail:
                                        raise error
                                self.assertTrue(output.closed)
                                self.assertEqual(target.read_bytes(), b'old')
                        except ValueError as caught:
                            self.assertTrue(fail)
                            self.assertIs(caught, error)
                        else:
                            self.assertFalse(fail)
                        self.assertEqual(target.read_bytes(), b'old' if fail else b'partial')
                        self.assertIsNotNone(output._process.process.poll())
                        self.assertFalse(list(self.root.glob('.syq-stream-*')))

    def test_explicit_commit_and_abort_after_payload_close(self):
        target = self.root / 'explicit'
        target.write_bytes(b'old')
        for commit in (False, True):
            output = self.client.open_writer(as_=target)
            try:
                with io.BufferedWriter(output) as buffered:
                    buffered.write(b'new')
                output.close()  # Idempotent payload closure.
                self.assertEqual(target.read_bytes(), b'old')
                with self.assertRaises(ValueError):
                    output.write(b'too late')
                if commit:
                    output.commit()
                    output.commit()
                    self.assertEqual(target.read_bytes(), b'new')
                else:
                    output.abort()
                    with self.assertRaises(ValueError):
                        output.commit()
                    self.assertEqual(target.read_bytes(), b'old')
            finally:
                output.abort()
        self.assertFalse(list(self.root.glob('.syq-stream-*')))

    def test_explicit_abort_inside_context_cancels_normal_exit(self):
        target = self.root / 'abort-in-context'
        target.write_bytes(b'old')
        with self.client.open_writer(as_=target) as output:
            output.write(b'new')
            output.close()
            output.abort()
        self.assertEqual(target.read_bytes(), b'old')
        with self.assertRaises(ValueError):
            output.commit()

    def test_text_reader_and_failed_read_all(self):
        target = self.root / 'text-input'
        target.write_text('one\ntwo\n', encoding='utf-8')
        with self.client.open_reader(target) as source:
            with io.TextIOWrapper(source, encoding='utf-8') as text:
                self.assertEqual(list(text), ['one\n', 'two\n'])
        fake = self.root / 'broken-reader'
        fake.write_text('#!/bin/sh\nprintf \'{"a": 1\'\nexit 1\n')
        fake.chmod(0o700)
        for size in (-1, None):
            with self.subTest(size=size), self.assertRaises(syq.SyqProcessError):
                with syq.Client(executable=fake).open_reader('unused') as source:
                    json.loads(source.read(size))
            self.assertEqual(source._process.process.returncode, 1)

    def test_successful_exit_is_not_overridden_by_deadline(self):
        fake = self.root / 'finished-reader'
        # The deadline can race with a successful exit. Arrange a child
        # that returns success on TERM, and arm the watchdog after it is ready.
        fake.write_text(f'#!{sys.executable}\nimport signal, sys\n'
                        'signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n'
                        'print("ready", end="", flush=True)\nsignal.pause()\n')
        fake.chmod(0o700)
        with syq.Client(executable=fake).open_reader('unused') as source:
            self.assertEqual(source.read(5), b'ready')
            process = source._process
            process.timeout = 0
            process.watchdog = threading.Thread(target=process._deadline, daemon=True)
            process.watchdog.start()
            self.assertEqual(source.read(), b'')
            self.assertTrue(process.expired)
            self.assertEqual(process.process.returncode, 0)

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
            root = Path(temp).resolve()
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

    async def test_closed_payload_commits_only_after_successful_context(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp).resolve() / 'target'
            client = syq.AsyncClient(executable=SYQ, timeout=10)
            for fail in (False, True):
                target.write_bytes(b'old')
                try:
                    async with client.open_writer(as_=target) as output:
                        await output.write(b'new')
                        await output.close()
                        self.assertEqual(target.read_bytes(), b'old')
                        if fail:
                            raise ValueError('producer failed')
                except ValueError:
                    self.assertTrue(fail)
                self.assertEqual(target.read_bytes(), b'old' if fail else b'new')
                self.assertIsNotNone(output._stream._process.process.poll())
            async with client.open_writer(as_=target) as output:
                await output.write(b'explicit')
                await output.commit()
                self.assertEqual(target.read_bytes(), b'explicit')

    async def test_explicit_abort_inside_context_cancels_normal_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp).resolve() / 'target'
            target.write_bytes(b'old')
            client = syq.AsyncClient(executable=SYQ, timeout=10)
            async with client.open_writer(as_=target) as output:
                await output.write(b'new')
                await output.close()
                await output.abort()
            self.assertEqual(target.read_bytes(), b'old')
            with self.assertRaises(ValueError):
                await output.commit()

    async def test_failed_read_all_reports_transfer_error(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp).resolve() / 'broken-reader'
            fake.write_text('#!/bin/sh\nprintf \'{"a": 1\'\nexit 1\n')
            fake.chmod(0o700)
            with self.assertRaises(syq.SyqProcessError):
                async with syq.AsyncClient(executable=fake).open_reader('unused') as source:
                    json.loads(await source.read())

    async def test_cancelled_commit_reaps_process(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp).resolve() / 'slow-syq'
            fake.write_text('#!/bin/sh\nexec sleep 60\n')
            fake.chmod(0o700)
            output = syq.AsyncClient(executable=fake).open_writer(as_='ignored')
            await output.__aenter__()
            task = asyncio.create_task(output.commit())
            await asyncio.sleep(.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 10)
            self.assertIsNotNone(output._stream._process.process.poll())
