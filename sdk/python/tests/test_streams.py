from __future__ import annotations

import asyncio
import contextlib
from array import array
import io
import hashlib
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


def ready_stub() -> str:
    fixture = Path(__file__).resolve().parents[3] / "tests/fixtures/automation/success.ndjson"
    run = json.loads(fixture.read_text().splitlines()[0])
    run["mapping"] = False
    ready = dict(schema="syq.automation", schema_version=2, seq=1, type="stream_ready")
    data = (json.dumps(run) + "\n" + json.dumps(ready) + "\n").encode()
    return (f'#!{sys.executable}\nimport os, sys, time\n'
            f'os.write(int(sys.argv[sys.argv.index("--results-fd") + 1]), {data!r})\n'
            'time.sleep(60)\n')


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('SYQ_')}
        self.env['HOME'] = str(self.root)
        self.client = syq.Client(executable=SYQ, env=self.env, timeout=10)

    def test_stream_controls_and_diagnostics(self):
        payload = b"checksummed stream" * 5000
        target = self.root / "checked"
        with self.client.open_writer(as_=target,
                integrity_checking="transfer=sha256", stats=True,
                resource_limits="bandwidth=1M", performance_tuning="request-size=8K") as out:
            out.write(payload)
        self.assertIn(b"stream complete", out.stderr)
        with self.client.open_reader(target, stats=True) as source:
            self.assertEqual(source.read(), payload)
        self.assertIn(b"stream complete", source.stderr)
        async def asynchronous():
            client = syq.AsyncClient(executable=SYQ, env=self.env, timeout=10)
            async with client.open_writer(as_=target,
                    stats=True, resource_limits="workers=1") as out:
                await out.write(payload)
            self.assertIn(b"stream complete", out.stderr)
            async with client.open_reader(target,
                    integrity_checking="transfer=md5", stats=True) as source:
                self.assertEqual(await source.read(), payload)
            self.assertIn(b"stream complete", source.stderr)
        asyncio.run(asynchronous())

    def test_removed_stream_options_are_rejected(self):
        for option in ("expected_hash", "expected_digest", "min_size", "max_size", "progress_json"):
            with self.subTest(option=option), self.assertRaises(TypeError):
                self.client.open_reader("missing", **{option: "1"})
        for option in ("--expected-hash=md5:" + "0" * 32, "--min-size=1", "--max-size=1", "--progress-json"):
            inherited = syq.Client(executable=SYQ, env={**self.env, "SYQ_CP_OPTIONS": option})
            with self.subTest(option=option), self.assertRaises(syq.SyqProcessError):
                inherited.open_writer(as_=self.root / "missing")
        self.assertFalse((self.root / "missing").exists())

    def test_stream_results_and_previews(self):
        target = self.root / "result-object"
        with self.client.open_writer(as_=target, dry_run=True) as out:
            self.assertTrue(out.dry_run)
            self.assertFalse(out.writable())
            with self.assertRaises(ValueError):
                out.write(b"not consumed")
        self.assertFalse(target.exists())
        self.assertTrue(out.result.dry_run)
        self.assertFalse(out.result.bytes_total_known)
        with self.client.open_writer(as_=target) as out:
            out.write(b"completed")
        self.assertEqual(out.result.bytes_transferred, 9)
        self.assertTrue(out.result.bytes_total_known)
        with self.client.open_reader(target, dry_run=True) as source:
            self.assertEqual(source.read(), b"")
        self.assertTrue(source.result.dry_run)
        self.assertEqual(source.result.bytes_transferred, 9)
        with self.assertRaises(syq.SyqProcessError):
            with self.client.open_reader(self.root / "missing") as source:
                source.read()
        self.assertEqual(source.result.exit_code, 1)
        fake = self.root / "missing-results"
        fake.write_text('#!/bin/sh\nprintf truncated\n')
        fake.chmod(0o700)
        with self.assertRaises(syq.SyqProtocolError):
            with syq.Client(executable=fake).open_reader("unused") as source:
                source.read()

        async def asynchronous():
            client = syq.AsyncClient(executable=SYQ, env=self.env, timeout=10)
            async with client.open_writer(as_=self.root / "preview", dry_run=True) as out:
                self.assertTrue(out.dry_run)
            self.assertTrue(out.result.dry_run)
            self.assertFalse((self.root / "preview").exists())
            async with client.open_reader(target, dry_run=True) as source:
                self.assertEqual(await source.read(), b"")
            self.assertEqual(source.result.bytes_transferred, 9)
        asyncio.run(asynchronous())

    def test_skip_is_known_before_producing_and_does_not_commit(self):
        target = self.root / "existing"
        target.write_bytes(b"old")
        for option, destination in [("only_new", target), ("only_existing", self.root / "missing"),
                                    ("only_new", self.root)]:
            with self.client.open_writer(as_=destination, **{option: True}) as out:
                self.assertTrue(out.skipped)
                self.assertFalse(out.writable())
                with self.assertRaises(ValueError):
                    out.write(b"must not be accepted")
            self.assertEqual(out.result.files_excluded, 1)
            self.assertEqual(out.result.bytes_transferred, 0)
        self.assertEqual(target.read_bytes(), b"old")
        self.assertFalse((self.root / "missing").exists())
        with self.assertWarnsRegex(FutureWarning, "only_existing.*unsupported"), \
                self.client.open_writer(as_=target, only_existing=True) as out:
            self.assertFalse(out.skipped)
            out.write(b"new")
        with self.client.open_writer(as_=self.root / "new", only_new=True) as out:
            self.assertFalse(out.skipped)
            out.write(b"created")
        self.assertEqual(target.read_bytes(), b"new")
        inherited = syq.Client(executable=SYQ, timeout=10,
                               env={**self.env, "SYQ_CP_OPTIONS": "--only-new"})
        with inherited.open_writer(as_=target) as out:
            self.assertTrue(out.skipped)
        inherited = syq.Client(executable=SYQ, timeout=10,
                               env={**self.env, "SYQ_CP_OPTIONS": "--dry-run"})
        with inherited.open_writer(as_=target) as out:
            self.assertTrue(out.dry_run)
        self.assertEqual(target.read_bytes(), b"new")

        async def asynchronous():
            client = syq.AsyncClient(executable=SYQ, env=self.env, timeout=10)
            async with client.open_writer(as_=target, only_new=True) as out:
                self.assertTrue(out.skipped)
            self.assertEqual(out.result.files_excluded, 1)
        asyncio.run(asynchronous())

    def test_writers_open_while_remote_setup_is_blocked(self):
        # A barrier proves setup can overlap, without a timing threshold. The
        # SDK timeout bounds failure if opening starts waiting for SSH again.
        gate = self.root / "setup-gate"
        os.mkfifo(gate)
        gate_fd = os.open(gate, os.O_RDWR | os.O_NONBLOCK)
        self.addCleanup(os.close, gate_fd)
        rsh = self.root / "gated-rsh"
        rsh.write_text(f'#!{sys.executable}\nimport os, sys\n'
                       f'with open({str(gate)!r}, "rb", buffering=0) as gate: gate.read(1)\n'
                       'os.execl("/bin/sh", "sh", "-c", sys.argv[-1])\n')
        rsh.chmod(0o700)
        options = dict(to="fixture", rsh=str(rsh), syq_path=str(SYQ),
                       no_tcp=True, performance_tuning="workers=1", timeout=3)
        env = {**self.env, "SYQ_CP_OPTIONS": "--no-compress"}
        client = syq.Client(executable=SYQ, env=env)
        with contextlib.ExitStack() as stack:
            outputs = [stack.enter_context(client.open_writer(as_=self.root / f"sync-{i}", **options))
                       for i in range(2)]
            self.assertTrue(all(not out.skipped for out in outputs))
            self.assertFalse((self.root / "sync-0").exists())
            os.write(gate_fd, b"xxxx")  # Two control sessions and two data workers.
            for out in outputs:
                out.write(b"overlapped")
        for i in range(2):
            self.assertEqual((self.root / f"sync-{i}").read_bytes(), b"overlapped")

        async def asynchronous():
            client = syq.AsyncClient(executable=SYQ, env=env)
            async with contextlib.AsyncExitStack() as stack:
                outputs = [await stack.enter_async_context(client.open_writer(
                    as_=self.root / f"async-{i}", **options)) for i in range(2)]
                self.assertFalse((self.root / "async-0").exists())
                os.write(gate_fd, b"xxxx")
                for out in outputs:
                    await out.write(b"overlapped")
            for i in range(2):
                self.assertEqual((self.root / f"async-{i}").read_bytes(), b"overlapped")
        asyncio.run(asynchronous())

    def test_writer_placement_and_reader_source_bases(self):
        rsh = self.root / "rsh"
        rsh.write_text('#!/bin/sh\nshift\nexec /bin/sh -c "$1"\n')
        rsh.chmod(0o700)
        for remote in (False, True):
            options = dict(rsh=str(rsh), syq_path=str(SYQ)) if remote else {}
            to = dict(to="fixture") if remote else {}
            from_ = dict(from_="fixture") if remote else {}
            base = self.root / ("remote" if remote else "local")
            base.mkdir()
            target = base / "object"
            with self.client.open_writer(as_new=target, **options, **to) as out:
                out.write(b"new")
            with self.assertRaises(syq.SyqProcessError):
                with self.client.open_writer(as_new=target, **options, **to) as out:
                    out.write(b"replacement")
            self.assertEqual(target.read_bytes(), b"new")
            with self.client.open_writer(as_existing=target, **options, **to) as out:
                out.write(b"updated")
            with self.assertRaises(ValueError):
                with self.client.open_writer(as_existing=target, **options, **to) as out:
                    out.write(b"aborted")
                    raise ValueError("producer failed")
            self.assertEqual(target.read_bytes(), b"updated")
            with self.assertRaises(syq.SyqProcessError):
                with self.client.open_writer(as_existing=base / "missing", **options, **to):
                    pass
            for name in ("cwd", "root"):
                with self.client.open_reader("object", **{name: base}, **options, **from_) as input:
                    self.assertEqual(input.read(), b"updated")
            with self.assertRaises(syq.SyqProcessError):
                with self.client.open_reader("../rsh", root=base, **options, **from_) as input:
                    input.read()
        with self.assertRaises(syq.SyqInvocationError):
            self.client.open_writer()
        with self.assertRaises(syq.SyqInvocationError):
            self.client.open_writer(as_=target, as_new=target)
        with self.assertRaises(syq.SyqInvocationError):
            self.client.open_reader("object", cwd=base, root=base)

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
        options = dict(rsh=str(rsh), syq_path=str(SYQ), no_tcp=True)
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
        fixtures = Path(__file__).resolve().parents[3] / "tests/fixtures/automation/success.ndjson"
        records = [json.loads(line) for line in fixtures.read_text().splitlines()]
        run, terminal = records[0], records[-1]
        run["mapping"] = False
        terminal["seq"] = 1
        result_bytes = (json.dumps(run) + "\n" + json.dumps(terminal) + "\n").encode()
        fake.write_text(f'#!{sys.executable}\nimport os, signal, sys\n'
                        f'os.write(int(sys.argv[sys.argv.index("--results-fd") + 1]), {result_bytes!r})\n'
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
        fake.write_text(ready_stub())
        fake.chmod(0o700)
        client = syq.Client(executable=fake, timeout=.1)
        with self.assertRaises(subprocess.TimeoutExpired):
            with client.open_writer(as_='ignored') as output:
                output.write(b'x' * (1 << 20))
        self.assertIsNotNone(output._process.process.poll())


class AsyncStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_placement_and_confined_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "object"
            client = syq.AsyncClient(executable=SYQ, timeout=10,
                                     env={k: v for k, v in os.environ.items() if not k.startswith("SYQ_")})
            async with client.open_writer(as_new=target) as out:
                await out.write(b"new")
            with self.assertRaises(syq.SyqProcessError):
                async with client.open_writer(as_new=target) as out:
                    await out.write(b"no")
            async with client.open_writer(as_existing=target) as out:
                await out.write(b"existing")
            async with client.open_reader("object", root=root) as input:
                self.assertEqual(await input.read(), b"existing")
            with self.assertRaises(syq.SyqInvocationError):
                async with client.open_writer(as_=target, as_new=target):
                    pass
            with self.assertRaises(syq.SyqProcessError):
                async with client.open_reader("../outside", root=root) as input:
                    await input.read()

    async def test_round_trip_and_cancelled_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            client = syq.AsyncClient(executable=SYQ, timeout=10)
            async with client.open_writer(as_=root / 'file') as output:
                await output.write(b'async bytes')
            async with client.open_reader(root / 'file') as input:
                self.assertEqual(await input.read(), b'async bytes')
            fake = root / 'slow-syq'
            fake.write_text(ready_stub())
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
            fake.write_text(ready_stub())
            fake.chmod(0o700)
            output = syq.AsyncClient(executable=fake).open_writer(as_='ignored')
            await output.__aenter__()
            task = asyncio.create_task(output.commit())
            await asyncio.sleep(.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 10)
            self.assertIsNotNone(output._stream._process.process.poll())
