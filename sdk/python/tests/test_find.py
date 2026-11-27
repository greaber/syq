from __future__ import annotations

import asyncio
import errno
import http.server
import json
import os
import sys
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

import syq
from support import (
    assert_descendant_exited,
    async_assert_descendant_exited,
    resolved_temporary_directory,
    warm_executable,
)
from syq.protocol import parse_find_line

try:
    from test_native import FAKE_NATIVE
except ModuleNotFoundError:
    from sdk.python.tests.test_native import FAKE_NATIVE


class S3ListingServer:
    """Minimal S3 server tracking requests for find/ls tests."""

    def __init__(self, objects: dict[str, bytes]) -> None:
        self.objects = dict(objects)
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def reply(
                self, code: int, body: bytes = b"", headers: list[tuple[str, str]] = ()
            ) -> None:
                owner.requests.append(
                    (
                        self.command,
                        self.path,
                        {key.lower(): value for key, value in self.headers.items()},
                    )
                )
                self.send_response(code)
                if not any(key.lower() == "content-length" for key, _ in headers):
                    self.send_header("Content-Length", str(len(body)))
                for key, value in headers:
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_HEAD(self) -> None:
                key = urllib.parse.unquote(
                    urllib.parse.urlsplit(self.path).path.removeprefix("/bucket/")
                )
                payload = owner.objects.get(key)
                if payload is None:
                    self.reply(404)
                    return
                self.reply(
                    200,
                    b"",
                    [
                        ("Content-Length", str(len(payload))),
                        ("ETag", '"head-etag"'),
                        ("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT"),
                        ("x-amz-meta-syq-format", "1"),
                        ("x-amz-meta-syq-kind", "file"),
                        ("x-amz-meta-syq-mode", str(0o640)),
                        ("x-amz-meta-syq-uid", "1000"),
                        ("x-amz-meta-syq-gid", "1001"),
                        ("x-amz-meta-syq-mtime", "1700000123"),
                        ("x-amz-meta-syq-mtime-nsec", "0"),
                    ],
                )

            def do_GET(self) -> None:
                parsed = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if "list-type" not in query:
                    self.reply(404)
                    return
                prefix = query.get("prefix", [""])[0]
                delimiter = query.get("delimiter", [None])[0]
                max_keys = int(query.get("max-keys", ["1000"])[0])
                matching = sorted(
                    key for key in owner.objects if key.startswith(prefix)
                )
                contents: list[str] = []
                prefixes: list[str] = []
                seen_prefixes: set[str] = set()
                items: list[tuple[str, str]] = []
                for key in matching:
                    rest = key[len(prefix) :]
                    if delimiter and delimiter in rest:
                        child_prefix = (
                            prefix + rest.split(delimiter, 1)[0] + delimiter
                        )
                        if child_prefix not in seen_prefixes:
                            seen_prefixes.add(child_prefix)
                            items.append(("prefix", child_prefix))
                    else:
                        items.append(("key", key))
                items.sort(key=lambda item: item[1])
                truncated = len(items) > max_keys
                for kind, value in items[:max_keys]:
                    if kind == "prefix":
                        prefixes.append(value)
                    else:
                        contents.append(value)
                body_parts = [
                    "<ListBucketResult>",
                    "<EncodingType>url</EncodingType>",
                    f"<Prefix>{urllib.parse.quote(prefix, safe='')}</Prefix>",
                    f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>",
                ]
                if truncated:
                    body_parts.append("<NextContinuationToken>next</NextContinuationToken>")
                for key in contents:
                    size = len(owner.objects[key])
                    quoted = urllib.parse.quote(key, safe="")
                    body_parts.append(
                        f"<Contents><Key>{quoted}</Key>"
                        "<LastModified>2026-01-01T00:00:00.000Z</LastModified>"
                        '<ETag>"list-etag"</ETag>'
                        f"<Size>{size}</Size></Contents>"
                    )
                for child_prefix in prefixes:
                    quoted = urllib.parse.quote(child_prefix, safe="")
                    body_parts.append(
                        f"<CommonPrefixes><Prefix>{quoted}</Prefix></CommonPrefixes>"
                    )
                body_parts.append("</ListBucketResult>")
                self.reply(200, "".join(body_parts).encode("utf-8"))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> S3ListingServer:
        return self

    def __exit__(self, *args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class FindProtocolTests(unittest.TestCase):
    def test_parse_find_line_valid_and_bounds(self) -> None:
        full = json.dumps({
            "path": "src/main.rs",
            "kind": "symlink",
            "size": 1824,
            "mtime": -5,
            "s3_last_modified": 1700000000,
            "etag": '"abc"',
            "mode": 0o755,
            "uid": 0,
            "gid": (1 << 32) - 1,
            "ctime": 1700000001,
            "link_target": "other.rs",
        }).encode("utf-8")
        entry = parse_find_line(full)
        self.assertEqual(
            entry,
            syq.FindEntry(
                path="src/main.rs",
                kind="symlink",
                size=1824,
                mtime=-5,
                s3_last_modified=1700000000,
                etag='"abc"',
                mode=0o755,
                uid=0,
                gid=(1 << 32) - 1,
                ctime=1700000001,
                link_target="other.rs",
            ),
        )
        for kind in ("file", "dir", "symlink", "fifo", "socket", "char", "block", "other"):
            parsed = parse_find_line(json.dumps({"path": "x", "kind": kind}).encode())
            self.assertEqual(parsed.kind, kind)

    def test_parse_find_line_rejects_malformed_records(self) -> None:
        cases = (
            (b"not-json", "valid UTF-8 JSON"),
            (b"[]", "JSON object"),
            ('{"path":"a"}'.encode("utf-16"), "valid UTF-8 JSON"),
            (b'{"path":"\\ud800"}', "unpaired Unicode surrogates"),
            (b'{"path":"a","etag":"\\ud800"}', "unpaired Unicode surrogates"),
            (b'{"path":"a","link_target":"\\ud800"}', "unpaired Unicode surrogates"),
            (b'{"path": "a", "extra": 1}', "unknown field 'extra'"),
            (b"{}", "field 'path' must be a string"),
            (b'{"path": ""}', "may not be empty"),
            (b'{"path": "a", "kind": "device"}', "unsupported"),
            (b'{"path": "a", "size": -1}', "must not be negative"),
            (b'{"path": "a", "size": true}', "must be an integer"),
            (json.dumps({"path": "a", "size": 1 << 64}).encode(), "unsigned 64-bit"),
            (json.dumps({"path": "a", "mtime": 1 << 63}).encode(), "signed 64-bit"),
            (b'{"path": "a", "mode": 4096}', "exceeds 0o7777"),
            (json.dumps({"path": "a", "uid": 1 << 32}).encode(), "unsigned 32-bit"),
            (json.dumps({"path": "a", "gid": 1 << 32}).encode(), "unsigned 32-bit"),
            (b'{"path": "a", "etag": 123}', "must be a string"),
            (b'{"path": "a", "link_target": null}', "must be a string"),
        )
        for line, message in cases:
            with self.subTest(line=line[:40]):
                with self.assertRaisesRegex(syq.SyqProtocolError, message):
                    parse_find_line(line)

        oversized_digits = b'{"path":"a","size":' + b"1" * 5000 + b"}"
        if hasattr(sys, "set_int_max_str_digits"):
            previous = sys.get_int_max_str_digits()
            try:
                sys.set_int_max_str_digits(4300)
                with self.assertRaisesRegex(syq.SyqProtocolError, "valid UTF-8 JSON"):
                    parse_find_line(oversized_digits)
                sys.set_int_max_str_digits(0)
                with self.assertRaisesRegex(syq.SyqProtocolError, "unsigned 64-bit"):
                    parse_find_line(oversized_digits)
            finally:
                sys.set_int_max_str_digits(previous)
        else:
            with self.assertRaisesRegex(syq.SyqProtocolError, "unsigned 64-bit"):
                parse_find_line(oversized_digits)


class FakeFindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._executable_dir = resolved_temporary_directory()
        cls.addClassCleanup(cls._executable_dir.cleanup)
        cls._shared_executable = Path(cls._executable_dir.name) / "syq"
        cls._shared_executable.write_text(FAKE_NATIVE, encoding="utf-8")
        cls._shared_executable.chmod(0o755)
        warm_executable(cls._shared_executable, "--version")

    def setUp(self) -> None:
        self.temporary_directory = resolved_temporary_directory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.executable = self._shared_executable
        self.argv_log = self.root / "argv.json"
        self.env = {**os.environ, "SYQ_FAKE_ARGV": os.fspath(self.argv_log)}
        self.client = syq.Client(executable=self.executable, env=self.env)

    def argv(self) -> list[str]:
        return json.loads(self.argv_log.read_text(encoding="utf-8"))

    def test_sync_find_and_ls_forward_all_options_and_protect_positionals(self) -> None:
        with self.client.find(
            "--rsh=evil",
            "-l",
            "-",
            on="user@server",
            cwd="-base",
            follow=True,
            follow_src=True,
            depth=2,
            ignore=[syq.IgnoreFrom("-rules"), "-keep.tmp"],
            ignore_from=["more.rules"],
            where="-1 < size",
            include=["kind", "ctime", "link_target"],
            rsh="-ssh",
            syq_path="-helper",
            auth_from="-@laptop",
            pscope="-scope",
        ) as stream:
            entries = list(stream)
        self.assertEqual(
            entries,
            [syq.FindEntry(path="a.txt", kind="file", size=3, mtime=100)],
        )
        argv = self.argv()
        self.assertEqual(argv[:2], ["find", "--json"])
        for expected in (
            "--on",
            "user@server",
            "--cwd=-base",
            "--follow",
            "--follow-src",
            "--depth",
            "2",
            "--ignore-from=-rules",
            "--ignore=-keep.tmp",
            "--ignore-from",
            "more.rules",
            "--where=-1 < size",
            "--include=kind",
            "--include=ctime",
            "--include=link_target",
            "--rsh=-ssh",
            "--syq-path=-helper",
            "--auth-from=-@laptop",
            "--pscope=-scope",
        ):
            self.assertIn(expected, argv)
        separator = argv.index("--")
        self.assertEqual(argv[separator + 1 :], ["--rsh=evil", "-l", "-"])

        with self.client.ls(
            on="s3://bucket",
            root="prefix",
            depth=3,
            include=["s3_last_modified", "etag"],
            performance_tuning="s3-requests=4",
            s3_endpoint="https://objects.example",
            s3_region="auto",
            s3_profile="archive",
            s3_header=["X-Test: a:b"],
            s3_retries=2,
        ) as ls_stream:
            self.assertEqual(len(list(ls_stream)), 1)
        ls_argv = self.argv()
        self.assertEqual(ls_argv[:2], ["ls", "--json"])
        for expected in (
            "--on",
            "s3://bucket",
            "--root",
            "prefix",
            "--depth",
            "3",
            "--include=s3_last_modified",
            "--include=etag",
            "--performance-tuning",
            "s3-requests=4",
            "--s3-endpoint=https://objects.example",
            "--s3-region=auto",
            "--s3-profile=archive",
            "--s3-header=X-Test: a:b",
            "--s3-retries=2",
        ):
            self.assertIn(expected, ls_argv)

    def test_module_level_functions_work_with_mocked_bundled(self) -> None:
        self.assertLessEqual(
            {"find", "ls", "FindEntry", "FindStream", "AsyncFindStream"},
            set(syq.__all__),
        )
        env = {**os.environ, "SYQ_FAKE_ARGV": os.fspath(self.argv_log)}
        with mock.patch("syq.client.bundled_executable", return_value=self.executable), \
                mock.patch.dict(os.environ, env):
            with syq.find("src") as found:
                self.assertEqual([entry.path for entry in found], ["a.txt"])
            with syq.ls("src") as listed:
                self.assertEqual([entry.path for entry in listed], ["a.txt"])

    def test_prelaunch_validation_rejects_invalid_inputs_before_spawn(self) -> None:
        self.argv_log.unlink(missing_ok=True)
        invalid_calls = (
            (dict(on=""), "empty"),
            (dict(cwd="a", root="b"), "mutually exclusive"),
            (dict(on="s3://bucket", follow=True), "filesystem endpoint"),
            (dict(on="s3://bucket", follow_src=True), "filesystem endpoint"),
            (dict(depth=0), "positive"),
            (dict(depth=-1), "non-negative"),
            (dict(depth=True), "non-negative"),
            (dict(where=123), "string"),
            (dict(include="kind"), "iterable"),
            (dict(include=[]), "at least one field"),
            (dict(include=["bogus"]), "unknown find field"),
            (dict(include=["etag"]), "S3 endpoint"),
            (dict(include=["s3_last_modified"]), "S3 endpoint"),
            (dict(on="s3://bucket", include=["ctime"]), "filesystem endpoint"),
            (dict(on="s3://bucket", include=["link_target"]), "filesystem endpoint"),
            (dict(performance_tuning="s3-requests=2"), "S3 listings"),
            (dict(on="s3://bucket", performance_tuning=True), "string"),
            (dict(auth_from="@laptop"), "SSH endpoint"),
            (dict(rsh="ssh"), "SSH endpoint"),
            (dict(syq_path="/opt/syq"), "SSH endpoint"),
            (dict(no_bootstrap=True), "SSH endpoint"),
            (dict(pscope="scope"), "SSH endpoint"),
            (dict(on="s3://bucket", auth_from="@laptop"), "SSH endpoint"),
            (dict(on="server", syq_path="/opt/syq", no_bootstrap=True), "conflict"),
            (dict(s3_endpoint="http://x"), "on='s3://BUCKET'"),
            (dict(s3_region="us-east-1"), "on='s3://BUCKET'"),
            (dict(s3_profile="p"), "on='s3://BUCKET'"),
            (dict(s3_header=["X: 1"]), "on='s3://BUCKET'"),
            (dict(s3_retries=1), "on='s3://BUCKET'"),
            (dict(on="s3://bucket", s3_retries=101), "s3_retries"),
            (dict(on="s3://bucket", s3_retries=True), "s3_retries"),
            (dict(follow="yes"), "boolean"),
        )
        for kwargs, message in invalid_calls:
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(syq.SyqInvocationError, message):
                    self.client.find(**kwargs)
                with self.assertRaisesRegex(syq.SyqInvocationError, message):
                    self.client.ls(**kwargs)
        for bad_path in (b"nul\0byte", "bad\0where"):
            with self.assertRaises(ValueError):
                self.client.find(bad_path)
        with self.assertRaises(ValueError):
            self.client.find(where="a\0b")
        self.assertFalse(self.argv_log.exists())

    def test_nonzero_exit_bounds_stderr_and_rejects_reuse(self) -> None:
        failing = syq.Client(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_EXIT": "1",
                "SYQ_FAKE_STDERR_BYTES": str(32 * 1024),
            },
        )
        with failing.find() as stream:
            first = next(stream)
            self.assertEqual(first.path, "a.txt")
            with self.assertRaises(syq.SyqProtocolError) as caught:
                next(stream)
        self.assertEqual(caught.exception.returncode, 1)
        self.assertEqual(caught.exception.stderr, b"x" * 8192)
        with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
            iter(stream)

        malformed = syq.Client(
            executable=self.executable,
            env={**self.env, "SYQ_FAKE_SHAPE": "bad-find-json"},
        )
        with self.assertRaisesRegex(syq.SyqProtocolError, "valid UTF-8 JSON"):
            with malformed.ls() as ls_stream:
                list(ls_stream)

        oversized = syq.Client(
            executable=self.executable,
            env={**self.env, "SYQ_FAKE_SHAPE": "oversized-line"},
        )
        with self.assertRaisesRegex(syq.SyqProtocolError, "larger than 16 MiB"):
            with oversized.find() as oversized_stream:
                list(oversized_stream)

    def test_early_context_exit_kills_process_group(self) -> None:
        marker = self.root / "find-descendant"
        client = syq.Client(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_DESCENDANT": os.fspath(marker),
                "SYQ_FAKE_PAUSE": "10",
            },
        )
        with client.find("src"):
            deadline = time.monotonic() + 2
            while not marker.with_suffix(".ready").exists():
                if time.monotonic() >= deadline:
                    self.fail("fake syq find did not become ready")
                time.sleep(0.01)
        assert_descendant_exited(self, marker)


class AsyncFakeFindTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._executable_dir = resolved_temporary_directory()
        cls.addClassCleanup(cls._executable_dir.cleanup)
        cls._shared_executable = Path(cls._executable_dir.name) / "syq"
        cls._shared_executable.write_text(FAKE_NATIVE, encoding="utf-8")
        cls._shared_executable.chmod(0o755)
        warm_executable(cls._shared_executable, "--version")

    def setUp(self) -> None:
        self.temporary_directory = resolved_temporary_directory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.executable = self._shared_executable
        self.argv_log = self.root / "argv.json"
        self.env = {**os.environ, "SYQ_FAKE_ARGV": os.fspath(self.argv_log)}
        self.client = syq.AsyncClient(executable=self.executable, env=self.env)

    def argv(self) -> list[str]:
        return json.loads(self.argv_log.read_text(encoding="utf-8"))

    async def test_lazy_async_stream_snapshots_client_state_and_rejects_reuse(self) -> None:
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        first_dir.mkdir()
        second_dir.mkdir()
        seen_cwd = first_dir / "cwd.txt"
        script = first_dir / "check-syq"
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['SEEN_CWD']).write_text(os.getcwd())\n"
            "print(json.dumps({'path': 'a', 'kind': 'file', 'size': 1, 'mtime': 2}))\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        env = {**self.env, "SEEN_CWD": os.fspath(seen_cwd)}
        client = syq.AsyncClient(
            executable=script, process_cwd=first_dir, env=env, timeout=5
        )
        stream = client.find("target")
        self.assertFalse(seen_cwd.exists(), "async find started before consumption")
        client.process_cwd = second_dir
        env["SEEN_CWD"] = os.fspath(second_dir / "wrong.txt")
        client.timeout = 0
        async with stream:
            items = [item async for item in stream]
        self.assertEqual([item.path for item in items], ["a"])
        self.assertEqual(seen_cwd.read_text(), os.fspath(first_dir))
        self.assertFalse((second_dir / "wrong.txt").exists())
        with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
            async with stream:
                pass
        with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
            aiter(stream)

    async def test_concurrent_aclose_during_startup_aborts_process(self) -> None:
        stream = self.client.find("src")
        started = asyncio.Event()
        proceed = asyncio.Event()
        fake_process = mock.Mock()
        fake_process.abort = mock.AsyncMock()
        calls = 0

        async def paused_start(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            started.set()
            await proceed.wait()
            return fake_process

        with mock.patch.object(
            stream._client, "_start_line", side_effect=paused_start
        ):
            enter_task = asyncio.create_task(stream.__aenter__())
            await asyncio.wait_for(started.wait(), timeout=2)
            close_task = asyncio.create_task(stream.aclose())
            await asyncio.sleep(0)
            proceed.set()
            entered = await enter_task
            await close_task
        self.assertIs(entered, stream)
        fake_process.abort.assert_awaited_once()
        self.assertEqual(calls, 1)
        with self.assertRaises(StopAsyncIteration):
            await anext(stream)
        with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
            async with stream:
                pass
        self.assertEqual(calls, 1)

    async def test_cancelled_aclose_allows_retry_of_abort(self) -> None:
        stream = self.client.find("src")
        abort_started = asyncio.Event()
        release_abort = asyncio.Event()
        abort_calls = 0

        async def blocked_then_ok_abort() -> None:
            nonlocal abort_calls
            abort_calls += 1
            if abort_calls == 1:
                abort_started.set()
                await release_abort.wait()

        fake_process = mock.Mock()
        fake_process.abort = mock.AsyncMock(side_effect=blocked_then_ok_abort)

        with mock.patch.object(
            stream._client, "_start_line", new=mock.AsyncMock(return_value=fake_process)
        ):
            await stream.__aenter__()
            close_task = asyncio.create_task(stream.aclose())
            await asyncio.wait_for(abort_started.wait(), timeout=2)
            close_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await close_task
            self.assertFalse(stream._complete)
            self.assertEqual(abort_calls, 1)

            release_abort.set()
            await stream.aclose()

        self.assertTrue(stream._complete)
        self.assertEqual(abort_calls, 2)
        with self.assertRaises(StopAsyncIteration):
            await anext(stream)
        with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
            async with stream:
                pass

    async def test_async_find_nonzero_exit_and_early_exit_cleanup(self) -> None:
        failing = syq.AsyncClient(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_EXIT": "1",
                "SYQ_FAKE_STDERR_BYTES": str(16 * 1024),
            },
        )
        async with failing.ls() as stream:
            first = await anext(stream)
            self.assertEqual(first.path, "a.txt")
            with self.assertRaises(syq.SyqProtocolError) as caught:
                await anext(stream)
        self.assertEqual(caught.exception.returncode, 1)
        self.assertEqual(caught.exception.stderr, b"x" * 8192)

        marker = self.root / "async-find-descendant"
        slow = syq.AsyncClient(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_DESCENDANT": os.fspath(marker),
                "SYQ_FAKE_PAUSE": "10",
            },
        )
        async with slow.find("src"):
            deadline = time.monotonic() + 2
            while not marker.with_suffix(".ready").exists():
                if time.monotonic() >= deadline:
                    self.fail("fake syq find did not become ready")
                await asyncio.sleep(0.01)
        await async_assert_descendant_exited(self, marker)


EXECUTABLE = os.environ.get("SYQ_CANDIDATE_EXECUTABLE")


@unittest.skipUnless(EXECUTABLE, "candidate binary required")
class CandidateFindTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = resolved_temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.client = syq.Client(executable=EXECUTABLE, process_cwd=self.root)
        self.async_client = syq.AsyncClient(executable=EXECUTABLE, process_cwd=self.root)

    def test_sync_and_async_local_find_and_ls(self) -> None:
        tree = self.root / "tree"
        (tree / "sub/deep").mkdir(parents=True)
        (tree / "top.txt").write_bytes(b"hello")
        (tree / "skip.tmp").write_bytes(b"ignored")
        (tree / "sub/keep.tmp").write_bytes(b"kept")
        (tree / "sub/deep/leaf.txt").write_bytes(b"leaf")
        (tree / "link").symlink_to("top.txt")
        (self.root / "rules").write_text("*.tmp\n", encoding="utf-8")

        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                if asynchronous:
                    async def run_async() -> tuple[list[syq.FindEntry], list[syq.FindEntry]]:
                        async with self.async_client.find("tree") as f:
                            all_items = [entry async for entry in f]
                        async with self.async_client.ls("tree") as l:
                            top_items = [entry async for entry in l]
                        return all_items, top_items

                    all_entries, ls_entries = asyncio.run(run_async())
                else:
                    with self.client.find("tree") as f:
                        all_entries = list(f)
                    with self.client.ls("tree") as l:
                        ls_entries = list(l)

                all_by_path = {entry.path: entry for entry in all_entries}
                self.assertEqual(
                    set(all_by_path),
                    {
                        "tree/link",
                        "tree/skip.tmp",
                        "tree/sub",
                        "tree/sub/deep",
                        "tree/sub/deep/leaf.txt",
                        "tree/sub/keep.tmp",
                        "tree/top.txt",
                    },
                )
                self.assertEqual(all_by_path["tree/top.txt"].kind, "file")
                self.assertEqual(all_by_path["tree/top.txt"].size, 5)
                self.assertIsInstance(all_by_path["tree/top.txt"].mtime, int)
                self.assertEqual(all_by_path["tree/sub"].kind, "dir")
                self.assertIsNone(all_by_path["tree/sub"].size)
                self.assertEqual(all_by_path["tree/link"].kind, "symlink")

                self.assertEqual(
                    {entry.path for entry in ls_entries},
                    {"tree/link", "tree/skip.tmp", "tree/sub", "tree/top.txt"},
                )

        with self.client.find(
            "tree",
            depth=2,
            ignore=[syq.IgnoreFrom("rules"), "!sub/keep.tmp"],
        ) as filtered_depth:
            self.assertEqual(
                {entry.path for entry in filtered_depth},
                {
                    "tree/link",
                    "tree/sub",
                    "tree/sub/deep",
                    "tree/sub/keep.tmp",
                    "tree/top.txt",
                },
            )

        with self.client.find(
            "tree",
            where='kind = "file" and extension = "txt" and size > 4B',
        ) as where_stream:
            self.assertEqual(
                {entry.path for entry in where_stream},
                {"tree/top.txt"},
            )

        with self.client.ls(
            root=tree,
            include=["kind", "mode", "uid", "gid", "ctime", "link_target"],
        ) as detailed:
            by_path = {entry.path: entry for entry in detailed}
        self.assertEqual(by_path["link"].link_target, "top.txt")
        self.assertIsNone(by_path["link"].size)
        self.assertIsInstance(by_path["top.txt"].mode, int)
        self.assertIsInstance(by_path["top.txt"].uid, int)
        self.assertIsInstance(by_path["top.txt"].gid, int)
        self.assertIsInstance(by_path["top.txt"].ctime, int)

        (self.root / "alias").symlink_to(tree, target_is_directory=True)
        with self.client.ls("alias", follow=True) as followed:
            self.assertIn("alias/top.txt", {entry.path for entry in followed})

        with self.client.find("tree", cwd=self.root) as rooted:
            self.assertIn("tree/top.txt", {entry.path for entry in rooted})

    def test_literal_hyphen_filenames_do_not_inject_options(self) -> None:
        (self.root / "--long").write_bytes(b"a")
        (self.root / "-d").write_bytes(b"b")
        with self.client.ls("--long", "-d") as stream:
            self.assertEqual([entry.path for entry in stream], ["--long", "-d"])

    def test_unreadable_directory_raises_after_streaming_entries(self) -> None:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root ignores directory read permissions")
        tree = self.root / "perm"
        (tree / "locked").mkdir(parents=True)
        (tree / "locked/secret").write_bytes(b"x")
        (tree / "visible").write_bytes(b"ok")
        (tree / "locked").chmod(0o000)
        self.addCleanup(lambda: (tree / "locked").chmod(0o700))

        seen: list[str] = []
        with self.assertRaises(syq.SyqProtocolError) as caught:
            with self.client.find("perm") as stream:
                for entry in stream:
                    seen.append(entry.path)
        self.assertIn("perm/visible", seen)
        self.assertNotEqual(caught.exception.returncode, 0)
        self.assertTrue(caught.exception.stderr)

    def test_non_utf8_filename_fails_cleanly(self) -> None:
        raw_path = os.fsencode(self.root) + b"/raw-\xff"
        try:
            fd = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as error:
            if error.errno == errno.EILSEQ:
                self.skipTest("temporary filesystem rejects non-UTF-8 filenames")
            raise
        os.close(fd)
        with self.assertRaises(syq.SyqProtocolError) as caught:
            with self.client.ls() as stream:
                list(stream)
        self.assertNotEqual(caught.exception.returncode, 0)
        self.assertIn(b"not valid UTF-8", caught.exception.stderr)

    def test_sync_and_async_s3_find_and_ls(self) -> None:
        with S3ListingServer(
            {
                "photos/a.jpg": b"12345",
                "photos/2026/b.jpg": b"12",
            }
        ) as server:
            env = os.environ | {
                "AWS_ACCESS_KEY_ID": "fixture",
                "AWS_SECRET_ACCESS_KEY": "fixture",
                "AWS_EC2_METADATA_DISABLED": "true",
                "AWS_CONFIG_FILE": str(self.root / "no-config"),
                "AWS_SHARED_CREDENTIALS_FILE": str(self.root / "no-credentials"),
            }
            for key in ("AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"):
                env.pop(key, None)
            s3_client = syq.Client(executable=EXECUTABLE, process_cwd=self.root, env=env, timeout=10)
            s3_async = syq.AsyncClient(executable=EXECUTABLE, process_cwd=self.root, env=env, timeout=10)

            with s3_client.find(
                "photos/",
                on="s3://bucket",
                s3_endpoint=server.endpoint,
                s3_region="us-east-1",
                s3_header=["X-Listing: yes"],
                s3_retries=0,
                performance_tuning="s3-requests=1",
            ) as found:
                entries = list(found)
            by_path = {entry.path: entry for entry in entries}
            self.assertEqual(set(by_path), {"photos/a.jpg", "photos/2026", "photos/2026/b.jpg"})
            self.assertEqual(by_path["photos/a.jpg"].size, 5)
            self.assertEqual(by_path["photos/a.jpg"].etag, '"list-etag"')
            self.assertIsInstance(by_path["photos/a.jpg"].s3_last_modified, int)
            self.assertIsNone(by_path["photos/a.jpg"].mtime)
            self.assertIsNone(by_path["photos/2026"].size)
            self.assertFalse(
                any(method == "HEAD" for method, _, _ in server.requests),
                server.requests,
            )
            self.assertTrue(
                all(headers.get("x-listing") == "yes" for _, _, headers in server.requests)
            )

            server.requests.clear()

            async def async_ls() -> list[syq.FindEntry]:
                async with s3_async.ls(
                    "photos/",
                    on="s3://bucket",
                    s3_endpoint=server.endpoint,
                    s3_region="us-east-1",
                ) as listed:
                    return [entry async for entry in listed]

            ls_entries = asyncio.run(async_ls())
            self.assertEqual({entry.path for entry in ls_entries}, {"photos/a.jpg", "photos/2026"})
            self.assertFalse(
                any(method == "HEAD" for method, _, _ in server.requests),
                server.requests,
            )

            server.requests.clear()
            with s3_client.ls(
                "photos/",
                on="s3://bucket",
                s3_endpoint=server.endpoint,
                s3_region="us-east-1",
                include=["kind", "mode", "uid", "gid", "mtime"],
            ) as with_head:
                head_by_path = {entry.path: entry for entry in with_head}
            self.assertEqual(head_by_path["photos/a.jpg"].mode, 0o640)
            self.assertEqual(head_by_path["photos/a.jpg"].uid, 1000)
            self.assertEqual(head_by_path["photos/a.jpg"].gid, 1001)
            self.assertEqual(head_by_path["photos/a.jpg"].mtime, 1700000123)
            self.assertTrue(any(method == "HEAD" for method, _, _ in server.requests))


if __name__ == "__main__":
    unittest.main()
