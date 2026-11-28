from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import syq
from support import (
    assert_descendant_exited,
    resolved_temporary_directory,
    warm_executable,
)


class ProcessGroupCleanupTests(unittest.TestCase):
    def test_exited_mapping_process_can_be_closed_without_consuming_output(self):
        from syq.client import _LineProcess

        # Leave the exited leader unreaped, as an abandoned mapping can do.
        # On Darwin, signalling its zombie-only group may return EPERM.
        for _ in range(10):
            process = _LineProcess(
                (sys.executable, "-c", "print('unconsumed mapping')"),
                cwd=None, env=None, timeout=5,
            )
            try:
                process._stderr_thread.join(timeout=5)
                self.assertFalse(process._stderr_thread.is_alive())
            finally:
                process.abort()
            self.assertIsNotNone(process.returncode)
            self.assertTrue(process._closed)

    def test_permission_error_reaps_exited_leader_and_retries_group(self):
        from syq.client import _kill_process_group

        # A leader still finishing its exit is not yet reaped by poll(), but a
        # brief wait reaps it.
        process = mock.Mock(
            pid=123, poll=mock.Mock(return_value=None), wait=mock.Mock(return_value=0)
        )
        for retry in (None, ProcessLookupError()):
            with self.subTest(retry=retry), mock.patch(
                "syq.client.os.killpg", side_effect=[PermissionError(), retry]
            ) as kill:
                _kill_process_group(process)
                self.assertEqual(kill.call_args_list, [
                    mock.call(123, signal.SIGKILL), mock.call(123, signal.SIGKILL),
                ])

    def test_permission_error_waits_for_transient_zombie_descendant_reap(self):
        from syq.client import _kill_process_group

        process = mock.Mock(pid=123, wait=mock.Mock(return_value=0))
        for final in (None, ProcessLookupError()):
            with self.subTest(final=final), mock.patch(
                "syq.client._REAP_RETRY_INTERVAL", 0.001
            ), mock.patch(
                "syq.client.os.killpg",
                side_effect=[PermissionError(), PermissionError(), final],
            ) as kill:
                _kill_process_group(process)
                self.assertEqual(kill.call_args_list, [
                    mock.call(123, signal.SIGKILL),
                    mock.call(123, signal.SIGKILL),
                    mock.call(123, signal.SIGKILL),
                ])

    def test_permission_errors_for_live_or_remaining_group_are_visible(self):
        from syq.client import _kill_process_group

        live = subprocess.TimeoutExpired("syq", 0.5)
        for wait, min_attempts in ((live, 1), (0, 2)):
            with self.subTest(wait=wait), mock.patch(
                "syq.client._REAP_RETRY_TIMEOUT", 0.01
            ), mock.patch(
                "syq.client._REAP_RETRY_INTERVAL", 0.001
            ), mock.patch(
                "syq.client.os.killpg", side_effect=PermissionError("denied")
            ) as kill:
                process = mock.Mock(pid=123, wait=mock.Mock(side_effect=[wait]))
                with self.assertRaisesRegex(PermissionError, "denied"):
                    _kill_process_group(process)
                if wait is live:
                    self.assertEqual(kill.call_count, 1)
                else:
                    self.assertGreaterEqual(kill.call_count, min_attempts)
                process.wait.assert_called_once_with(timeout=0.5)

    def test_stream_kill_group_retries_transient_zombie_descendant_eperm(self):
        from syq._streams import _kill_group

        process = mock.Mock(pid=123, wait=mock.Mock(return_value=0))
        with mock.patch("syq.client._REAP_RETRY_INTERVAL", 0.001), mock.patch(
            "syq.client.os.killpg",
            side_effect=[PermissionError(), PermissionError(), ProcessLookupError()],
        ) as kill:
            _kill_group(process)
            self.assertEqual(kill.call_count, 3)


class AsyncProcessGroupCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_permission_error_reaps_exited_leader_and_retries_group(self):
        from syq.async_client import _kill_process_group

        process = mock.Mock(pid=123, returncode=None)
        process.wait = mock.AsyncMock(return_value=0)
        for retry in (None, ProcessLookupError()):
            with self.subTest(retry=retry), mock.patch(
                "syq.async_client.os.killpg", side_effect=[PermissionError(), retry]
            ) as kill:
                await _kill_process_group(process)
                self.assertEqual(kill.call_args_list, [
                    mock.call(123, signal.SIGKILL), mock.call(123, signal.SIGKILL),
                ])

    async def test_permission_error_waits_for_transient_zombie_descendant_reap(self):
        from syq.async_client import _kill_process_group

        process = mock.Mock(pid=123, returncode=0)
        process.wait = mock.AsyncMock(return_value=0)
        for final in (None, ProcessLookupError()):
            with self.subTest(final=final), mock.patch(
                "syq.async_client._REAP_RETRY_INTERVAL", 0.001
            ), mock.patch(
                "syq.async_client.os.killpg",
                side_effect=[PermissionError(), PermissionError(), final],
            ) as kill:
                await _kill_process_group(process)
                self.assertEqual(kill.call_args_list, [
                    mock.call(123, signal.SIGKILL),
                    mock.call(123, signal.SIGKILL),
                    mock.call(123, signal.SIGKILL),
                ])

    async def test_live_or_remaining_group_permission_error_is_visible(self):
        from syq.async_client import _kill_process_group

        for wait_result, is_live in ((asyncio.TimeoutError(), True), (0, False)):
            process = mock.Mock(pid=123, returncode=None)
            process.wait = mock.AsyncMock(side_effect=[wait_result])
            with self.subTest(is_live=is_live), mock.patch(
                "syq.async_client._REAP_RETRY_TIMEOUT", 0.01
            ), mock.patch(
                "syq.async_client._REAP_RETRY_INTERVAL", 0.001
            ), mock.patch(
                "syq.async_client.os.killpg", side_effect=PermissionError("denied")
            ) as kill:
                with self.assertRaisesRegex(PermissionError, "denied"):
                    await _kill_process_group(process)
                if is_live:
                    self.assertEqual(kill.call_count, 1)
                else:
                    self.assertGreaterEqual(kill.call_count, 2)
                process.wait.assert_awaited_once()


FAKE_SYQ = f"""#!{sys.executable}
import fcntl
import os
import sys
import time

command = sys.argv[1] if len(sys.argv) > 1 else ""
if command == "--version":
    sys.stdout.write("syq 9.8.7\\n")
elif command == "emit":
    sys.stdout.write(sys.argv[2])
    sys.stderr.write("diagnostic")
elif command == "fail":
    sys.stdout.write("partial")
    sys.stderr.write("failed")
    raise SystemExit(23)
elif command in ("spawn-descendant", "interrupt"):
    marker = sys.argv[2]
    if command == "interrupt":
        with open(marker + ".pid", "w", encoding="utf-8") as pid_file:
            pid_file.write(str(os.getpid()))
    if os.fork() == 0:
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)
        lock = open(marker + ".lock", "wb")
        fcntl.flock(lock, fcntl.LOCK_EX)
        tmp = marker + ".ready.tmp"
        with open(tmp, "w", encoding="utf-8") as ready_file:
            ready_file.write(str(os.getpid()))
        os.replace(tmp, marker + ".ready")
        time.sleep(10)
        os._exit(0)
    deadline = time.monotonic() + 5
    while not os.path.exists(marker + ".ready"):
        if time.monotonic() >= deadline:
            raise SystemExit("fake descendant did not become ready")
        time.sleep(0.005)
    time.sleep(30 if command == "spawn-descendant" else 3)
else:
    raise SystemExit(2)
"""


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._executable_dir = resolved_temporary_directory()
        cls.addClassCleanup(cls._executable_dir.cleanup)
        cls.executable = Path(cls._executable_dir.name) / "syq"
        cls.executable.write_text(FAKE_SYQ, encoding="utf-8")
        cls.executable.chmod(0o755)
        warm_executable(cls.executable, "--version")

    def setUp(self) -> None:
        self.temporary_directory = resolved_temporary_directory()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_custom_executable_version_can_differ_from_package(self) -> None:
        self.assertRegex(syq.__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(syq.version(executable=self.executable), "9.8.7")

    def test_run_preserves_one_argument_with_shell_metacharacters(self) -> None:
        argument = "a path; $(not-a-command)"
        result = syq.run(["emit", argument], executable=self.executable)
        self.assertEqual(result.argv, (os.fspath(self.executable), "emit", argument))
        self.assertEqual(result.stdout, argument.encode())
        self.assertEqual(result.stderr, b"diagnostic")

    def test_default_run_uses_the_bundled_executable(self) -> None:
        with mock.patch(
            "syq.client.bundled_executable", return_value=self.executable
        ) as bundled:
            result = syq.run(["emit", "bundled"])

        bundled.assert_called_once_with()
        self.assertEqual(result.stdout, b"bundled")

    def test_explicit_executable_bypasses_the_bundled_selection(self) -> None:
        with mock.patch(
            "syq.client.bundled_executable",
            side_effect=AssertionError("bundled install should not run"),
        ):
            result = syq.run(["emit", "custom"], executable=self.executable)

        self.assertEqual(result.stdout, b"custom")

    def test_nonzero_result_is_retained(self) -> None:
        with self.assertRaises(syq.SyqProcessError) as caught:
            syq.run(["fail"], executable=self.executable)

        self.assertEqual(caught.exception.result.returncode, 23)
        self.assertEqual(caught.exception.result.stdout, b"partial")
        self.assertEqual(caught.exception.result.stderr, b"failed")

    def test_nonzero_result_can_be_returned(self) -> None:
        result = syq.run(["fail"], executable=self.executable, check=False)
        self.assertEqual(result.returncode, 23)

    def test_timeout_stops_spawned_descendants(self) -> None:
        marker = Path(self.temporary_directory.name) / "descendant-marker"

        with self.assertRaises(subprocess.TimeoutExpired):
            syq.run(
                ["spawn-descendant", marker],
                executable=self.executable,
                timeout=0.5,
            )

        assert_descendant_exited(self, marker)

    def test_keyboard_interrupt_stops_spawned_descendants(self) -> None:
        marker = Path(self.temporary_directory.name) / "interrupt-marker"
        ready = marker.with_suffix(".ready")
        pid_file = marker.with_suffix(".pid")
        script = (
            "from pathlib import Path\n"
            "import sys\n"
            "import syq\n"
            "syq.run(['interrupt', Path(sys.argv[2])], "
            "executable=Path(sys.argv[1]))\n"
        )
        wrapper = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                os.fspath(self.executable),
                os.fspath(marker),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            deadline = time.monotonic() + 3
            while not ready.exists() and wrapper.poll() is None:
                if time.monotonic() >= deadline:
                    self.fail(
                        "timed out waiting for the interrupt fixture; "
                        f"wrapper status is {wrapper.returncode}"
                    )
                time.sleep(0.01)
            self.assertIsNone(wrapper.poll())

            wrapper.send_signal(signal.SIGINT)
            wrapper.communicate(timeout=3)

            self.assertNotEqual(wrapper.returncode, 0)
            assert_descendant_exited(self, marker)
        finally:
            if wrapper.poll() is None:
                wrapper.kill()
                wrapper.communicate()
            if pid_file.exists():
                try:
                    os.killpg(int(pid_file.read_text(encoding="utf-8")), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_one_string_is_not_treated_as_an_argument_sequence(self) -> None:
        with self.assertRaisesRegex(TypeError, "individual arguments"):
            syq.run("emit", executable=self.executable)


if __name__ == "__main__":
    unittest.main()
