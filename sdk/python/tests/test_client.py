from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import syq


FAKE_SYQ = """#!/bin/sh
case "$1" in
  --version)
    printf 'syq 9.8.7\\n'
    ;;
  emit)
    printf '%s' "$2"
    printf 'diagnostic' >&2
    ;;
  fail)
    printf 'partial'
    printf 'failed' >&2
    exit 23
    ;;
  spawn-descendant)
    (
      printf 'ready' > "$2.ready"
      sleep 1
      printf 'survived' > "$2"
    ) &
    while [ ! -f "$2.ready" ]; do
      sleep 0.01
    done
    sleep 30
    ;;
  interrupt)
    printf '%s' "$$" > "$2.pid"
    (
      printf 'ready' > "$2.ready"
      sleep 1
      printf 'survived' > "$2"
    ) &
    while [ ! -f "$2.ready" ]; do
      sleep 0.01
    done
    sleep 3
    ;;
  *)
    exit 2
    ;;
esac
"""


class ClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.executable = Path(self.temporary_directory.name) / "syq"
        self.executable.write_text(FAKE_SYQ, encoding="utf-8")
        self.executable.chmod(0o755)

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

    def test_default_run_uses_the_managed_executable(self) -> None:
        with mock.patch(
            "syq.client.managed_executable", return_value=self.executable
        ) as managed:
            result = syq.run(["emit", "managed"])

        managed.assert_called_once_with()
        self.assertEqual(result.stdout, b"managed")

    def test_explicit_executable_bypasses_the_managed_install(self) -> None:
        with mock.patch(
            "syq.client.managed_executable",
            side_effect=AssertionError("managed install should not run"),
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

        self.assertTrue(marker.with_suffix(".ready").exists())
        time.sleep(0.75)
        self.assertFalse(marker.exists())

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
            time.sleep(1.1)
            self.assertFalse(marker.exists())
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
