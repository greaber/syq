#!/usr/bin/env python3
"""Tests for the shared helpers in scripts/tooling.py."""
import support  # Make production tooling importable.

import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import tooling  # noqa: E402


class ForwardSignalsTests(unittest.TestCase):
    def setUp(self):
        saved = {signum: signal.getsignal(signum) for signum in tooling.ForwardSignals.SIGNALS}
        self.addCleanup(lambda: [signal.signal(signum, handler)
                                 for signum, handler in saved.items()])

    def test_signal_while_the_child_starts_is_forwarded(self):
        # The signal arrives after the child exists but before run() records it,
        # so the handler cannot forward it. run() must pass it on itself instead
        # of waiting for the child to finish.
        children = tooling.ForwardSignals()
        real_popen = subprocess.Popen

        def popen_then_signal(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            os.kill(os.getpid(), signal.SIGTERM)
            return child

        started = time.monotonic()
        with mock.patch.object(tooling.subprocess, "Popen", popen_then_signal):
            with self.assertRaises(SystemExit) as raised:
                children.run("sleep", "30")
        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        self.assertLess(time.monotonic() - started, 10)

    def test_signal_during_the_child_is_forwarded(self):
        children = tooling.ForwardSignals()
        timer = subprocess.Popen([sys.executable, "-c",
                                  f"import os, signal, time; time.sleep(1); "
                                  f"os.kill({os.getpid()}, signal.SIGINT)"])
        self.addCleanup(timer.wait)
        started = time.monotonic()
        with self.assertRaises(SystemExit) as raised:
            children.run("sleep", "30")
        self.assertEqual(raised.exception.code, 128 + signal.SIGINT)
        self.assertLess(time.monotonic() - started, 10)


if __name__ == "__main__":
    unittest.main()
