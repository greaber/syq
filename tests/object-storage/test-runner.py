#!/usr/bin/env python3
"""Real process-group teardown checks; no syq executable or container needed."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CleanupTests(unittest.TestCase):
    def group(self):
        leader = subprocess.Popen(
            [sys.executable, '-c',
             'import signal,time; signal.signal(signal.SIGINT, lambda *_: exit(0)); '
             'print("ready", flush=True); time.sleep(30)'],
            preexec_fn=os.setpgrp, stdout=subprocess.PIPE, text=True)
        self.addCleanup(leader.stdout.close)
        self.addCleanup(self.reap, leader)
        self.assertEqual(leader.stdout.readline().strip(), 'ready')
        member = subprocess.Popen(
            [sys.executable, '-c',
             'import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); '
             'print("ready", flush=True); time.sleep(30)'],
            preexec_fn=lambda: os.setpgid(0, leader.pid),
            stdout=subprocess.PIPE, text=True)
        self.addCleanup(member.stdout.close)
        self.addCleanup(self.reap, member)
        self.assertEqual(member.stdout.readline().strip(), 'ready')
        return leader, member

    @staticmethod
    def reap(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)

    def test_waits_for_other_group_members_to_be_reaped(self):
        leader, member = self.group()
        killed = threading.Event()
        killpg = os.killpg

        def signal_group(pid, signum):
            killpg(pid, signum)
            if signum == signal.SIGKILL:
                killed.set()

        def delayed_reap():
            if killed.wait(5):
                time.sleep(.05)
                member.wait(timeout=5)

        reaper = threading.Thread(target=delayed_reap)
        reaper.start()
        try:
            with mock.patch.object(runner.os, 'killpg', side_effect=signal_group):
                runner.stop([(leader, [], 0)])
        finally:
            killed.set()
            reaper.join(timeout=6)
        self.assertFalse(reaper.is_alive())
        with self.assertRaises(ProcessLookupError):
            killpg(leader.pid, 0)

    def test_still_rejects_group_surviving_deadline(self):
        leader, member = self.group()
        killpg = os.killpg

        def ignore_kill(pid, signum):
            if signum != signal.SIGKILL:
                killpg(pid, signum)

        started = time.monotonic()
        with mock.patch.object(runner.os, 'killpg', side_effect=ignore_kill):
            with self.assertRaisesRegex(RuntimeError, 'survived cleanup'):
                runner.stop([(leader, [], 0)])
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsNone(member.poll())


if __name__ == '__main__':
    unittest.main()
