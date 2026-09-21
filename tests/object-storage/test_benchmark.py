"""Command-policy checks; no credentials, network or benchmark binaries needed."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('benchmark', Path(__file__).with_name('benchmark.py'))
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def settings(**overrides):
    return SimpleNamespace(**(dict(workers=None, concurrency=None, part_size=None,
                                  s5cmd_workers=None, s5cmd_concurrency=None,
                                  s5cmd_part_size=None, syq_tuning=None) | overrides))


class TransferSettings(unittest.TestCase):
    def test_defaults_leave_both_tools_automatic(self):
        self.assertEqual(benchmark.transfer_tuning_mode(settings()), 'tool-defaults')
        self.assertEqual(benchmark.transfer_tuning(settings()), '')
        self.assertEqual(benchmark.s5cmd_transfer_flags(settings()), ['cp'])

    def test_s5cmd_tuning_does_not_disable_syq_adaptation(self):
        args = settings(s5cmd_workers=512, s5cmd_concurrency=8, s5cmd_part_size=16)
        self.assertEqual(benchmark.transfer_tuning_mode(args), 'per-tool-overrides')
        self.assertEqual(benchmark.transfer_tuning(args), '')
        self.assertEqual(benchmark.s5cmd_transfer_flags(args), ['--numworkers', '512', 'cp', '-c', '8', '-p', '16'])

    def test_syq_override_is_used_for_transfers(self):
        args = settings(syq_tuning='s3-requests=96')
        self.assertEqual(benchmark.transfer_tuning_mode(args), 'per-tool-overrides')
        self.assertEqual(benchmark.transfer_tuning(args), args.syq_tuning)
        self.assertEqual(benchmark.s5cmd_transfer_flags(args), ['cp'])

    def test_explicit_shared_setting_leaves_other_settings_automatic(self):
        args = settings(workers=16)
        self.assertEqual(benchmark.transfer_tuning_mode(args), 'shared-overrides')
        self.assertEqual(benchmark.transfer_tuning(args), 's3-objects=16')
        self.assertEqual(benchmark.s5cmd_transfer_flags(args), ['--numworkers', '16', 'cp'])


if __name__ == '__main__':
    unittest.main()
