#!/usr/bin/env python3
"""Exercise benchmark failures, accounting and comparisons without big fixtures."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("benchmark", ROOT / "scripts/benchmark-concurrency.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="syq-benchmark-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def case(self, operation="cp"):
        return dict(name="tree", operation=operation, root=str(self.root), files=6,
                    directories=2, sizes=[0, 19, 4097])

    def run_measure(self, command, cpus=None, timeout=10, operation=None, sample_processes=True):
        with contextlib.redirect_stdout(io.StringIO()):
            return bench.measure(command, dict(os.environ, LC_ALL="C"), cpus,
                                 self.root / "measure", timeout, operation, sample_processes)

    def test_verification_checks_bytes_source_and_unexpected_directories(self):
        case = self.case()
        with contextlib.redirect_stdout(io.StringIO()):
            hashes, sizes = bench.fixture(self.root, case, bench.Deadline(10, "setup"))
            self.assertEqual(sizes["logical_bytes"], 8232)
            shutil.copytree(self.root / "source", self.root / "destination", dirs_exist_ok=True)
            bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            path = self.root / "destination" / bench.filename(case, 1)
            path.write_bytes(b"wrong content")
            with self.assertRaisesRegex(RuntimeError, "changed file"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            shutil.copyfile(self.root / "source" / bench.filename(case, 1), path)
            (self.root / "destination/extra").mkdir()
            with self.assertRaisesRegex(RuntimeError, "tree differs"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            (self.root / "destination/extra").rmdir()
            shutil.rmtree(self.root / "destination")
            (self.root / "destination").symlink_to(self.root / "source", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "expected directory"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            (self.root / "destination").unlink()
            shutil.copytree(self.root / "source", self.root / "destination")
            (self.root / "source" / bench.filename(case, 1)).unlink()
            with self.assertRaisesRegex(RuntimeError, "tree differs"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))

    def test_failure_preserves_partial_results_and_cleans_only_owned_fixture(self):
        # A zero-exit executable doing no work must fail result verification.
        sentinel = self.root / "unrelated"
        sentinel.write_text("keep me")
        plan = dict(reference="noop", cases=[self.case("rm")], variants=[
            dict(name="noop", binary="/usr/bin/true", workers=None, cpus=None)])
        path = self.root / "plan.json"
        path.write_text(json.dumps(plan))
        result = subprocess.run([sys.executable, str(ROOT / "scripts/benchmark-concurrency.py"),
                                 "--plan", str(path), "--output", str(self.root / "results"),
                                 "--rounds", "1"], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        report = json.loads((self.root / "results/results.json").read_text())
        self.assertIn("left paths", report["error"])
        self.assertFalse(report["complete"])
        self.assertTrue(report["cleaned"])
        self.assertFalse(report["trials"][0]["verified"])
        self.assertEqual(sentinel.read_text(), "keep me")
        self.assertFalse(list(self.root.glob("syq-concurrency-*")))

    def test_deep_fixture_verifies_all_directory_levels_and_file_contents(self):
        case = self.case() | dict(depth=4)
        with contextlib.redirect_stdout(io.StringIO()):
            hashes, sizes = bench.fixture(self.root, case, bench.Deadline(10, "setup"))
            self.assertEqual(sizes["logical_bytes"], 8232)
            expected = {
                f"d{index:04d}{suffix}" for index in range(2) for suffix in (
                    "", "/level0001", "/level0001/level0002", "/level0001/level0002/level0003")
            }
            actual = {str(p.relative_to(self.root / "source"))
                      for p in (self.root / "source").rglob("*") if p.is_dir()}
            self.assertEqual(actual, expected)
            self.assertEqual(len(hashes), 6)
            self.assertTrue(all(len(Path(path).parts) == 5 for path in hashes))
            shutil.copytree(self.root / "source", self.root / "destination", dirs_exist_ok=True)
            bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            file = self.root / "destination/d0001/level0001/level0002/level0003/f000000001"
            file.write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "changed file"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            shutil.copyfile(self.root / "source" / file.relative_to(self.root / "destination"), file)
            (self.root / "destination/d0000/unexpected").mkdir()
            with self.assertRaisesRegex(RuntimeError, "tree differs"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))

    def test_omitting_depth_preserves_the_original_fixture_layout(self):
        case = self.case()
        self.assertEqual(bench.filename(case, 3), Path("d0001/f000000003"))
        self.assertEqual(list(bench.fixture_directories(case)), [Path("d0000"), Path("d0001")])

    def test_native_accounting_does_not_inherit_fixture_builder_peak_rss(self):
        # wait4 on a Python-spawned child itself can inherit this memory peak.
        allocation = bytearray(96 * 1024 * 1024)
        allocation[0] = 1
        result = self.run_measure(["/usr/bin/true"], operation="rm")
        self.assertEqual(result["exit_code"], 0)
        self.assertLess(result["resources"]["peak_rss_bytes"], len(allocation) // 2)
        self.assertGreater(result["seconds"], 0)

    def measure_family(self, wait, sample_processes=True):
        child_stats, parent_stats = self.root / "child.json", self.root / "parent.json"
        child = f"""
import json, os, pathlib, resource, time
memory = bytearray(20 * 1024 * 1024)
fds = [open(os.devnull) for _ in range(12)]
pathlib.Path({str(self.root / 'written')!r}).write_bytes(b'x' * (4 * 1024 * 1024))
end = time.process_time() + .6
while time.process_time() < end:
    sum(range(1000))
u = resource.getrusage(resource.RUSAGE_SELF)
pathlib.Path({str(child_stats)!r}).write_text(json.dumps(dict(pid=os.getpid(), cpu=u.ru_utime+u.ru_stime)))
"""
        parent = f"""
import json, os, pathlib, resource, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', {child!r}])
end = time.process_time() + .2
while time.process_time() < end:
    sum(range(1000))
if {wait!r}:
    child.wait()
u = resource.getrusage(resource.RUSAGE_SELF)
pathlib.Path({str(parent_stats)!r}).write_text(json.dumps(dict(pid=os.getpid(), cpu=u.ru_utime+u.ru_stime)))
# Bypass Popen's destructor: this intentionally leaves the child un-waited.
os._exit(0)
"""
        result = self.run_measure([sys.executable, "-c", parent], operation="cp", sample_processes=sample_processes)
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(child_stats.exists(), "the harness killed a successful operation's helper")
        records = [json.loads(p.read_text()) for p in (parent_stats, child_stats)]
        expected = sum(r["cpu"] for r in records)
        actual = result["resources"]["cpu_seconds"]
        self.assertAlmostEqual(actual, expected, delta=.10 if platform.system() == "Darwin" else .04)
        if not sample_processes:
            self.assertTrue(result["cpu_accounting_complete"])
            self.assertFalse(result["sampling_enabled"])
            self.assertEqual(result["processes"], [])
            self.assertIsNone(result["resources"]["peak_rss_bytes"])
            self.assertIsNone(result["max_sample_gap_seconds"])
            return result
        self.assertTrue(result["expected_processes_observed"])
        sampled = {p["pid"]: p["sampled"] for p in result["processes"]}
        for record in records:
            self.assertAlmostEqual(sampled[record["pid"]]["user_seconds"] + sampled[record["pid"]]["system_seconds"],
                                   record["cpu"], delta=.10)
        self.assertGreaterEqual(sampled[records[1]["pid"]]["fds"], 12)
        self.assertGreaterEqual(result["sampled"]["threads"], 2)
        self.assertGreater(sampled[records[1]["pid"]]["peak_rss_bytes"], 20 * 1024 * 1024)
        if platform.system() == "Linux":
            self.assertEqual(len(result["accounting"]), 1 if wait else 2)
            self.assertTrue(result["cpu_accounting_complete"])
        else:
            self.assertFalse(result["cpu_accounting_complete"])
        return result

    def test_unwaited_helper_finishes_and_its_cpu_is_counted(self):
        result = self.measure_family(False)
        self.assertGreater(result["drain_seconds"], .1)

    def test_waited_helper_cpu_is_not_counted_twice(self):
        self.measure_family(True)

    @unittest.skipUnless(platform.system() == "Linux", "complete exit accounting requires Linux")
    def test_disabled_sampling_keeps_unwaited_helper_cpu(self):
        self.measure_family(False, sample_processes=False)

    @unittest.skipUnless(hasattr(os, "sched_getaffinity"), "CPU affinity is Linux-only")
    def test_affinity_applies_to_product_and_restores_runner(self):
        before = os.sched_getaffinity(0)
        chosen = min(before)
        result = self.run_measure([sys.executable, "-c",
            f"import os,time; assert os.sched_getaffinity(0)=={{{chosen}}}; time.sleep(.08)"], [chosen])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(os.sched_getaffinity(0), before)
        self.assertEqual(result["observed_cpu_sets"], [str(chosen)])

    def test_timeout_terminates_grandchild_process_group(self):
        pidfile = self.root / "group"
        code = ("import os,subprocess,time,pathlib; "
                f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpgrp())); "
                "subprocess.Popen(['sleep','60']); time.sleep(60)")
        with self.assertRaises(TimeoutError):
            self.run_measure([sys.executable, "-c", code], timeout=.3)
        self.assertTrue(pidfile.exists())
        self.assertFalse(bench.group_alive(int(pidfile.read_text())))

    def test_comparison_preserves_bad_case_and_bad_round(self):
        rows = []
        for case, seconds in (("fast", [5, 5]), ("bad", [10, 30])):
            for iteration, value in enumerate(seconds):
                for variant, elapsed in (("reference", 10), ("candidate", value)):
                    rows.append(dict(case=case, variant=variant, round=iteration, verified=True,
                                     seconds=elapsed, resources=dict(cpu_seconds=10, peak_rss_bytes=1024)))
        # An incomplete/unverified round is never paired or counted as a win.
        rows.append(dict(case="bad", variant="candidate", round=2, verified=False))
        results = bench.comparisons(rows, "reference")
        self.assertEqual(results[0]["case"], "bad")
        self.assertEqual(results[0]["paired_rounds"], 2)
        self.assertEqual(results[0]["seconds"]["paired_ratios"], [1, 3])
        self.assertEqual(results[0]["seconds"]["worst_ratio"], 3)
        self.assertEqual(results[1]["seconds"]["median_ratio"], .5)

    def test_zero_cpu_resolution_is_not_a_ratio(self):
        base = dict(case="case", round=1, verified=True, seconds=.001,
                    resources=dict(cpu_seconds=0, peak_rss_bytes=100))
        result = bench.comparisons([dict(base, variant="old"), dict(base, variant="new")], "old")
        self.assertIsNone(result[0]["cpu_seconds"]["median_ratio"])
        self.assertEqual(result[0]["cpu_seconds"]["paired_ratios"], [])
        nonzero = copy.deepcopy(base)
        nonzero["resources"]["cpu_seconds"] = .01
        result = bench.comparisons([dict(nonzero, variant="old"), dict(base, variant="new")], "old")
        self.assertIsNone(result[0]["cpu_seconds"]["median_ratio"])

    def test_missing_samples_do_not_claim_a_cpu_or_memory_ratio(self):
        base = dict(case="case", round=1, verified=True, seconds=.001,
                    resources=dict(cpu_seconds=None, peak_rss_bytes=None))
        result = bench.comparisons([dict(base, variant="old"), dict(base, variant="new")], "old")[0]
        self.assertEqual(result["seconds"]["median_ratio"], 1)
        for key in ("cpu_seconds", "peak_rss_bytes"):
            self.assertIsNone(result[key]["median_ratio"])
            self.assertEqual(result[key]["available_pairs"], 0)

    def test_prune_fixed_reference_is_rejected(self):
        plan = dict(reference="fixed", cases=[self.case("prune")], variants=[
            dict(name="fixed", binary="/usr/bin/true", workers=8, cpus=None)])
        with self.assertRaisesRegex(ValueError, "automatic-worker reference"):
            bench.validate(plan)

    def test_unique_logs_and_prune_skips_fixed_workers(self):
        binary = self.root / "fake-syq"
        binary.write_text(f"#!{sys.executable}\n" + """
import pathlib, shutil, sys
args = sys.argv
source = pathlib.Path(args[args.index('--srcs-in') + 1])
tree = pathlib.Path(args[args.index('--into') + 1]) if '--prune' in args else source
if '--prune' in args:
    assert '--performance-tuning' not in args
for path in tree.iterdir():
    shutil.rmtree(path)
print(' '.join(args))
""")
        binary.chmod(0o755)
        plan = dict(reference="auto-1-fixed", cases=[dict(self.case("rm"), name=n) for n in ("tree", "tree-1-auto")]
                    + [self.case("prune") | dict(name="prune", depth=3)], variants=[
            dict(name=n, binary=str(binary), workers=w, cpus=None) for n, w in (("auto-1-fixed", None), ("fixed", 8))])
        path = self.root / "plan.json"
        path.write_text(json.dumps(plan))
        subprocess.run([sys.executable, str(ROOT / "scripts/benchmark-concurrency.py"),
                        "--plan", str(path), "--output", str(self.root / "results"), "--rounds", "1"],
                       check=True, capture_output=True, text=True, timeout=20)
        report = json.loads((self.root / "results/results.json").read_text())
        self.assertTrue(report["complete"])
        self.assertTrue(report["cleaned"])
        self.assertEqual(len(report["trials"]), 5)
        prefixes = [t["log_prefix"] for t in report["trials"]]
        self.assertEqual(len(set(prefixes)), 5)
        for prefix in prefixes:
            self.assertTrue(Path(prefix + ".stdout").read_text())
        self.assertEqual(len(report["skipped_variants"]), 1)
        self.assertEqual(report["skipped_variants"][0]["variant"], "fixed")
        self.assertIn("disabled", report["tuning_history"])

    def test_failed_snapshot_replace_preserves_previous_results(self):
        path = self.root / "results.json"
        bench.save_json(path, {"trials": [1]})
        with mock.patch.object(Path, "replace", side_effect=OSError("interrupted replacement")):
            with self.assertRaises(OSError):
                bench.save_json(path, {"trials": [1, 2]})
        self.assertEqual(json.loads(path.read_text()), {"trials": [1]})

    def test_changed_binary_invalidates_run(self):
        path = self.root / "binary"
        path.write_bytes(b"old")
        report = dict(plan=dict(variants=[dict(name="base", binary=str(path))]),
                      binary_sha256={"base": bench.sha256_file(path)})
        path.write_bytes(b"new")
        with self.assertRaisesRegex(RuntimeError, "binary changed"):
            bench.check_binaries(report)

    def test_macos_time_units_and_missing_fields(self):
        log = """syq: incidental diagnostic
        1.24 real         0.31 user         0.87 sys
             5242880  maximum resident set size
                   3  voluntary context switches
                   4  involuntary context switches
                   5  block input operations
                   6  block output operations
"""
        result = bench.time_usage(log, "Darwin")
        self.assertEqual(result["peak_rss_bytes"], 5242880)
        self.assertEqual(result["system_seconds"], .87)
        self.assertEqual(result["input_blocks"], 5)
        with self.assertRaisesRegex(ValueError, "missing macOS time field"):
            bench.time_usage(log.replace("maximum resident set size", "unknown"), "Darwin")

    def test_plan_rejects_unknown_knobs_and_affinity_outside_allowed_set(self):
        plan = dict(reference="base", cases=[self.case()], variants=[
            dict(name="base", binary="/usr/bin/true", workers=32, cpus=None)])
        bench.validate(copy.deepcopy(plan))
        bad = copy.deepcopy(plan)
        bad["cases"][0]["filez"] = 1
        with self.assertRaisesRegex(ValueError, "case needs"):
            bench.validate(bad)
        deep = copy.deepcopy(plan)
        deep["cases"][0]["depth"] = 12
        bench.validate(deep)
        for invalid in (0, -1, True, 1.5, None):
            bad = copy.deepcopy(deep)
            bad["cases"][0]["depth"] = invalid
            with self.assertRaisesRegex(ValueError, "depth must"):
                bench.validate(bad)
        if hasattr(os, "sched_getaffinity"):
            bad = copy.deepcopy(plan)
            bad["variants"][0]["cpus"] = [max(os.sched_getaffinity(0)) + 1]
            with self.assertRaisesRegex(ValueError, "outside"):
                bench.validate(bad)

    def test_nonfinite_timeout_is_rejected_before_creating_output(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/benchmark-concurrency.py"),
                                 "--plan", "unused.json", "--output", str(self.root / "results"),
                                 "--timeout", "nan"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("positive rounds/timeouts", result.stderr)
        self.assertFalse((self.root / "results").exists())


if __name__ == "__main__":
    unittest.main()
