#!/usr/bin/env python3
"""Exercise reusable evidence and package handoff using disposable repositories."""
from support import SCRIPTS

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("readiness", SCRIPTS / "release-readiness.py")
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.original = Path.cwd()
        self.temp = tempfile.TemporaryDirectory(prefix="syq-release-readiness.")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        os.chdir(self.repo)
        self.git("init", "-q", "-b", "master")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "commit.gpgsign", "false")
        Path("source").write_text("one")
        self.commit()

    def tearDown(self):
        os.chdir(self.original)
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], text=True).strip()

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def record(self, script="exit 0\n"):
        lab = self.root / "lab"
        lab.mkdir(exist_ok=True)
        runner = lab / "test-real-ssh.py"
        runner.write_text("#!/usr/bin/env bash\nset -eu\n" + script)
        runner.chmod(0o755)
        real_run = readiness.run
        def run(*args):
            return "fixture docker" if args[0] == "docker" else real_run(*args)
        with mock.patch.object(readiness, "SCRIPTS", lab), mock.patch.object(readiness, "run", run):
            readiness.check_ssh()

    def test_same_tree_merge_and_worktree_reuse(self):
        self.assertIsNone(readiness.ssh_evidence())
        self.record()
        checked = self.git("rev-parse", "HEAD")
        self.git("commit", "--allow-empty", "-qm", "same-tree merge equivalent")
        self.assertNotEqual(checked, self.git("rev-parse", "HEAD"))
        self.assertEqual(readiness.ssh_evidence()["commit"], checked)
        other = self.root / "other"
        self.git("worktree", "add", "--detach", str(other), "HEAD")
        os.chdir(other)
        self.assertEqual(readiness.ssh_evidence()["commit"], checked)

    def test_release_prose_reuses_evidence_and_failed_rerun_supersedes_it(self):
        self.record()
        checked = self.git("rev-parse", "HEAD")
        Path("CHANGELOG.md").write_text("Release notes")
        self.commit()
        self.assertEqual(readiness.ssh_evidence()["commit"], checked)
        with self.assertRaises(subprocess.CalledProcessError):
            self.record("exit 1\n")
        self.assertIsNone(readiness.ssh_evidence())

    def test_documentation_examples_do_not_require_another_ssh_lab(self):
        self.record()
        checked = self.git("rev-parse", "HEAD")
        Path("docs").mkdir()
        Path("docs/automation.md").write_text("changed example")
        self.commit()
        self.assertEqual(readiness.ssh_evidence()["commit"], checked)

    def test_changed_committed_tree_invalidates_evidence(self):
        self.record()
        Path("source").write_text("two")
        self.commit()
        self.assertIsNone(readiness.ssh_evidence())

    def test_dirty_tree_refuses_recording_and_reuse(self):
        self.record()
        Path("untracked").write_text("dirty")
        with self.assertRaisesRegex(ValueError, "not clean"):
            self.record()
        with self.assertRaisesRegex(ValueError, "not clean"):
            readiness.ssh_evidence()

    def test_failed_rerun_invalidates_prior_success(self):
        self.record()
        with self.assertRaises(subprocess.CalledProcessError):
            self.record("exit 1\n")
        self.assertIsNone(readiness.ssh_evidence())

    def test_missing_tool_on_rerun_invalidates_prior_success(self):
        self.record()
        real_run = readiness.run
        def run(*args):
            if args[0] == "docker":
                raise FileNotFoundError("docker unavailable")
            return real_run(*args)
        with mock.patch.object(readiness, "run", run):
            with self.assertRaises(FileNotFoundError):
                readiness.check_ssh()
        self.assertIsNone(readiness.ssh_evidence())

    def test_checkout_mutation_during_check_does_not_certify(self):
        with self.assertRaisesRegex(ValueError, "not clean"):
            self.record("echo changed > source\n")
        self.git("restore", "source")
        self.assertIsNone(readiness.ssh_evidence())

    def test_wrong_profile_is_rejected(self):
        self.record()
        path = readiness.inputs_receipt_path(self.git("rev-parse", "HEAD"))
        receipt = json.loads(path.read_text())
        receipt["profile"] = "max-sessions-1"
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "invalid real-SSH"):
            readiness.ssh_evidence()

    def test_source_package_handoff_rejects_different_bytes(self):
        fakebin = self.root / "bin"
        fakebin.mkdir()
        target = self.root / "target"
        target.mkdir()
        cargo = fakebin / "cargo"
        cargo.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FIXTURE_TARGET'])
with (root / 'calls').open('a') as output:
    output.write(' '.join(sys.argv[1:]) + '\\n')
if sys.argv[1] == 'metadata':
    print(json.dumps({'packages':[{'name':'syq','version':'9.9.9'}], 'target_directory':str(root)}))
elif sys.argv[1] == 'package':
    (root / 'package').mkdir(exist_ok=True)
    (root / 'package' / 'syq-9.9.9.crate').write_text(os.environ.get('FIXTURE_BYTES','validated'))
else:
    sys.exit(2)
''')
        cargo.chmod(0o755)
        env = {**os.environ, "PATH": str(fakebin) + os.pathsep + os.environ["PATH"],
               "FIXTURE_TARGET": str(target)}
        prepared = self.root / "prepared"
        subprocess.run([str(SCRIPTS / "prepare-release-crate.py"), "v9.9.9", str(prepared)], env=env, check=True)
        command = [str(SCRIPTS / "verify-prepared-crate.py"), "v9.9.9", str(prepared)]
        subprocess.run(command, env=env, check=True)
        result = subprocess.run(command, env={**env, "FIXTURE_BYTES": "different"}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the validated artifact", result.stderr)
        calls = (target / "calls").read_text().splitlines()
        self.assertEqual(calls.count("package --locked"), 1)
        self.assertEqual(calls.count("package --locked --no-verify"), 2)


FAKE_RUSTUP = '''#!{python}
import os, pathlib, sys
with pathlib.Path(os.environ["FIXTURE_LOG"]).open("a") as log:
    log.write("rustup " + " ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:3] == ["component", "list"]:
    print(os.environ["FIXTURE_INSTALLED"].replace(" ", "\\n"))
elif sys.argv[2:3] == ["add"]:
    sys.exit(int(os.environ.get("FIXTURE_ADD_STATUS", "0")))
'''

FAKE_CARGO = '''#!{python}
import json, os, pathlib, sys
with pathlib.Path(os.environ["FIXTURE_LOG"]).open("a") as log:
    log.write("cargo " + " ".join(sys.argv[1:]) + "\\n")
    if sys.argv[1] == "fetch":
        sys.exit(int(os.environ.get("FIXTURE_FETCH_STATUS", "0")))
    log.write(json.dumps({{"cwd": os.getcwd(), "env": {{
        key: value for key, value in os.environ.items()
        if key.endswith(("apple-darwin", "apple_darwin"))}}}}) + "\\n")
sys.exit(int(os.environ.get("FIXTURE_CARGO_STATUS", "0")))
'''


class MacosLintTests(unittest.TestCase):
    """Drive scripts/check-macos-lint.py with fake rustup and cargo."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syq-macos-lint.")
        root = Path(self.temp.name)
        fakebin = root / "bin"
        fakebin.mkdir()
        for name, text in [("rustup", FAKE_RUSTUP), ("cargo", FAKE_CARGO)]:
            (fakebin / name).write_text(text.format(python=sys.executable))
            (fakebin / name).chmod(0o755)
        self.checkout = root / "checkout"
        self.checkout.mkdir()
        self.log = root / "log"
        # A fresh CI runner's minimal toolchain: no clippy, no macOS target.
        self.env = {**os.environ, "PATH": str(fakebin) + os.pathsep + os.environ["PATH"],
                    "FIXTURE_LOG": str(self.log),
                    "FIXTURE_INSTALLED": "cargo-x86_64-unknown-linux-gnu "
                                         "rust-std-x86_64-unknown-linux-gnu"}

    def tearDown(self):
        self.temp.cleanup()

    def lint(self, *args, **env):
        self.log.unlink(missing_ok=True)
        result = subprocess.run([str(SCRIPTS / "check-macos-lint.py"), *args], cwd=self.checkout,
                                env={**self.env, **env}, capture_output=True, text=True)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return result, calls

    def test_lints_the_current_checkout_for_macos_without_its_compilers(self):
        result, calls = self.lint()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[:5], [
            "rustup component list --installed",
            "rustup target add aarch64-apple-darwin",
            "rustup component add clippy",
            "cargo fetch --locked",
            "cargo clippy --locked --all-targets --all-features --target aarch64-apple-darwin "
            "-- -D warnings"])
        cargo = json.loads(calls[5])
        self.assertTrue(os.path.samefile(cargo["cwd"], self.checkout))
        # Every spelling cc-rs checks first, so a caller's compiler cannot win.
        stubs = {f"{variable}_{target}" for variable in ("CC", "CXX", "AR")
                 for target in ("aarch64-apple-darwin", "aarch64_apple_darwin")}
        self.assertEqual(set(cargo["env"]), stubs)
        for path in cargo["env"].values():
            self.assertEqual(subprocess.run([path]).returncode, 0)
            self.assertEqual(Path(path).name, "true")

    def test_installed_components_are_not_added_again(self):
        result, calls = self.lint(FIXTURE_INSTALLED="clippy-x86_64-unknown-linux-gnu "
                                                    "rust-std-aarch64-apple-darwin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(" add " in call for call in calls), calls)

    def test_lint_failure_and_setup_failure_have_distinct_statuses(self):
        result, _ = self.lint(FIXTURE_CARGO_STATUS="101")
        self.assertEqual(result.returncode, 1)
        result, calls = self.lint(FIXTURE_ADD_STATUS="1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot add aarch64-apple-darwin", result.stderr)
        self.assertFalse(any(call.startswith("cargo") for call in calls))
        # Cargo exits 101 for a download or lockfile problem too; that is not a lint failure.
        result, calls = self.lint(FIXTURE_FETCH_STATUS="101")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot download the locked crates", result.stderr)
        self.assertFalse(any(call.startswith("cargo clippy") for call in calls))
        result, calls = self.lint("unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
