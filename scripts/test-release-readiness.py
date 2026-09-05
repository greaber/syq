#!/usr/bin/env python3
"""Exercise reusable evidence and package handoff using disposable repositories."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
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
        runner = lab / "test-real-ssh.sh"
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

    def test_checkout_mutation_during_check_does_not_certify(self):
        with self.assertRaisesRegex(ValueError, "not clean"):
            self.record("echo changed > source\n")
        self.git("restore", "source")
        self.assertIsNone(readiness.ssh_evidence())

    def test_wrong_profile_is_rejected(self):
        self.record()
        path = readiness.receipt_path(self.git("rev-parse", "HEAD^{tree}"))
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
        subprocess.run([str(SCRIPTS / "prepare-release-crate.sh"), "v9.9.9", str(prepared)], env=env, check=True)
        command = [str(SCRIPTS / "verify-prepared-crate.sh"), "v9.9.9", str(prepared)]
        subprocess.run(command, env=env, check=True)
        result = subprocess.run(command, env={**env, "FIXTURE_BYTES": "different"}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the validated artifact", result.stderr)
        calls = (target / "calls").read_text().splitlines()
        self.assertEqual(calls.count("package --locked"), 1)
        self.assertEqual(calls.count("package --locked --no-verify"), 2)


if __name__ == "__main__":
    unittest.main()
