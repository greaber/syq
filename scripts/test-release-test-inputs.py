#!/usr/bin/env python3
"""Test release preparation equivalence and certification selection."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from release_test_inputs import fingerprint, candidates

SCRIPTS = Path(__file__).resolve().parent


class InputsTests(unittest.TestCase):
    def setUp(self):
        self.original = Path.cwd()
        self.temp = tempfile.TemporaryDirectory(prefix='syq-release-inputs.')
        self.root = Path(self.temp.name)
        os.chdir(self.root)
        self.git('init', '-q', '-b', 'master')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.com')
        self.git('config', 'commit.gpgsign', 'false')
        Path('Cargo.toml').write_text('[package]\nname = "syq"\nversion = "0.6.0"\n[dependencies]\nexample = "1.0"\n')
        Path('Cargo.lock').write_text('version = 4\n[[package]]\nname = "example"\nversion = "1.0.0"\n[[package]]\nname = "syq"\nversion = "0.6.0"\ndependencies = ["example"]\n')
        Path('source.rs').write_text('fn main() {}\n')
        self.base = self.commit()

    def tearDown(self):
        os.chdir(self.original)
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', *args], text=True).strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def prepare(self):
        for name in ['Cargo.toml', 'Cargo.lock']:
            p = Path(name)
            p.write_text(p.read_text().replace('0.6.0', '0.7.0'))
        Path('CHANGELOG.md').write_text('New release\n')
        return self.commit()

    def test_version_and_prose_reuse(self):
        head = self.prepare()
        self.assertEqual(fingerprint(self.base), fingerprint(head))
        self.assertEqual(list(candidates(head)), [head, self.base])

    def test_dependency_and_other_manifest_changes_require_tests(self):
        for name, before, after in [('Cargo.toml', 'example = "1.0"', 'example = "2.0"'),
                                    ('Cargo.lock', 'version = "1.0.0"', 'version = "2.0.0"'),
                                    ('Cargo.toml', 'name = "syq"', 'name = "other"')]:
            with self.subTest(name=name, after=after):
                self.git('reset', '--hard', self.base)
                self.prepare()
                p = Path(name)
                p.write_text(p.read_text().replace(before, after))
                head = self.commit()
                self.assertNotEqual(fingerprint(self.base), fingerprint(head))
                self.assertEqual(list(candidates(head)), [head])

    def test_test_build_workflow_and_executable_docs_changes_require_tests(self):
        for name in ['tests/test.rs', 'build.rs', '.github/workflows/ci.yml',
                     'docs/mappings.md', 'docs/automation.md', 'docs/commands/map.md',
                     'scripts/check.sh', 'sdk/python/pyproject.toml']:
            with self.subTest(name=name):
                self.git('reset', '--hard', self.base)
                p = Path(name)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('changed\n')
                self.assertNotEqual(fingerprint(self.base), fingerprint(self.commit()))

    def test_scope_skips_version_only_but_not_dependency_edits(self):
        head = self.prepare()
        event = self.root / '.git/event.json'
        event.write_text(json.dumps({'before': self.base, 'after': head}))
        output = subprocess.check_output([SCRIPTS / 'ci-scope.sh', event], text=True)
        self.assertIn('native=false\n', output)
        Path('docs').mkdir()
        Path('docs/automation.md').write_text('updated executable example')
        event.write_text(json.dumps({'before': self.base, 'after': self.commit()}))
        output = subprocess.check_output([SCRIPTS / 'ci-scope.sh', event], text=True)
        self.assertIn('native=false\n', output)
        self.assertIn('mapping_docs=true\n', output)
        self.assertIn('macos=false\n', output)
        p = Path('Cargo.toml')
        p.write_text(p.read_text().replace('example = "1.0"', 'example = "2.0"'))
        event.write_text(json.dumps({'before': self.base, 'after': self.commit()}))
        output = subprocess.check_output([SCRIPTS / 'ci-scope.sh', event], text=True)
        self.assertIn('native=true\n', output)

    def test_certification_reuse_does_not_hide_newer_failure_or_pending_run(self):
        head = self.prepare()
        fakebin = self.root / '.git/bin'
        fakebin.mkdir()
        gh = fakebin / 'gh'
        gh.write_text('''#!/usr/bin/env python3
import json, os, sys
url = sys.argv[-1]
if '/jobs?' in url:
    jobs = [] if '/runs/2/' in url else [{'name':'release-certification','status':'completed','conclusion':'success'}]
    if '/runs/2/' in url and os.environ.get('CURRENT_DOCS'):
        jobs = [{'name':'rust', 'steps':[{'name':'Test executable mapping documentation','status':'completed','conclusion':'success'}]}]
    print(json.dumps([{'jobs': jobs}]))
else:
    sha = url.split('head_sha=')[1].split('&')[0]
    is_base = sha == os.environ['BASE']
    status = 'completed' if is_base else os.environ.get('CURRENT_STATUS', 'completed')
    conclusion = 'success' if is_base else os.environ.get('CURRENT_CONCLUSION', 'success')
    run = dict(id=1 if is_base else 2,run_attempt=1,run_number=1,head_sha=sha,head_branch='master',head_repository={'full_name':'greaber/syq'},event='push',status=status,conclusion=conclusion)
    print(json.dumps([{'workflow_runs':[run]}]))
''')
        gh.chmod(0o755)
        env = {**os.environ, 'PATH': str(fakebin) + os.pathsep + os.environ['PATH'], 'BASE': self.base}
        cmd = [SCRIPTS / 'verify-release-ci.sh', '--json', 'greaber/syq', head]
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(w['evidence_commit'] == self.base for w in json.loads(result.stdout)['workflows']))
        for variables, expected in [({'CURRENT_CONCLUSION':'failure'}, 'repair'),
                                    ({'CURRENT_STATUS':'in_progress'}, 'wait')]:
            result = subprocess.run(cmd, env={**env, **variables}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(all(w['state'] == expected for w in json.loads(result.stdout)['workflows']))


        # Changed examples require their focused tests, not new native suites.
        Path('docs').mkdir()
        Path('docs/automation.md').write_text('changed executable example')
        doc_head = self.commit()
        self.assertEqual(fingerprint(self.base, native=True), fingerprint(doc_head, native=True))
        self.assertNotEqual(fingerprint(self.base), fingerprint(doc_head))
        cmd[-1] = doc_head
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        workflows = json.loads(result.stdout)['workflows']
        self.assertIn('documentation_only=true', workflows[0]['next_action'])
        self.assertTrue(all(w['state'] == 'ready' for w in workflows[1:]))
        result = subprocess.run(cmd, env={**env, 'CURRENT_DOCS':'true'}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        workflows = json.loads(result.stdout)['workflows']
        self.assertEqual(workflows[0]['documentation_commit'], doc_head)
        self.assertTrue(all(w['evidence_commit'] == self.base for w in workflows))

    def test_all_executable_pages_select_focused_tests(self):
        for page in ['docs/mappings.md', 'docs/automation.md', 'docs/commands/map.md']:
            paths = self.root / '.git/changed-paths'
            paths.write_text(page + '\n')
            output = subprocess.check_output([SCRIPTS / 'ci-scope.sh'], text=True,
                env={**os.environ, 'SYQ_TEST_CHANGED_PATHS_FILE': str(paths)})
            self.assertIn('native=false\n', output)
            self.assertIn('mapping_docs=true\n', output)
        output = subprocess.check_output([SCRIPTS / 'ci-scope.sh'], text=True,
            env={**os.environ, 'SYQ_CI_DOCUMENTATION_ONLY':'true'})
        self.assertIn('native=false\n', output)
        self.assertIn('mapping_docs=true\n', output)
        self.assertIn('full_suite=false\n', output)


if __name__ == '__main__':
    unittest.main()
