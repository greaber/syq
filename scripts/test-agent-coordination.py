#!/usr/bin/env python3
"""Exercise public commands with real processes, Git worktrees and disposable state."""
import json
import os
from pathlib import Path
import shlex
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().with_name('agent-coordination.py')
sys.path.insert(0, str(SCRIPT.parent))
from coordination.store import Store


class CoordinationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='coordination-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / 'state'
        self.env = dict(os.environ)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env['PATH'] = str(self.bin) + os.pathsep + self.env['PATH']
        self.env['TEST_ROOT'] = str(self.root)
        self.cwd = self.root

    def cmd(self, *args, code=0):
        result = subprocess.run([sys.executable, str(SCRIPT), '--state-dir', str(self.state), *args],
                                cwd=self.cwd, env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return json.loads(result.stdout if result.stdout else result.stderr.splitlines()[-1])

    def stub(self, executable, body):
        path = self.bin / executable
        path.write_text('#!/usr/bin/env python3\n' + body)
        path.chmod(0o755)

    def define(self, *names):
        for name in names:
            self.cmd('resource', 'define', name, '--description', 'Disposable test resource')

    def acquire(self, agent, *names, mode='exclusive', code=0):
        return self.cmd('resource', 'acquire', *names, '--agent', agent, '--mode', mode, code=code)['id']

    def test_shared_builds_exclusive_benchmark_and_fairness(self):
        self.define('local-compute')
        a = self.acquire('build-a', 'local-compute', mode='shared')
        b = self.acquire('review-build', 'local-compute', mode='shared')
        benchmark = self.acquire('benchmark', 'local-compute', code=3)
        later = self.acquire('late-build', 'local-compute', mode='shared', code=3)
        self.cmd('resource', 'release', a, '--agent', 'build-a')
        self.cmd('resource', 'release', b, '--agent', 'review-build')
        states = {r['id']: r['status'] for r in self.cmd('resource', 'status')['requests']}
        self.assertEqual(states[benchmark], 'held')
        self.assertEqual(states[later], 'queued')
        self.cmd('resource', 'release', benchmark, '--agent', 'benchmark')
        self.assertEqual(self.cmd('resource', 'wait', later, '--agent', 'late-build')['status'], 'held')

    def test_group_claims_avoid_partial_acquisition_and_independent_work_proceeds(self):
        self.define('source', 'destination', 'elsewhere')
        first = self.acquire('first', 'destination')
        pair = self.acquire('pair', 'source', 'destination', code=3)
        self.acquire('other', 'elsewhere')
        self.acquire('late', 'source', code=3)
        self.cmd('resource', 'release', first, '--agent', 'first')
        self.assertEqual(self.cmd('resource', 'wait', pair, '--agent', 'pair')['status'], 'held')

    def test_concurrent_claims_have_one_owner(self):
        self.define('server')
        processes = [subprocess.Popen([sys.executable, str(SCRIPT), '--state-dir', str(self.state),
                     'resource', 'acquire', 'server', '--agent', f'a{i}'], stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, text=True, env=self.env) for i in range(10)]
        results = []
        for process in processes:
            out, err = process.communicate(timeout=10)
            self.assertIn(process.returncode, (0, 3), err)
            results.append(json.loads(out))
        self.assertEqual(sum(r['status'] == 'held' for r in results), 1)
        self.assertEqual(len(self.cmd('resource', 'status')['requests']), 10)

    def test_wait_timeout_and_signal_withdraw_unused_claim(self):
        self.define('server')
        owner = self.acquire('owner', 'server')
        ticket = self.acquire('waiting', 'server', code=3)
        self.cmd('resource', 'wait', ticket, '--agent', 'waiting', '--timeout', '1', code=2)
        ticket = self.acquire('waiting', 'server', code=3)
        process = subprocess.Popen([sys.executable, str(SCRIPT), '--state-dir', str(self.state),
                                   'resource', 'wait', ticket, '--agent', 'waiting'],
                                  stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertIn('Waiting for', process.stderr.readline())
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130)
        states = {r['id']: r['status'] for r in self.cmd('resource', 'status')['requests']}
        self.assertEqual(states[ticket], 'cancelled')
        self.assertEqual(states[owner], 'held')
        self.cmd('resource', 'cancel', owner, '--agent', 'owner', code=2)
        self.cmd('resource', 'release', owner, '--agent', 'impostor', code=2)

    def test_unknown_resource_and_duplicate_claim_fail(self):
        self.cmd('resource', 'acquire', 'unknown', '--agent', 'a', code=2)
        self.define('server')
        self.acquire('a', 'server')
        self.cmd('resource', 'acquire', 'server', '--agent', 'a', code=2)

    def test_topics_notify_only_subscribers_and_preserve_unread_state(self):
        self.stub('codex', "import json,os,sys\nfrom pathlib import Path\np=Path(os.environ['TEST_ROOT'])/'notifications'\nwith p.open('a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n")
        for agent in ('interested', 'unrelated'):
            self.cmd('agent', 'register', agent, '--codex-thread', agent)
        self.cmd('topic', 'subscribe', 'discussion', '--agent', 'interested')
        self.cmd('topic', 'subscribe', 'elsewhere', '--agent', 'unrelated')
        body = self.root / 'body.md'; body.write_text('A longer discussion.\n')
        result = self.cmd('topic', 'publish', 'discussion', '--agent', 'writer', '--title', 'Update',
                         '--body-file', str(body), '--notify')
        self.assertEqual(set(result['delivery']), {'interested'})
        self.assertEqual(self.cmd('topic', 'list')['discussion']['subscribers'], ['interested'])
        self.assertEqual(json.loads((self.root / 'notifications').read_text())[2], 'interested')
        first = self.cmd('topic', 'read', 'discussion', '--agent', 'interested')
        self.assertEqual(len(first['events']), 1)
        self.assertEqual(Path(first['events'][0]['path']).read_text(), body.read_text())
        self.cmd('topic', 'ack', 'discussion', '1', '--agent', 'interested')
        self.assertEqual(self.cmd('topic', 'read', 'discussion', '--agent', 'interested')['events'], [])
        self.cmd('topic', 'ack', 'discussion', '0', '--agent', 'interested', code=2)

    def test_reads_do_not_rewrite_state_and_future_schema_is_rejected(self):
        self.define('server')
        path = self.state / 'state.json'; before = path.stat().st_mtime_ns
        self.cmd('resource', 'status')
        self.assertEqual(before, path.stat().st_mtime_ns)
        state = json.loads(path.read_text()); state['version'] = 100
        path.write_text(json.dumps(state))
        self.cmd('resource', 'status', code=2)
        self.assertEqual(json.loads(path.read_text())['version'], 100)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.cwd, text=True, stderr=subprocess.DEVNULL).strip()

    def review_setup(self):
        self.cwd = self.root / 'repo'; self.cwd.mkdir()
        self.git('init', '-b', 'master')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.cwd / '.gitignore').write_text('/current-plans\n/.worktrees\n/target\n')
        (self.cwd / 'file').write_text('base\n')
        self.git('add', '.'); self.git('commit', '-m', 'base')
        self.base = self.git('rev-parse', 'HEAD')
        task = self.root / 'task'
        self.git('worktree', 'add', '-b', 'task', str(task))
        self.cwd = task
        (task / 'file').write_text('changed\n'); self.git('commit', '-am', 'change')
        self.git('remote', 'add', 'origin', 'https://github.com/example/project.git')
        self.git('config', 'branch.task.remote', 'origin')
        self.sha = self.git('rev-parse', 'HEAD')
        self.metadata()
        self.stub('claude', 'pass\n')
        self.stub('codex', 'pass\n')
        self.stub('gh', "import os,json,sys\nfrom pathlib import Path\nif sys.argv[1:3]==['repo','view']: print(json.dumps({'nameWithOwner':'example/project'}))\nelse: print((Path(os.environ['TEST_ROOT'])/'pr.json').read_text())\n")
        real_git = subprocess.check_output(['which', 'git'], text=True).strip()
        self.stub('git', f"import os,sys\nif sys.argv[1]=='fetch': sys.exit(0)\nos.execv({real_git!r},[{real_git!r},*sys.argv[1:]])\n")
        self.stub('tmux', "import json,os,sys\nfrom pathlib import Path\np=Path(os.environ['TEST_ROOT'])/'windows'\nwith p.open('a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\nprint('@7')\n")
        self.brief = self.root / 'brief.md'; self.brief.write_text('Task requirements, not a PR-derived scope.\n')
        self.body = self.root / 'report.md'; self.body.write_text('Finding F1: examine error propagation.\n')

    def metadata(self):
        self.sha = self.git('rev-parse', 'HEAD')
        (self.root / 'pr.json').write_text(json.dumps({'number': 17, 'url': 'https://github.com/example/project/pull/17',
            'state': 'OPEN', 'headRefName': 'task', 'headRefOid': self.sha, 'baseRefOid': self.base,
            'headRepositoryOwner': {'login': 'example'}, 'headRepository': {'name': 'project'}}))

    def review(self, mode='auto', reviewer='claude', limit=3):
        return self.cmd('review', 'start', '--pr', '17', '--agent', 'implementer', '--reviewer', reviewer,
                        '--mode', mode, '--max-rounds', str(limit), '--brief', str(self.brief))

    def submit(self, review, verdict='findings'):
        current = review['rounds'][-1]
        return self.cmd('review', 'submit', review['id'], '--round', str(current['number']),
                        '--sha', current['sha'], '--verdict', verdict, '--body-file', str(self.body))

    def triage(self, review, action, unresolved=(), code=0):
        return self.cmd('review', 'triage', review['id'], '--agent', 'implementer', '--sha',
                        review['rounds'][-1]['sha'], '--body-file', str(self.body), '--action', action,
                        '--unresolved', *unresolved, code=code)

    def advance(self):
        with (self.cwd / 'file').open('a') as out: out.write('fix\n')
        self.git('commit', '-am', 'fix'); self.metadata()

    def test_review_freshness_worktree_report_and_collect_mode(self):
        self.review_setup()
        review = self.review(mode='collect')
        current = review['rounds'][0]
        self.assertEqual(subprocess.check_output(['git', '-C', current['worktree'], 'rev-parse', 'HEAD'], text=True).strip(), self.sha)
        self.assertTrue((Path(current['worktree']) / 'current-plans').is_symlink())
        self.cmd('review', 'submit', review['id'], '--round', '1', '--sha', self.base, '--verdict', 'clean', '--body-file', str(self.body), code=2)
        ready = self.submit(review)
        self.assertEqual(ready['status'], 'review_ready')
        self.assertEqual(self.cmd('review', 'wait', review['id'])['status'], 'review_ready')
        self.assertEqual(Path(ready['rounds'][0]['report']).read_text(), self.body.read_text())
        self.assertEqual(self.triage(ready, 'discuss')['status'], 'needs_discussion')

    def test_auto_loop_repeats_and_limit(self):
        self.review_setup()
        review = self.review(limit=2)
        self.submit(review); self.advance()
        review = self.triage(review, 'revise', ['F1'])
        self.assertEqual(len(review['rounds']), 2)
        self.submit(review); self.advance()
        review = self.triage(review, 'revise', ['F1'])
        self.assertEqual(review['status'], 'needs_discussion')
        self.assertEqual(self.cmd('review', 'next', review['id'], '--agent', 'implementer')['status'], 'round_limit')

    def test_unchanged_revision_stops_and_stale_completion_fails(self):
        self.review_setup()
        review = self.review()
        self.submit(review)
        self.assertEqual(self.triage(review, 'revise')['status'], 'needs_discussion')
        self.advance()
        review = self.cmd('review', 'next', review['id'], '--agent', 'implementer')
        self.submit(review); self.advance()
        self.triage(review, 'complete', code=2)

    def test_triage_mode_does_not_launch_another_round(self):
        self.review_setup()
        review = self.review(mode='triage', reviewer='codex')
        self.submit(review); self.advance()
        self.assertEqual(self.triage(review, 'revise')['status'], 'needs_revision')
        windows = [json.loads(line) for line in (self.root / 'windows').read_text().splitlines()]
        self.assertEqual(sum(args[0] == 'new-window' for args in windows), 1)

    def test_stop_keeps_report_available_without_restarting(self):
        self.review_setup(); review = self.review()
        self.cmd('review', 'stop-loop', review['id'], '--agent', 'implementer')
        self.assertEqual(self.submit(review)['status'], 'stopped')
        self.triage(review, 'revise', code=2)

    def test_worker_both_runtimes_and_failure_without_report(self):
        for runtime in ('claude', 'codex'):
            with self.subTest(runtime=runtime):
                if not hasattr(self, 'brief'): self.review_setup()
                self.stub(runtime, "import json,os,sys\nfrom pathlib import Path\n(Path(os.environ['TEST_ROOT'])/'launch.json').write_text(json.dumps(sys.argv[1:]))\n")
                review = self.review(reviewer=runtime)
                self.cmd('review', 'worker', review['id'], '--round', '1')
                result = self.cmd('review', 'status', review['id'])
                self.assertEqual(result['status'], 'failed')
                launched = json.loads((self.root / 'launch.json').read_text())
                self.assertIn('review submit', launched[-1])
                self.assertIn(self.sha, launched[-1])
                self.assertIn('local-compute', launched[-1])

    def test_dirty_unpushed_and_wrong_repository_heads_are_rejected(self):
        self.review_setup()
        (self.cwd / 'untracked').write_text('dirty')
        self.cmd('review', 'start', '--pr', '17', '--agent', 'a', '--reviewer', 'claude', '--brief', str(self.brief), code=2)
        (self.cwd / 'untracked').unlink()
        self.git('remote', 'set-url', 'origin', 'https://github.com/other/project.git')
        self.cmd('review', 'start', '--pr', '17', '--agent', 'a', '--reviewer', 'claude', '--brief', str(self.brief), code=2)


    def test_cancel_racing_with_grant_releases_only_unused_ticket(self):
        from coordination import resources
        self.define('server')
        first = self.acquire('first', 'server')
        ticket = self.acquire('second', 'server', code=3)
        store = Store(self.state)
        def interrupt(_seconds):
            resources.release(store, first, 'first')
            raise KeyboardInterrupt
        with patch('coordination.resources.time.sleep', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                resources.wait(store, ticket, 'second', 5)
        self.acquire('third', 'server')

    def test_real_tmux_handoff_with_both_stub_agents(self):
        self.review_setup()
        tmux = shutil.which('tmux', path=os.environ['PATH'])
        self.assertIsNotNone(tmux, 'tmux is required to verify reviewer window launch')
        socket = str(self.root / 'tmux.sock')
        subprocess.run([tmux, '-f', '/dev/null', '-S', socket, 'new-session', '-d', '-s', 'coord-test', 'sleep 60'], check=True)
        self.addCleanup(subprocess.run, [tmux, '-S', socket, 'kill-server'], capture_output=True)
        self.stub('tmux', f"import os,sys\nos.execv({tmux!r}, [{tmux!r},'-S',{socket!r},*sys.argv[1:]])\n")
        agent_body = """import json,os,shlex,subprocess,sys
from pathlib import Path
prompt=sys.argv[-1]
command=next(line for line in prompt.splitlines() if ' review submit ' in line)
args=shlex.split(command)
report=Path.cwd()/'target'/'review.md'; report.parent.mkdir(exist_ok=True)
report.write_text('Independent fixture review: no defects.\\n')
args[args.index('--body-file')+1]=str(report)
args[args.index('--verdict')+1]='clean'
subprocess.run(args,check=True)
"""
        for runtime in ('claude', 'codex'):
            self.stub(runtime, agent_body)
            # tmux's server environment predates the per-test PATH override.
            subprocess.run([tmux, '-S', socket, 'set-environment', 'PATH', self.env['PATH']], check=True)
            review = self.review(reviewer=runtime)
            ready = self.cmd('review', 'wait', review['id'], '--timeout', '10')
            self.assertEqual(ready['status'], 'review_ready')
            self.assertEqual(ready['rounds'][0]['verdict'], 'clean')
            self.assertEqual(self.triage(ready, 'complete')['status'], 'complete')



    def test_notification_failure_does_not_lose_publication(self):
        self.stub('codex', "import sys\nprint('No app server',file=sys.stderr)\nsys.exit(2)\n")
        self.cmd('agent', 'register', 'reader', '--codex-thread', 'session')
        self.cmd('topic', 'subscribe', 'news', '--agent', 'reader')
        body = self.root / 'body.md'
        body.write_text('Durable even if delivery fails.')
        published = self.cmd('topic', 'publish', 'news', '--agent', 'writer', '--title', 'Result',
                             '--body-file', str(body), '--notify')
        self.assertIn('delivery failed', published['delivery']['reader'])
        self.assertEqual(len(self.cmd('topic', 'read', 'news', '--agent', 'reader')['events']), 1)

    def test_failed_attempt_can_retry_same_sha(self):
        self.review_setup()
        review = self.review()
        self.cmd('review', 'worker', review['id'], '--round', '1')
        retry = self.cmd('review', 'next', review['id'], '--agent', 'implementer')
        self.assertEqual(retry['status'], 'waiting_review')
        self.assertEqual(retry['rounds'][1]['sha'], self.sha)
        self.submit(retry)
        self.triage(retry, 'discuss')
        rerun = self.cmd('review', 'next', review['id'], '--agent', 'implementer', '--allow-unchanged')
        self.assertEqual(rerun['status'], 'waiting_review')

    def test_default_state_is_shared_across_worktrees(self):
        self.review_setup()
        command = [sys.executable, str(SCRIPT), 'resource', 'define', 'fixture', '--description', 'Fixture']
        subprocess.run(command, cwd=self.cwd, env=self.env, capture_output=True, check=True)
        out = subprocess.check_output([sys.executable, str(SCRIPT), 'resource', 'status'],
                                      cwd=self.root / 'repo', env=self.env, text=True)
        self.assertIn('fixture', json.loads(out)['resources'])
        self.assertTrue((self.root / 'repo' / '.git' / 'agent-coordination' / 'state.json').exists())


if __name__ == '__main__':
    unittest.main()
