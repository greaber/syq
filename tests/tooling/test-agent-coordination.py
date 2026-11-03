#!/usr/bin/env python3
"""Exercise public commands with real processes, Git worktrees and disposable state."""
from support import SCRIPTS

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

SCRIPT = SCRIPTS / 'agent-coordination.py'
sys.path.insert(0, str(SCRIPT.parent))
from coordination.store import Store


FIXTURE_REVIEWER = """import json,os,shlex,subprocess,sys,time
from pathlib import Path
root=Path(os.environ['TEST_ROOT'])
runtime=Path(sys.argv[0]).name
with (root/'launches').open('a') as out:
 out.write(json.dumps({'review':os.environ['SYQ_REVIEW_ID'],'runtime':runtime,'argv':sys.argv[1:],
  'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
  'env':sorted(k for k in os.environ if k.startswith(('CLAUDE','CODEX')))})+'\\n')
behavior=os.environ.get('FIXTURE_REVIEWER','submit')
if behavior=='fail-early': sys.exit(1)
if runtime=='codex': event={'type':'thread.started','thread_id':'fixture-codex-session'}
else:
 flag=next(f for f in ('--session-id','--resume') if f in sys.argv)
 event={'type':'system','subtype':'init','session_id':sys.argv[sys.argv.index(flag)+1]}
print(json.dumps(event),flush=True)
if behavior=='fail': sys.exit(1)
if behavior=='hold':
 deadline=time.monotonic()+30
 while not (root/'release').exists() and time.monotonic()<deadline: time.sleep(0.05)
 sys.exit(0)
args=shlex.split(next(line for line in sys.argv[-1].splitlines() if ' review submit ' in line))
report=Path.cwd()/'target'/'review.md'; report.parent.mkdir(exist_ok=True)
report.write_text('Finding F1: examine error propagation.\\n')
args[args.index('--body-file')+1]=str(report)
subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
"""


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

    def cmd(self, *args, code=0, behavior=None):
        env = self.env if behavior is None else dict(self.env, FIXTURE_REVIEWER=behavior)
        result = subprocess.run([sys.executable, str(SCRIPT), '--state-dir', str(self.state), *args],
                                cwd=self.cwd, env=env, capture_output=True, text=True, timeout=15)
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

    def test_shared_claims_exclusive_waiter_and_fairness(self):
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

    def test_wait_timeout_keeps_ticket_and_signal_withdraws(self):
        self.define('server')
        owner = self.acquire('owner', 'server')
        ticket = self.acquire('waiting', 'server', code=3)
        self.cmd('resource', 'wait', ticket, '--agent', 'waiting', '--timeout', '1', code=2)
        states = {r['id']: r['status'] for r in self.cmd('resource', 'status')['requests']}
        self.assertEqual(states[ticket], 'queued')
        self.cmd('resource', 'cancel', ticket, '--agent', 'waiting')
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

    def test_timeout_preserves_exclusive_waiters_priority(self):
        self.define('resource')
        first = self.acquire('first', 'resource', mode='shared')
        queued = self.cmd('resource', 'acquire', 'resource', '--agent', 'exclusive', '--wait', '1', code=2)
        self.assertIn('ticket retained', queued['error'])
        requests = self.cmd('resource', 'status')['requests']
        ticket = next(r['id'] for r in requests if r['agent'] == 'exclusive')
        later = self.acquire('later', 'resource', mode='shared', code=3)
        self.cmd('resource', 'wait', ticket, '--agent', 'exclusive', '--timeout', '1', code=2)
        self.cmd('resource', 'release', first, '--agent', 'first')
        self.assertEqual(self.cmd('resource', 'wait', ticket, '--agent', 'exclusive')['status'], 'held')
        states = {r['id']: r['status'] for r in self.cmd('resource', 'status')['requests']}
        self.assertEqual(states[later], 'queued')
        self.cmd('resource', 'release', ticket, '--agent', 'exclusive')
        self.assertEqual(self.cmd('resource', 'wait', later, '--agent', 'later')['status'], 'held')

    def test_unknown_topic_operations_do_not_create_topics(self):
        self.cmd('topic', 'subscribe', 'known', '--agent', 'reader')
        for action in ('read', 'ack', 'unsubscribe'):
            args = ('1',) if action == 'ack' else ()
            result = self.cmd('topic', action, 'typo', *args, '--agent', 'reader', code=2)
            self.assertIn('Unknown topic', result['error'])
        self.assertEqual(set(self.cmd('topic', 'list')), {'known'})

    def test_topic_wait_preserves_updates_on_timeout_and_interrupt(self):
        self.cmd('topic', 'subscribe', 'updates', '--agent', 'reader')
        self.cmd('topic', 'wait', 'updates', '--agent', 'reader', '--timeout', '1', code=2)
        process = subprocess.Popen([sys.executable, str(SCRIPT), '--state-dir', str(self.state),
            'topic', 'wait', 'updates', '--agent', 'reader', '--timeout', '10'],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertIn('Waiting for topic', process.stderr.readline())
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130)
        body = self.root / 'update.md'; body.write_text('Relevant coordination update')
        self.cmd('topic', 'publish', 'updates', '--agent', 'writer', '--title', 'Ready', '--body-file', str(body))
        first = self.cmd('topic', 'wait', 'updates', '--agent', 'reader', '--timeout', '1')
        self.assertEqual(len(first['events']), 1)
        self.assertEqual(first, self.cmd('topic', 'wait', 'updates', '--agent', 'reader', '--timeout', '1'))
        self.cmd('topic', 'ack', 'updates', '1', '--agent', 'reader')
        self.cmd('topic', 'wait', 'updates', '--agent', 'reader', '--timeout', '1', code=2)
        self.assertIn('reader', self.cmd('topic', 'list')['updates']['subscribers'])

    @staticmethod
    def running_processes(groups):
        # An exited process stays in its group as a zombie until its parent
        # reaps it, and os.killpg(group, 0) still finds it. A zombie writes
        # nothing more, and an orphaned worker's new parent may be slow to reap it.
        result = subprocess.run(['ps', '-A', '-o', 'pgid=,stat=,pid=,command='],
                                capture_output=True, text=True, check=True, timeout=5)
        running = {}
        for line in result.stdout.splitlines():
            pgid, stat, process = line.split(None, 2)
            if int(pgid) in groups and not stat.startswith('Z'):
                running.setdefault(int(pgid), []).append(f'{process} ({stat})')
        return running

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.cwd, text=True, stderr=subprocess.DEVNULL).strip()

    def metadata(self):
        self.sha = self.git('rev-parse', 'HEAD')
        (self.root / 'pr.json').write_text(json.dumps({'number': 17, 'url': 'https://github.com/example/project/pull/17',
            'state': 'OPEN', 'headRefName': 'task', 'headRefOid': self.sha, 'baseRefOid': self.base,
            'headRepositoryOwner': {'login': 'example'}, 'headRepository': {'name': 'project'}}))

    def advance(self):
        with (self.cwd / 'file').open('a') as out: out.write('fix\n')
        self.git('commit', '-am', 'fix'); self.metadata()

    def submit(self, review, verdict='findings'):
        current = review['rounds'][-1]
        return self.cmd('review', 'submit', review['id'], '--round', str(current['number']),
                        '--sha', current['sha'], '--verdict', verdict, '--body-file', str(self.body))

    def triage(self, review, action, unresolved=(), code=0):
        return self.cmd('review', 'triage', review['id'], '--agent', 'implementer', '--sha',
                        review['rounds'][-1]['sha'], '--body-file', str(self.body), '--action', action,
                        '--unresolved', *unresolved, code=code)

    def test_dirty_unpushed_and_wrong_repository_heads_are_rejected(self):
        self.review_setup()
        (self.cwd / 'untracked').write_text('dirty')
        self.cmd('review', 'start', '--pr', '17', '--agent', 'a', '--reviewer', 'claude', '--brief', str(self.brief), code=2)
        (self.cwd / 'untracked').unlink()
        self.git('remote', 'set-url', 'origin', 'https://github.com/other/project.git')
        self.cmd('review', 'start', '--pr', '17', '--agent', 'a', '--reviewer', 'claude', '--brief', str(self.brief), code=2)

    def test_default_state_is_shared_across_worktrees(self):
        self.review_setup()
        command = [sys.executable, str(SCRIPT), 'resource', 'define', 'fixture', '--description', 'Fixture']
        subprocess.run(command, cwd=self.cwd, env=self.env, capture_output=True, check=True)
        out = subprocess.check_output([sys.executable, str(SCRIPT), 'resource', 'status'],
                                      cwd=self.root / 'repo', env=self.env, text=True)
        self.assertIn('fixture', json.loads(out)['resources'])
        self.assertTrue((self.root / 'repo' / '.git' / 'agent-coordination' / 'state.json').exists())

    def test_fetch_preserves_configured_transport_for_head_and_fork_base(self):
        self.review_setup()
        head_url = 'git@github.com:example/project.git'
        base_url = 'ssh://git@github.com/upstream/project.git'
        self.git('remote', 'set-url', 'origin', head_url)
        self.git('remote', 'set-url', '--push', 'origin', 'https://github.com/example/project.git')
        self.git('remote', 'add', 'upstream', base_url)
        self.stub('gh', "import os,json,sys\nfrom pathlib import Path\nif sys.argv[1:3]==['repo','view']: print(json.dumps({'nameWithOwner':'upstream/project'}))\nelse: print((Path(os.environ['TEST_ROOT'])/'pr.json').read_text())\n")
        real_git = shutil.which('git')
        self.stub('git', f"import json,os,sys\nfrom pathlib import Path\nif sys.argv[1]=='fetch':\n with (Path(os.environ['TEST_ROOT'])/'fetches').open('a') as out: out.write(json.dumps(sys.argv[2:])+'\\n')\n sys.exit(0)\nos.execv({real_git!r},[{real_git!r},*sys.argv[1:]])\n")
        self.review()
        fetches = [json.loads(line) for line in (self.root / 'fetches').read_text().splitlines()]
        self.assertEqual(fetches, [[head_url, self.sha], [base_url, self.base]])

    def test_effort_must_be_a_level_name(self):
        # Codex receives the level inside a TOML string.
        result = subprocess.run([sys.executable, str(SCRIPT), '--state-dir', str(self.state), 'review', 'start',
                                 '--pr', '17', '--agent', 'a', '--brief', 'brief.md', '--effort', 'high"'],
                                cwd=self.cwd, env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('level name', result.stderr)

    def stop_workers(self):
        # Reviewer workers run detached from the command that launched them.
        # Release held fixture reviewers and wait for every recorded worker's
        # process group, so none outlives the test or writes into its removed state.
        (self.root / 'release').touch()
        path = self.state / 'state.json'
        if not path.exists():
            return
        groups = {r['pid'] for review in json.loads(path.read_text())['reviews'].values()
                  for r in review['rounds'] if 'pid' in r}
        running = {}
        try:
            for signum in (None, signal.SIGTERM, signal.SIGKILL):
                for group in groups if signum else ():
                    try:
                        os.killpg(group, signum)
                    except ProcessLookupError:
                        pass
                deadline = time.monotonic() + 10
                next_progress = 0
                while groups and time.monotonic() < deadline:
                    running = self.running_processes(groups)
                    groups = set(running)
                    if groups:
                        now = time.monotonic()
                        if now >= next_progress:
                            print(f'Waiting for fixture reviewer workers: {sorted(groups)}', flush=True)
                            next_progress = now + 1
                        time.sleep(0.05)
                if not groups:
                    break
            self.assertFalse(groups, f'Fixture reviewer workers did not exit: {running}')
        finally:
            self.assertFalse((self.root / 'tmux-calls').exists(), 'Reviews must not use tmux')

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
        # The fixture reviewer records each launch, reports its session as
        # claude -p --output-format stream-json and codex exec --json do, and
        # then behaves as FIXTURE_REVIEWER says: submit a report (the default),
        # fail, or hold until the test releases it. fail-early exits before
        # reporting a session, like a bad option or an authentication error.
        for runtime in ('claude', 'codex'):
            self.stub(runtime, FIXTURE_REVIEWER)
        self.stub('tmux', "import os\nfrom pathlib import Path\n(Path(os.environ['TEST_ROOT'])/'tmux-calls').touch()\n")
        self.stub('gh', "import os,json,sys\nfrom pathlib import Path\nif sys.argv[1:3]==['repo','view']: print(json.dumps({'nameWithOwner':'example/project'}))\nelse: print((Path(os.environ['TEST_ROOT'])/'pr.json').read_text())\n")
        real_git = subprocess.check_output(['which', 'git'], text=True).strip()
        self.stub('git', f"import os,sys\nif sys.argv[1]=='fetch': sys.exit(0)\nos.execv({real_git!r},[{real_git!r},*sys.argv[1:]])\n")
        self.brief = self.root / 'brief.md'; self.brief.write_text('Task requirements, not a PR-derived scope.\n')
        self.body = self.root / 'report.md'; self.body.write_text('Finding F1: examine error propagation.\n')
        self.addCleanup(self.stop_workers)

    def review(self, mode='auto', reviewer='claude', limit=3, additional=False, extra=(), behavior=None, code=0):
        return self.cmd('review', 'start', '--pr', '17', '--agent', 'implementer',
                        *(['--reviewer', reviewer] if reviewer else []),
                        '--mode', mode, '--max-rounds', str(limit), '--brief', str(self.brief),
                        *(['--additional-reviewer'] if additional else []), *extra,
                        behavior=behavior, code=code)

    def wait(self, review, status='review_ready'):
        result = self.cmd('review', 'wait', review['id'], '--timeout', '10')
        self.assertEqual(result['status'], status, result)
        return result

    def launches(self):
        path = self.root / 'launches'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def wait_launched(self, review):
        # The worker starts the reviewer after review start returns.
        deadline = time.monotonic() + 10
        print('Waiting for the fixture reviewer to start', flush=True)
        while not any(c['review'] == review['id'] for c in self.launches()):
            self.assertLess(time.monotonic(), deadline, 'Fixture reviewer did not start before the deadline')
            time.sleep(0.05)

    def test_review_freshness_worktree_report_and_collect_mode(self):
        self.review_setup()
        review = self.review(mode='collect', behavior='hold')
        current = review['rounds'][0]
        self.assertEqual(subprocess.check_output(['git', '-C', current['worktree'], 'rev-parse', 'HEAD'], text=True).strip(), self.sha)
        self.assertTrue((Path(current['worktree']) / 'current-plans').is_symlink())
        self.cmd('review', 'submit', review['id'], '--round', '1', '--sha', self.base, '--verdict', 'clean', '--body-file', str(self.body), code=2)
        ready = self.submit(review)
        self.assertEqual(ready['status'], 'review_ready')
        self.assertIn('End your turn now', ready['reviewer_next_action'])
        self.assertEqual(self.cmd('review', 'wait', review['id'])['status'], 'review_ready')
        self.assertEqual(Path(ready['rounds'][0]['report']).read_text(), self.body.read_text())
        self.assertEqual(self.triage(ready, 'discuss')['status'], 'needs_discussion')

    def test_auto_loop_repeats_and_limit(self):
        self.review_setup()
        review = self.wait(self.review(limit=2))
        self.advance()
        review = self.triage(review, 'revise', ['F1'])
        self.assertEqual(len(review['rounds']), 2)
        review = self.wait(review)
        self.advance()
        review = self.triage(review, 'revise', ['F1'])
        self.assertEqual(review['status'], 'needs_discussion')
        self.assertEqual(self.cmd('review', 'next', review['id'], '--agent', 'implementer')['status'], 'round_limit')

    def test_unchanged_revision_stops_and_stale_completion_fails(self):
        self.review_setup()
        review = self.wait(self.review())
        self.assertEqual(self.triage(review, 'revise')['status'], 'needs_discussion')
        self.advance()
        review = self.wait(self.cmd('review', 'next', review['id'], '--agent', 'implementer'))
        self.advance()
        self.triage(review, 'complete', code=2)

    def test_triage_mode_does_not_launch_another_round(self):
        self.review_setup()
        review = self.wait(self.review(mode='triage', reviewer='codex'))
        self.advance()
        self.assertEqual(self.triage(review, 'revise')['status'], 'needs_revision')
        self.assertEqual(len(self.launches()), 1)

    def test_stop_keeps_report_available_without_restarting(self):
        self.review_setup(); review = self.review(behavior='hold')
        self.cmd('review', 'stop-loop', review['id'], '--agent', 'implementer')
        self.assertEqual(self.submit(review)['status'], 'stopped')
        self.triage(review, 'revise', code=2)

    def test_failed_reviewer_reports_its_log_for_both_runtimes(self):
        self.review_setup()
        for runtime in ('claude', 'codex'):
            with self.subTest(runtime=runtime):
                review = self.review(reviewer=runtime, additional=True, behavior='fail')
                failed = self.wait(review, 'failed')
                self.assertFalse(failed['running'])
                self.assertEqual(failed['rounds'][0]['exit_code'], 1)
                self.assertIn('without publishing a report', failed['reason'])
                self.assertIn(failed['log'], failed['next_action'])
                self.assertIn(f'round 1: {runtime} ', Path(failed['log']).read_text())
                prompt = self.launches()[-1]['argv'][-1]
                self.assertIn('review submit', prompt)
                self.assertIn(self.sha, prompt)
                self.assertNotIn('topic wait', prompt)
                self.assertNotIn('Acquire shared local-compute', prompt)

    def test_sigterm_to_the_worker_ends_its_reviewer(self):
        self.review_setup()
        review = self.review(behavior='hold')
        self.wait_launched(review)
        self.assertTrue(self.cmd('review', 'status', review['id'])['running'])
        os.kill(review['pid'], signal.SIGTERM)
        failed = self.wait(review, 'failed')
        self.assertFalse(failed['running'])
        self.assertIn('interrupted', failed['reason'])
        self.assertEqual(self.running_processes({review['pid']}), {})

    def test_reviewer_outliving_a_killed_worker_counts_as_running_until_stopped(self):
        self.review_setup()
        review = self.review(behavior='hold')
        self.wait_launched(review)
        os.kill(review['pid'], signal.SIGKILL)
        current = self.cmd('review', 'status', review['id'])
        self.assertEqual((current['status'], current['running']), ('waiting_review', True))
        self.cmd('review', 'resume', review['id'], '--agent', 'implementer', code=2)
        self.cmd('review', 'stop', review['id'], '--agent', 'other', code=2)
        stopped = self.cmd('review', 'stop', review['id'], '--agent', 'implementer')
        self.assertEqual((stopped['status'], stopped['running']), ('failed', False))
        self.assertIn('review stop', stopped['reason'])
        self.assertEqual(self.running_processes({review['pid']}), {})
        self.cmd('review', 'resume', review['id'], '--agent', 'implementer')
        self.wait(review)
        self.assertFalse(self.cmd('review', 'stop', review['id'], '--agent', 'implementer')['running'])

    def test_reviewer_that_fails_before_its_session_starts_gets_a_new_one(self):
        self.review_setup()
        for runtime in ('claude', 'codex'):
            with self.subTest(runtime=runtime):
                review = self.review(reviewer=runtime, additional=True, behavior='fail-early')
                failed = self.wait(review, 'failed')
                self.assertFalse(failed['session_started'])
                self.cmd('review', 'resume', review['id'], '--agent', 'implementer')
                ready = self.wait(review)
                self.assertTrue(ready['session_started'])
                calls = [c['argv'] for c in self.launches() if c['review'] == review['id']]
                self.assertEqual(len(calls), 2)
                for argv in calls:
                    if runtime == 'claude':
                        self.assertNotIn('--resume', argv)
                        self.assertEqual(argv[argv.index('--session-id') + 1], review['session_id'])
                    else:
                        self.assertNotIn('resume', argv)
                self.assertEqual(ready['session_id'], review['session_id'] if runtime == 'claude'
                                 else 'fixture-codex-session')

    def test_two_reviewers_resume_their_own_sessions_across_rounds(self):
        self.review_setup()
        first = self.review(reviewer='claude')
        self.review(reviewer='codex', code=2)
        second = self.review(reviewer='codex', additional=True)
        reviewers = [self.wait(r) for r in (first, second)]
        self.assertNotEqual(reviewers[0]['rounds'][0]['worktree'], reviewers[1]['rounds'][0]['worktree'])
        self.advance()
        for review in reviewers:
            self.triage(review, 'revise')
        for review in reviewers:
            ready = self.wait(review)
            self.assertEqual(ready['rounds'][1]['worktree'], ready['rounds'][0]['worktree'])
            self.assertEqual(self.triage(ready, 'complete')['status'], 'complete')
        launches = self.launches()
        for review, runtime in zip(reviewers, ('claude', 'codex')):
            calls = [c for c in launches if c['review'] == review['id']]
            self.assertEqual([c['runtime'] for c in calls], [runtime, runtime])
            self.assertNotEqual(calls[0]['head'], self.sha)
            self.assertEqual(calls[1]['head'], self.sha)
            self.assertIn('round 2', calls[1]['argv'][-1])
            if runtime == 'claude':
                session = review['session_id']
                self.assertEqual(calls[0]['argv'][calls[0]['argv'].index('--session-id') + 1], session)
                self.assertEqual(calls[1]['argv'][calls[1]['argv'].index('--resume') + 1], session)
            else:
                self.assertNotIn('resume', calls[0]['argv'])
                self.assertEqual(calls[1]['argv'][calls[1]['argv'].index('resume') + 1], 'fixture-codex-session')
        codex = self.cmd('review', 'status', second['id'])
        self.assertEqual(codex['session_id'], 'fixture-codex-session')

    def test_reviewer_settings_reach_launch_and_resume(self):
        self.review_setup()
        # The requesting agent's own session must not leak into the reviewer;
        # ordinary configuration such as CLAUDE_CONFIG_DIR still reaches it.
        for key in [k for k in self.env if k.startswith(('CLAUDE', 'CODEX'))]:
            del self.env[key]
        self.env.update(CLAUDECODE='1', CLAUDE_CODE_SESSION_ID='requester', CODEX_THREAD_ID='requester',
                        CLAUDE_CONFIG_DIR=str(self.root / 'claude-config'))
        tricky = 'two words; "quoted" $(touch injected) | cat'
        claude_skip, codex_skip = '--dangerously-skip-permissions', '--dangerously-bypass-approvals-and-sandbox'
        # (reviewer flag, review start arguments, expected settings before the tool's own arguments)
        requests = [
            (None, [], ['--model', 'claude-opus-5-5', '--effort', 'xhigh', claude_skip]),
            ('codex', [], ['--model', 'gpt-6-astra', '-c', 'model_reasoning_effort="xhigh"', codex_skip]),
            ('claude', ['--model', 'claude-fixture', '--effort', 'high', '--reviewer-option=--append-system-prompt',
                        f'--reviewer-option={tricky}'],
             ['--model', 'claude-fixture', '--effort', 'high', claude_skip, '--append-system-prompt', tricky]),
            ('codex', ['--model', 'gpt-6.1-sol', '--effort', 'medium', '--reviewer-option=--strict-config'],
             ['--model', 'gpt-6.1-sol', '-c', 'model_reasoning_effort="medium"', codex_skip, '--strict-config'])]
        started = [self.review(reviewer=reviewer, extra=extra, additional=bool(index), behavior='fail')
                   for index, (reviewer, extra, _settings) in enumerate(requests)]
        self.assertEqual([r['reviewer'] for r in started], ['claude', 'codex', 'claude', 'codex'])
        self.assertEqual([(r['model'], r['effort'], r['reviewer_options']) for r in started],
                         [('claude-opus-5-5', 'xhigh', []), ('gpt-6-astra', 'xhigh', []),
                          ('claude-fixture', 'high', ['--append-system-prompt', tricky]),
                          ('gpt-6.1-sol', 'medium', ['--strict-config'])])
        for review in started:
            failed = self.wait(review, 'failed')
            self.cmd('review', 'resume', review['id'], '--agent', 'implementer', '--session', 'wrong-session', code=2)
            self.assertEqual(self.cmd('review', 'status', review['id'])['session_id'], failed['session_id'])
            resumed = self.cmd('review', 'resume', review['id'], '--agent', 'implementer')
            self.assertEqual(len(resumed['rounds']), 1)
            ready = self.wait(review)
            self.assertEqual(ready['rounds'][0]['report'], str(self.state / 'reviews' / review['id'] / 'round-1' / 'report.md'))
        launches = {}
        for call in self.launches():
            launches.setdefault(call['review'], []).append(call)
        state = str(self.state)
        for review, (_reviewer, _extra, settings) in zip(started, requests):
            runtime, rid = review['reviewer'], review['id']
            session = self.cmd('review', 'status', rid)['session_id']
            if runtime == 'claude':
                expected = [['-p', '--output-format', 'stream-json', '--verbose', *settings, '--add-dir', state,
                             flag, session, '--name', rid] for flag in ('--session-id', '--resume')]
            else:
                expected = [['exec', '--json', *settings, '--add-dir', state],
                            ['exec', '--add-dir', state, 'resume', session, '--json', *settings]]
            calls = launches[rid]
            self.assertEqual([(c['runtime'], c['argv'][:-1]) for c in calls], [(runtime, argv) for argv in expected])
            for call in calls:
                self.assertEqual(call['env'], ['CLAUDE_CONFIG_DIR'])
        self.assertFalse(any(self.root.rglob('injected')))

    def test_failed_attempt_can_retry_same_sha(self):
        self.review_setup()
        review = self.wait(self.review(behavior='fail'), 'failed')
        retry = self.cmd('review', 'next', review['id'], '--agent', 'implementer')
        self.assertEqual(retry['status'], 'waiting_review')
        self.assertEqual(retry['rounds'][1]['sha'], self.sha)
        retry = self.wait(retry)
        self.triage(retry, 'discuss')
        rerun = self.cmd('review', 'next', review['id'], '--agent', 'implementer', '--allow-unchanged')
        self.assertEqual(rerun['status'], 'waiting_review')
        self.wait(rerun)

    def test_rounds_reuse_checkout_and_preserve_build_artifacts(self):
        self.review_setup()
        review = self.review(behavior='hold')
        worktree = Path(review['rounds'][0]['worktree'])
        artifact = worktree / 'target' / 'incremental' / 'fixture'
        artifact.parent.mkdir(parents=True)
        artifact.write_text('Existing build artifact')
        first_sha = review['rounds'][0]['sha']
        self.submit(review)
        (self.root / 'release').touch()
        self.advance()
        second = self.wait(self.triage(review, 'revise'))
        self.assertEqual(second['rounds'][1]['worktree'], str(worktree))
        self.assertEqual(len(self.launches()), 2)
        self.assertEqual(artifact.read_text(), 'Existing build artifact')
        head = subprocess.check_output(['git', '-C', str(worktree), 'rev-parse', 'HEAD'], text=True).strip()
        self.assertEqual(head, self.sha)
        self.assertEqual(second['rounds'][0]['sha'], first_sha)
        self.assertTrue(Path(second['rounds'][0]['report']).is_file())
        entries = [line for line in self.git('worktree', 'list', '--porcelain').splitlines() if line.startswith('worktree ')]
        self.assertEqual(len(entries), 3)  # coordination checkout, implementation, review

    def test_dirty_review_checkout_is_not_discarded(self):
        self.review_setup()
        review = self.wait(self.review())
        worktree = Path(review['rounds'][0]['worktree'])
        (worktree / 'file').write_text('Keep this edit')
        (worktree / 'untracked').write_text('Keep this file too')
        self.advance()
        self.triage(review, 'revise', code=2)
        self.assertEqual((worktree / 'file').read_text(), 'Keep this edit')
        self.assertEqual((worktree / 'untracked').read_text(), 'Keep this file too')

    def test_review_checkout_commits_are_not_abandoned(self):
        self.review_setup()
        review = self.wait(self.review())
        worktree = Path(review['rounds'][0]['worktree'])
        subprocess.run(['git', '-C', str(worktree), 'commit', '--allow-empty', '-m', 'Reviewer work'],
                       check=True, capture_output=True)
        head = subprocess.check_output(['git', '-C', str(worktree), 'rev-parse', 'HEAD'], text=True)
        self.advance()
        self.triage(review, 'revise', code=2)
        self.assertEqual(subprocess.check_output(
            ['git', '-C', str(worktree), 'rev-parse', 'HEAD'], text=True), head)

    def test_failed_attempts_do_not_exhaust_completed_round_limit(self):
        self.review_setup()
        review = self.wait(self.review(limit=1, behavior='fail'), 'failed')
        self.wait(self.cmd('review', 'next', review['id'], '--agent', 'implementer', behavior='fail'), 'failed')
        review = self.wait(self.cmd('review', 'next', review['id'], '--agent', 'implementer'))
        self.assertEqual(review['rounds'][-1]['number'], 3)
        self.advance()
        self.assertEqual(self.triage(review, 'revise')['status'], 'round_limit')
        self.cmd('review', 'next', review['id'], '--agent', 'implementer', code=2)

    def test_interactive_reviewer_from_earlier_version_can_finish(self):
        # Shape a request like one an earlier, tmux-based version left running:
        # no process ID, a live-worker flag, and a pane.
        self.review_setup()
        review = self.review(behavior='hold')
        (self.root / 'release').touch()
        self.wait(review, 'failed')
        path = self.state / 'state.json'
        state = json.loads(path.read_text())
        record = state['reviews'][review['id']]
        record.update(status='waiting_review', worker_alive=True, worker_started=True, pane='%7',
                      window='@7', inbox=review['id'] + '.inbox')
        for key in ('reason', 'session_started'):
            record.pop(key)
        for key in ('pid', 'log', 'exit_code'):
            record['rounds'][0].pop(key)
        record['rounds'][0].update(status='running', sequence=1, window='@7')
        path.write_text(json.dumps(state))
        self.assertTrue(self.cmd('review', 'status', review['id'])['running'])
        self.cmd('review', 'wait', review['id'], '--timeout', '1', code=2)
        self.assertIn('tmux pane %7', self.cmd('review', 'stop', review['id'], '--agent', 'implementer', code=2)['error'])
        self.assertEqual(self.submit(review)['status'], 'review_ready')
        self.advance()
        blocked = self.triage(review, 'revise', code=2)
        self.assertIn('tmux pane %7', blocked['error'])
        self.assertEqual(self.cmd('review', 'status', review['id'])['status'], 'review_ready')
        # Its worker clears the flag once that interactive reviewer exits.
        state = json.loads(path.read_text())
        state['reviews'][review['id']]['worker_alive'] = False
        path.write_text(json.dumps(state))
        ready = self.wait(self.triage(review, 'revise'))
        self.assertEqual(len(ready['rounds']), 2)
        call = self.launches()[-1]
        self.assertEqual(call['argv'][call['argv'].index('--resume') + 1], review['session_id'])


if __name__ == '__main__':
    unittest.main()
