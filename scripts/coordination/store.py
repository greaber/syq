import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import uuid


class Error(Exception):
    pass


def run(*args, cwd=None):
    process = subprocess.Popen(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = process.communicate(timeout=60)
    except BaseException:
        # These short CLI helpers must not leave fetch/transport children behind.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if process.returncode:
        raise Error(f'{args[0]} failed: {err.strip() or out.strip()}')
    return out.strip()


def name(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', value):
        raise Error('Names must use 1–96 letters, digits, dots, underscores or hyphens')
    return value


def identifier(prefix):
    return prefix + '-' + uuid.uuid4().hex[:16]


def atomic(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.write-')
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Store:
    def __init__(self, root=None):
        if root is None:
            common = Path(run('git', 'rev-parse', '--git-common-dir')).resolve()
            root = common / 'agent-coordination'
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    @contextlib.contextmanager
    def locked(self):
        with (self.root / 'state.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            path = self.root / 'state.json'
            state = json.loads(path.read_text()) if path.exists() else {
                'version': 1, 'agents': {}, 'resources': {}, 'requests': {},
                'topics': {}, 'reviews': {},
            }
            if state.get('version') != 1:
                raise Error('Unsupported coordination state version; use its matching tool')
            before = json.dumps(state, sort_keys=True)
            yield state
            if not path.exists() or json.dumps(state, sort_keys=True) != before:
                atomic(path, json.dumps(state, indent=2) + '\n')

    def document(self, relative, text):
        path = self.root / relative
        atomic(path, text)
        return str(path)


def publish(store, state, topic, author, title, body):
    topic = name(topic)
    entry = state['topics'].setdefault(topic, {'events': [], 'subscribers': {}})
    seq = len(entry['events']) + 1
    path = store.document(f'topics/{topic}/{seq}.md', body)
    event = {'sequence': seq, 'author': author, 'title': title, 'path': path,
             'time': time.time()}
    entry['events'].append(event)
    return event


def notify(store, agents, message):
    """Notifications are hints. A failed delivery never rolls back publication."""
    with store.locked() as state:
        targets = {a: state['agents'].get(a, {}) for a in set(agents)}
    results = {}
    for agent, endpoint in targets.items():
        if not endpoint.get('codex_thread'):
            results[agent] = 'available in shared files; no push endpoint'
            continue
        cmd = ['codex', 'queue', '--thread', endpoint['codex_thread'], '--message', message]
        if endpoint.get('remote'):
            cmd += ['--remote', endpoint['remote']]
        try:
            run(*cmd)
            results[agent] = 'queued (not an acknowledgment of reading)'
        except (Error, subprocess.TimeoutExpired, OSError) as exc:
            results[agent] = f'delivery failed: {exc}'
    return results
