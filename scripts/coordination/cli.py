import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from . import resources, reviews
from .store import Error, Store, name, notify, publish


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('Must be positive')
    return number


def parser():
    root = argparse.ArgumentParser(description='Local agent coordination; state is shared across Git worktrees.')
    root.add_argument('--state-dir', default=os.environ.get('SYQ_COORDINATION_DIR'),
                      help='Default: common Git directory agent-coordination')
    groups = root.add_subparsers(dest='group', required=True)
    agent = groups.add_parser('agent').add_subparsers(dest='action', required=True)
    p = agent.add_parser('register', help='Optional Codex delivery endpoint; otherwise use shared-file reads/waits')
    p.add_argument('agent')
    p.add_argument('--codex-thread')
    p.add_argument('--remote')
    resource = groups.add_parser('resource').add_subparsers(dest='action', required=True)
    p = resource.add_parser('define', help='Define only after reconciling current users and reservations')
    p.add_argument('name')
    p.add_argument('--description', required=True)
    resource.add_parser('status')
    p = resource.add_parser('acquire')
    p.add_argument('resources', nargs='+')
    p.add_argument('--agent', required=True)
    p.add_argument('--mode', choices=['shared', 'exclusive'], default='exclusive')
    p.add_argument('--wait', type=positive, metavar='SECONDS')
    for action in ('wait', 'release', 'cancel'):
        p = resource.add_parser(action)
        p.add_argument('ticket')
        p.add_argument('--agent', required=True)
        if action == 'wait':
            p.add_argument('--timeout', type=positive, default=60)
    topic = groups.add_parser('topic').add_subparsers(dest='action', required=True)
    topic.add_parser('list')
    for action in ('subscribe', 'unsubscribe', 'read', 'ack', 'wait'):
        p = topic.add_parser(action)
        p.add_argument('topic')
        p.add_argument('--agent', required=True)
        if action == 'wait':
            p.add_argument('--timeout', type=positive, default=60)
        if action == 'ack':
            p.add_argument('sequence', type=int)
    p = topic.add_parser('publish')
    p.add_argument('topic')
    p.add_argument('--agent', required=True)
    p.add_argument('--title', required=True)
    p.add_argument('--body-file', required=True)
    p.add_argument('--notify', action='store_true')
    review = groups.add_parser('review').add_subparsers(dest='action', required=True)
    review.add_parser('list')
    p = review.add_parser('start', help='Launch reviewer in a new tmux window; requester drives triage/auto loop')
    p.add_argument('--pr', type=positive, required=True)
    p.add_argument('--agent', required=True)
    p.add_argument('--brief', required=True, help='Markdown task context, including actual requirements and open questions')
    p.add_argument('--reviewer', choices=['claude', 'codex'], required=True)
    p.add_argument('--additional-reviewer', action='store_true',
                   help='Explicitly start another independent reviewer for this task')
    p.add_argument('--mode', choices=['collect', 'triage', 'auto'], default='triage')
    p.add_argument('--max-rounds', type=positive, default=3)
    p.add_argument('--notify', action='store_true', help='Also queue a hint to the requesting agent’s registered Codex endpoint')
    for action in ('status', 'wait', 'next', 'stop-loop', 'worker', 'resume', 'bind-session'):
        p = review.add_parser(action)
        p.add_argument('id')
        if action == 'wait':
            p.add_argument('--timeout', type=positive, default=60)
        if action in ('next', 'stop-loop', 'resume'):
            p.add_argument('--agent', required=True)
        if action == 'next':
            p.add_argument('--allow-unchanged', action='store_true', help='Explicitly request re-review of an already reviewed SHA')
        if action == 'resume':
            p.add_argument('--session', help='Exact saved session ID, if not recorded automatically')
        if action == 'worker':
            p.add_argument('--round', type=positive, required=True)
            p.add_argument('--resume', action='store_true')
    p = review.add_parser('submit')
    p.add_argument('id')
    p.add_argument('--round', type=positive, required=True)
    p.add_argument('--sha', required=True)
    p.add_argument('--body-file', required=True)
    p.add_argument('--verdict', choices=['clean', 'findings', 'blocked'], required=True)
    p = review.add_parser('triage')
    p.add_argument('id')
    p.add_argument('--agent', required=True)
    p.add_argument('--sha', required=True)
    p.add_argument('--body-file', required=True)
    p.add_argument('--action', dest='decision', choices=['complete', 'revise', 'discuss'], required=True)
    p.add_argument('--unresolved', nargs='*', default=[], help='Stable finding IDs still unresolved; repeats stop automatic cycling')
    return root


def dispatch(store, args):
    if args.group == 'agent':
        name(args.agent)
        if args.remote and not args.codex_thread:
            raise Error('--remote requires --codex-thread')
        with store.locked() as state:
            state['agents'][args.agent] = {'codex_thread': args.codex_thread, 'remote': args.remote}
            return state['agents'][args.agent]
    if args.group == 'resource':
        if args.action == 'acquire':
            request = resources.acquire(store, args.resources, args.agent, args.mode)
            if args.wait:
                return resources.wait(store, request['id'], args.agent, args.wait)
            return request
        if args.action == 'wait':
            return resources.wait(store, args.ticket, args.agent, args.timeout)
        if args.action in ('release', 'cancel'):
            return resources.release(store, args.ticket, args.agent, args.action == 'cancel')
        with store.locked() as state:
            if args.action == 'define':
                name(args.name)
                name('resource.' + args.name)
                state['resources'][args.name] = args.description
            return {'resources': state['resources'], 'requests': list(state['requests'].values())}
    if args.group == 'topic':
        if args.action == 'wait':
            return wait_topic(store, args.topic, args.agent, args.timeout)
        if args.action == 'list':
            with store.locked() as state:
                return {key: {'subscribers': list(value['subscribers']),
                              'latest_sequence': len(value['events'])}
                        for key, value in state['topics'].items()}
        name(args.topic)
        name(args.agent)
        with store.locked() as state:
            if args.action in ('subscribe', 'publish'):
                topic = state['topics'].setdefault(args.topic, {'events': [], 'subscribers': {}})
            else:
                if args.topic not in state['topics']:
                    raise Error(f'Unknown topic: {args.topic}')
                topic = state['topics'][args.topic]
            if args.action == 'subscribe':
                topic['subscribers'].setdefault(args.agent, 0)
            elif args.action == 'unsubscribe':
                topic['subscribers'].pop(args.agent, None)
            elif args.action == 'publish':
                event = publish(store, state, args.topic, args.agent, args.title, Path(args.body_file).read_text())
                targets = list(topic['subscribers'])
            elif args.action == 'ack':
                if args.agent not in topic['subscribers']:
                    raise Error('Subscribe before acknowledging updates')
                if not topic['subscribers'][args.agent] <= args.sequence <= len(topic['events']):
                    raise Error('Acknowledgment must advance within the published sequence')
                topic['subscribers'][args.agent] = args.sequence
            if args.action != 'publish':
                cursor = topic['subscribers'].get(args.agent, 0)
                return {'topic': args.topic, 'cursor': cursor,
                        'events': topic['events'][cursor:]}
        result = {'topic': args.topic, 'event': event}
        if args.notify:
            result['delivery'] = notify(store, [a for a in targets if a != args.agent],
                f'[Agent coordination] Topic {args.topic} update {event["sequence"]}: {event["path"]}. '
                'Read it when relevant to your current task.')
        return result
    if args.action == 'list':
        with store.locked() as state:
            return [{'id': r['id'], 'agent': r['agent'], 'repo': r['repo'],
                     'status': r['status'], 'mode': r['mode'],
                     'sha': r['rounds'][-1]['sha'] if r['rounds'] else None}
                    for r in state['reviews'].values()]
    if args.action == 'start':
        return reviews.start(store, args)
    if args.action == 'submit':
        return reviews.submit(store, args)
    if args.action == 'triage':
        args.action = args.decision
        return reviews.triage(store, args)
    if args.action == 'bind-session':
        return reviews.bind_session(store, args.id)
    if args.action == 'worker':
        return reviews.worker(store, args.id, args.round, args.resume)
    if args.action == 'wait':
        return reviews.wait(store, args.id, args.timeout)
    if args.action == 'resume':
        return reviews.resume(store, args.id, args.agent, args.session)
    if args.action == 'next':
        return reviews.next_round(store, args.id, args.agent, args.allow_unchanged)
    with store.locked() as state:
        review = reviews.get(state, args.id)
        if args.action == 'stop-loop':
            if review['agent'] != args.agent:
                raise Error('Only the requester can stop the loop')
            review['status'] = 'stopped'
            review['reason'] = 'Automatic continuation stopped. Existing reviewer terminal was not interrupted.'
            reviews.publish_stop(store, state, review)
        return reviews.view(review)


def wait_topic(store, topic_name, agent, timeout):
    name(topic_name)
    name(agent)
    deadline = time.monotonic() + timeout
    progress = 0
    while True:
        with store.locked() as state:
            topic = state['topics'].get(topic_name)
            if topic is None:
                raise Error(f'Unknown topic: {topic_name}')
            if agent not in topic['subscribers']:
                raise Error('Subscribe before waiting for updates')
            cursor = topic['subscribers'][agent]
            events = topic['events'][cursor:]
            if events:
                return {'topic': topic_name, 'cursor': cursor, 'events': events}
        if time.monotonic() >= deadline:
            raise Error(f'Timed out waiting for {topic_name}; no unread updates. Subscription and cursor unchanged.')
        if time.monotonic() >= progress:
            print(f'Waiting for topic {topic_name}: no unread updates', file=sys.stderr, flush=True)
            progress = time.monotonic() + 10
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))


def main(argv=None):
    args = parser().parse_args(argv)
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        result = dispatch(Store(args.state_dir), args)
        print(json.dumps(result, indent=2))
        if args.group == 'resource' and result.get('status') == 'queued':
            sys.exit(3)
    except KeyboardInterrupt:
        print(json.dumps({'error': 'Interrupted; a resource wait withdraws its unused claim. Reviewers continue.'}), file=sys.stderr)
        sys.exit(130)
    except (Error, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        sys.exit(2)
