import sys
import time

from .store import Error, identifier, name, publish


def conflict(left, right):
    return bool(set(left['resources']) & set(right['resources'])) and (
        left['mode'] == 'exclusive' or right['mode'] == 'exclusive')


def schedule(state):
    active = [r for r in state['requests'].values() if r['status'] == 'held']
    waiting = []
    for request in state['requests'].values():
        if request['status'] != 'queued':
            continue
        if any(conflict(request, other) for other in active + waiting):
            waiting.append(request)
        else:
            request['status'] = 'held'
            active.append(request)


def owned(state, ticket, agent):
    request = state['requests'].get(ticket)
    if request is None or request['agent'] != agent:
        raise Error('No such ticket owned by this agent')
    return request


def acquire(store, resources, agent, mode):
    resources = sorted(set(map(name, resources)))
    name(agent)
    with store.locked() as state:
        if any(r not in state['resources'] for r in resources):
            raise Error('Define each resource and reconcile existing users before acquiring it')
        if any(r['agent'] == agent and r['status'] in ('queued', 'held')
               and set(r['resources']) & set(resources) for r in state['requests'].values()):
            raise Error('This agent already holds or awaits an overlapping resource; inspect status')
        request = {'id': identifier('claim'), 'agent': agent, 'resources': resources,
                   'mode': mode, 'status': 'queued', 'created': time.time()}
        state['requests'][request['id']] = request
        schedule(state)
        return dict(request)


def release(store, ticket, agent, cancel=False):
    with store.locked() as state:
        request = owned(state, ticket, agent)
        if cancel and request['status'] == 'held':
            raise Error('Ticket already holds resources; use release after stopping owned work')
        if request['status'] not in ('held', 'queued'):
            return dict(request)
        request['status'] = 'cancelled' if cancel else 'released'
        schedule(state)
        for resource in request['resources']:
            publish(store, state, 'resource.' + resource, agent, request['status'],
                    f"{agent} {request['status']} ticket {ticket}. Check resource status for ownership.\n")
        return dict(request)


def wait(store, ticket, agent, timeout):
    deadline = time.monotonic() + timeout
    progress = 0
    try:
        while True:
            with store.locked() as state:
                request = dict(owned(state, ticket, agent))
            if request['status'] == 'held':
                return request
            if request['status'] != 'queued':
                raise Error(f"Ticket is {request['status']}")
            if time.monotonic() >= deadline:
                raise Error(f'Timed out waiting for {ticket}; ticket retained. Last observed status: queued. '
                            'Wait again with the same ticket, or inspect status and cancel/release it.')
            if time.monotonic() >= progress:
                print(f'Waiting for {ticket}: queued', file=sys.stderr, flush=True)
                progress = time.monotonic() + 10
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        # This command has not handed resources to its caller. If scheduling raced
        # with interruption, release that unused grant too. Never expire used claims.
        with store.locked() as state:
            request = owned(state, ticket, agent)
            if request['status'] in ('queued', 'held'):
                request['status'] = 'cancelled'
                schedule(state)
        raise
