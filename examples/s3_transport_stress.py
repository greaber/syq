"""Sustained adversarial download comparison; owned containers and files only."""
import concurrent.futures
import datetime
import errno
import hashlib
import hmac
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import signal
import ssl
import subprocess
import sys
import time
import threading
import urllib.parse
import urllib.request

ROOT = Path.cwd()
assert subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip() == str(ROOT)
PLAIN_HTTP = os.environ.get('SYQ_STRESS_HTTP') == '1'
QUEUE_SWEEP = os.environ.get('SYQ_STRESS_QUEUES')
MEMORY_TRACE = os.environ.get('SYQ_STRESS_MEMORY') == '1'
QUEUES = [int(q) for q in QUEUE_SWEEP.split(',')] if QUEUE_SWEEP else []
D = ROOT / ('target/transport-stress-http-v2' if PLAIN_HTTP else 'target/transport-stress-v2')
if QUEUE_SWEEP:
    run_name = os.environ.get('SYQ_STRESS_RUN', 'transport-queue-sweep-v1')
    assert Path(run_name).name == run_name
    D = ROOT / 'target' / run_name
D.mkdir(exist_ok=True)
STAGE = D / 'stage'
STAGE.mkdir(exist_ok=True)
CERT = STAGE / 'cert'
CERT.mkdir(exist_ok=True)
IMAGE = 'ubuntu@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b'
MINIO = 'minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e'
BIN = ROOT / 'target/release/examples/s3_transport_spike'
if QUEUE_SWEEP:
    BIN = ROOT / os.environ.get('SYQ_STRESS_BINARY', 'target/transport-queue-build/client')
shutil.copy2(BIN, STAGE / 'client')
BINARY_SHA256 = hashlib.sha256(BIN.read_bytes()).hexdigest()
# Delay/rate are applied only inside owned container network namespaces.
NETEM_MS = int(os.environ.get('SYQ_STRESS_NETEM_MS', 0))
NETEM_RATE = os.environ.get('SYQ_STRESS_NETEM_RATE', '1gbit')
SENDER_MAX = int(os.environ.get('SYQ_STRESS_SENDER_MAX', 0))
RECEIVER_NETEM = NETEM_MS and os.environ.get('SYQ_STRESS_NETEM_PLACEMENT', 'receiver') == 'receiver'
NETLAB = 'sha256:04a80a4748e69b7ee5a46a4e3424f536c17d1ee384791bdf301a128c4e704e3d'
HEAP_PROBE = os.environ.get('SYQ_STRESS_HEAP') == '1'
if HEAP_PROBE:
    shutil.copy2(ROOT / 'target/memory-probe.so', STAGE / 'memory-probe.so')
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(CERT / 'private.key'), '-out', str(CERT / 'public.crt'),
                '-days', '1', '-subj', '/CN=localhost', '-addext', 'basicConstraints=critical,CA:FALSE',
                '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:s3-spike.test'],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.environ.update(AWS_ACCESS_KEY_ID='syq-test-user', AWS_SECRET_ACCESS_KEY='syq-test-password',
                  AWS_REGION='us-east-1', AWS_EC2_METADATA_DISABLED='true', SYQ_TEST_BUCKET='transport-stress')
for key in ('AWS_SESSION_TOKEN', 'AWS_PROFILE'):
    os.environ.pop(key, None)
context = ssl.create_default_context(cafile=str(CERT / 'public.crt'))
original_urlopen = urllib.request.urlopen
urllib.request.urlopen = lambda *a, **k: original_urlopen(*a, context=context, **k)
server = None
receiver = None
active = None
results = json.loads((D / "results.json").read_text()) if (D / "results.json").exists() else []
for previous in results:
    previous.setdefault("commit", "d8e5585f")
COMMIT = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
cleanup = json.loads((D / "cleanup.json").read_text()) if (D / "cleanup.json").exists() else []

def command(args, **kwargs):
    return subprocess.check_output(args, text=True, timeout=60, **kwargs).strip()

def presign(key):
    now = datetime.datetime.now(datetime.timezone.utc)
    day = now.strftime('%Y%m%d')
    stamp = now.strftime('%Y%m%dT%H%M%SZ')
    scope = f'{day}/us-east-1/s3/aws4_request'
    path = '/transport-stress/' + key
    query = urllib.parse.urlencode(sorted({
        'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': 'syq-test-user/' + scope,
        'X-Amz-Date': stamp, 'X-Amz-Expires': '21600', 'X-Amz-SignedHeaders': 'host'
    }.items()), quote_via=urllib.parse.quote)
    canonical = '\n'.join(['GET', path, query,
                           'host:' + urllib.parse.urlsplit(download_endpoint).netloc + '\n',
                           'host', 'UNSIGNED-PAYLOAD'])
    signed = '\n'.join(['AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    secret = b'AWS4syq-test-password'
    for item in [day, 'us-east-1', 's3', 'aws4_request']:
        secret = hmac.new(secret, item.encode(), hashlib.sha256).digest()
    return download_endpoint + path + '?' + query + '&X-Amz-Signature=' + hmac.new(secret, signed.encode(), hashlib.sha256).hexdigest()

def remove_container(cid):
    command(['docker', 'rm', '-f', cid])
    assert not command(['docker', 'ps', '-aq', '--filter', 'id=' + cid])
    cleanup.append(cid)
    (D / 'cleanup.json').write_text(json.dumps(cleanup))

def network_command(args, namespace=None):
    helper = command(['docker', 'create', '--network', 'container:' + (namespace or server),
                      '--cap-add', 'NET_ADMIN', NETLAB, *args])
    try:
        return command(['docker', 'start', '-a', helper])
    finally:
        remove_container(helper)

class MemoryTrace:
    def __init__(self, cid, tag):
        self.samples = []
        self.done = threading.Event()
        self.path = D / (tag + '.memory.json')
        for _ in range(100):
            self.pid = int(command(['docker', 'inspect', '--format', '{{.State.Pid}}', cid]))
            if self.pid:
                break
            time.sleep(.02)
        assert self.pid, 'container did not start within bounded startup check'
        group = Path(f'/proc/{self.pid}/cgroup').read_text().strip().split('::', 1)[1]
        self.group = Path('/sys/fs/cgroup') / group.lstrip('/')
        assert (self.group / 'memory.stat').is_file(), self.group
        self.started = time.monotonic()
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()

    def sample(self):
        while not self.done.is_set() and time.monotonic() - self.started < 600:
            row = {'seconds': time.monotonic() - self.started}
            try:
                for name in ('memory.current', 'memory.peak'):
                    row[name] = int((self.group / name).read_text())
                for name in ('memory.stat', 'memory.events', 'cpu.stat'):
                    row[name] = {k: int(v) for k, v in
                                 (line.split() for line in (self.group / name).read_text().splitlines())}
                wanted = {'VmRSS', 'VmHWM', 'RssAnon', 'RssFile', 'VmSize', 'Threads'}
                row['process'] = {k: int(v.split()[0]) for k, v in
                                  (line.split(':', 1) for line in Path(f'/proc/{self.pid}/status').read_text().splitlines())
                                  if k in wanted}
                self.samples.append(row)
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ENODEV, errno.ESRCH):
                    self.samples.append({'error': str(error)})
                break
            self.done.wait(.02)

    def stop(self):
        self.done.set()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive(), 'memory sampler did not stop'
        self.path.write_text(json.dumps(self.samples))
        assert self.samples and not any('error' in r for r in self.samples), self.samples

def run(case, mode, repeats, label):
    global active
    for row in results:
        if row['case'] == case and row['mode'] == mode and row['label'] == label and row['repeats'] == repeats and (not QUEUE_SWEEP or row.get('binary_sha256') == BINARY_SHA256):
            print(f"Reusing recorded {case['name']}-{mode}-{label} at {row['commit'][:8]}", flush=True)
            return row
    tag = f"{case['name']}-{mode}-{label}"
    out = D / (tag + '-output')
    out.mkdir()
    memory = case.get('memory', '1g')
    args = ['docker', 'create', '--network', 'container:' + receiver if RECEIVER_NETEM else 'host',
            *(['--add-host', 's3-spike.test:' + server_ip] if NETEM_MS and not RECEIVER_NETEM else []),
            '--cpuset-cpus', case['cpus'],
            '--memory', memory, '--memory-swap', memory, '--pids-limit', '512',
            '-v', str(STAGE) + ':/bench:ro', '-v', str(out) + ':/output:rw',
            '-e', 'SYQ_SPIKE_READERS_PER_WRITER=' + str(case.get('readers', 1)),
            *(['--cpus', str(case['cpu_quota'])] if 'cpu_quota' in case else []),
            *(['--device-write-bps', case['write_bps']] if 'write_bps' in case else []),
            *(['-e', 'SYQ_SPIKE_QUEUE=' + mode.removeprefix('queue-')] if QUEUE_SWEEP else []),
            IMAGE, '/bench/client', 'async' if mode.startswith('queue-') else mode, '/bench/' + case['fixture'] + '.json',
            str(case['concurrency']), '/output', '/bench/cert/public.crt', 'auto', str(repeats)]
    if HEAP_PROBE:
        at = args.index(IMAGE) + 1
        args[at:at] = ['/usr/bin/env', 'LD_PRELOAD=/bench/memory-probe.so',
                      'SYQ_SPIKE_RCVBUF=' + str(case.get('receive_buffer', 0)),
                      'SYQ_SPIKE_RCVBUDGET=' + str(case.get('receive_budget', 0)),
                      *(['MALLOC_ARENA_MAX=' + str(case['malloc_arenas'])] if 'malloc_arenas' in case else [])]
    gate = STAGE / 'start-client'
    if MEMORY_TRACE:
        gate.unlink(missing_ok=True)
        at = args.index(IMAGE) + 1
        args[at:at] = ['/bin/sh', '-c',
                      'for i in $(seq 1 200); do if [ -f /bench/start-client ]; then exec "$@"; fi; sleep .05; done; exit 124',
                      'gate']
    active = command(args)
    process = subprocess.Popen(['docker', 'start', '-a', active], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    deadline = time.monotonic() + 600
    started = time.monotonic()
    monitor = None
    try:
        if MEMORY_TRACE:
            monitor = MemoryTrace(active, tag)
            gate.touch()
        while True:
            try:
                stdout, stderr = process.communicate(timeout=10)
                break
            except subprocess.TimeoutExpired:
                print(f'{tag}: running {time.monotonic() - started:.0f}s', flush=True)
                if NETEM_MS:
                    with (D / (tag + '.sender-tcp.txt')).open('a') as trace:
                        trace.write(network_command(['ss', '-tin', 'state', 'established']) + '\n')
                if time.monotonic() > deadline:
                    raise TimeoutError(f'{tag}: 600s deadline exceeded')
        if monitor:
            monitor.stop()
            monitor = None
        if HEAP_PROBE:
            shutil.move(out / '.allocator.csv', D / (tag + '.allocator.csv'))
        if NETEM_MS:
            stats = json.loads(network_command(['tc', '-j', '-s', 'qdisc', 'show', 'dev',
                                                 'ifb0' if RECEIVER_NETEM else 'eth0'], receiver))
            (D / (tag + '.netem.json')).write_text(json.dumps(stats, indent=2))
            assert all(q.get('drops', 0) == 0 for q in stats), stats
        state = json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', active]))
        (D / (tag + '.state.json')).write_text(json.dumps(state))
        (D / (tag + '.stderr')).write_text(stderr)
        if state['OOMKilled']:
            row = {'case': case, 'mode': mode, 'label': label, 'repeats': repeats,
                   'commit': COMMIT, 'binary_sha256': BINARY_SHA256, 'status': 'oom', 'elapsed': time.monotonic()-started,
                   'bytes': fixtures[case['fixture']]['count'] * fixtures[case['fixture']]['size'] * repeats}
            results.append(row)
            (D / 'results.json').write_text(json.dumps(results, indent=2))
            print(f'{tag}: OOM killed; not a completed transfer', flush=True)
            return row
        assert process.returncode == 0 and state['ExitCode'] == 0, (tag, state, stderr)
        row = json.loads(stdout)
        row.update(case=case, mode=mode, label=label, repeats=repeats, commit=COMMIT, binary_sha256=BINARY_SHA256)
        (D / (tag + '.json')).write_text(json.dumps(row, indent=2))
        print(f"{tag}: {row['bytes']/2**30:.1f} GiB in {row['elapsed']:.2f}s, "
              f"CPU {row['user']+row['system']:.2f}s, RSS {row['rss_kib']/1024:.1f} MiB", flush=True)
        files = sorted(out.iterdir())
        assert len(files) == row['objects']
        verify_start = time.monotonic()
        next_progress = verify_start + 10
        expected_hash = fixtures[case['fixture']]['sha256']
        if case.get('readers', 1) > 1:
            data = (STAGE / (case['fixture'] + '.source')).read_bytes()
            combined = hashlib.sha256()
            for _ in range(case['readers']):
                combined.update(data)
            expected_hash = combined.hexdigest()
        def verify(path):
            with path.open('rb') as f:
                digest = hashlib.file_digest(f, 'sha256').hexdigest()
            assert digest == expected_hash, (tag, path)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for count, _ in enumerate(pool.map(verify, files), 1):
                if time.monotonic() >= next_progress:
                    print(f'{tag}: independently verified {count}/{len(files)} files', flush=True)
                    next_progress = time.monotonic() + 10
        row['independently_verified_files'] = len(files)
        row['verification_seconds'] = time.monotonic() - verify_start
        results.append(row)
        (D / 'results.json').write_text(json.dumps(results, indent=2))
        return row
    finally:
        if monitor:
            monitor.stop()
        if process.poll() is None:
            command(['docker', 'kill', active])
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=30)
        remove_container(active)
        active = None
        shutil.rmtree(out)

try:
    server = command(['docker', 'run', '--detach', '--rm', '--cpuset-cpus', '8-15',
                      *(['--sysctl', f'net.ipv4.tcp_wmem=4096 131072 {SENDER_MAX}'] if SENDER_MAX else []),
                      '--tmpfs', '/data:rw,size=2g', '-p', '127.0.0.1::9000',
                      '-v', str(CERT) + ':/certs:ro', '-e', 'MINIO_ROOT_USER=syq-test-user',
                      '-e', 'MINIO_ROOT_PASSWORD=syq-test-password', MINIO,
                      'server', '/data'] + ([] if PLAIN_HTTP else ['--certs-dir', '/certs']))
    port = command(['docker', 'inspect', '--format',
                    '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}', server])
    endpoint = ('http' if PLAIN_HTTP else 'https') + '://127.0.0.1:' + port
    server_ip = command(['docker', 'inspect', '--format',
                         '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', server])
    # Fixture setup may use the published port, but measured delayed TCP must
    # bypass Docker's userland proxy, which would split it into two connections.
    download_endpoint = ('http' if PLAIN_HTTP else 'https') + '://s3-spike.test:9000' if NETEM_MS else endpoint
    os.environ['AWS_ENDPOINT_URL_S3'] = endpoint
    deadline = time.monotonic() + 60
    while True:
        try:
            with urllib.request.urlopen(endpoint + '/minio/health/ready', timeout=2) as response:
                assert response.status == 200
            break
        except Exception as error:
            if time.monotonic() > deadline:
                raise RuntimeError(f'MinIO readiness timeout: {error}')
            print(f'Waiting for MinIO: {error}', flush=True)
            time.sleep(2)
    sys.argv = [sys.argv[0], str(BIN)]
    spec = importlib.util.spec_from_file_location('checks', ROOT / 'tests/object-storage/check.py')
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    checks.request('PUT')
    fixtures = {}
    for name, count, size in [('large', 8, 128 * 1024 * 1024), ('small', 1024, 64 * 1024)]:
        source = STAGE / (name + '.source')
        data = source.read_bytes() if source.exists() else os.urandom(size)
        assert len(data) == size
        source.write_bytes(data)
        digest = command([str(BIN), 'digest', str(source)])
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: checks.request('PUT', f'{name}/{i}', data), range(count)))
        manifest = [{'url': presign(f'{name}/{i}'), 'size': size, 'blake3': digest} for i in range(count)]
        (STAGE / (name + '.json')).write_text(json.dumps(manifest))
        fixtures[name] = {'count': count, 'size': size, 'sha256': hashlib.sha256(data).hexdigest()}
        print(f'Prepared {name}: {count} x {size} bytes', flush=True)
    (D / 'fixtures.json').write_text(json.dumps(fixtures, indent=2))
    cases = [
        {'name': 'single-stream', 'fixture': 'large', 'cpus': '0-1', 'concurrency': 1},
        {'name': 'two-core-fanout', 'fixture': 'large', 'cpus': '0-1', 'concurrency': 64},
        {'name': 'writeback-pressure', 'fixture': 'large', 'cpus': '0-7', 'concurrency': 64},
        {'name': 'small-file-fanout', 'fixture': 'small', 'cpus': '0-1', 'concurrency': 64},
    ]
    if PLAIN_HTTP:
        cases = [{'name': 'one-core-http', 'fixture': 'large', 'cpus': '0', 'concurrency': 64}]
    if not PLAIN_HTTP:
        cases = [cases[2], cases[0], cases[1], cases[3]]
    if QUEUE_SWEEP:
        cases.append({'name': 'writeback-roomy', 'fixture': 'large', 'cpus': '0-7',
                      'concurrency': 64, 'memory': '4g'})
        cases.extend([
            {'name': 'shared-writer', 'fixture': 'large', 'cpus': '0-7',
             'concurrency': 8, 'memory': '4g', 'readers': 8},
            {'name': 'many-cores', 'fixture': 'large', 'cpus': '0-7,16-39',
             'concurrency': 64, 'memory': '4g'},
            {'name': 'cpu-quota', 'fixture': 'large', 'cpus': '0-7',
             'concurrency': 64, 'memory': '4g', 'cpu_quota': 2},
            {'name': 'disk-limited', 'fixture': 'large', 'cpus': '0-7',
             'concurrency': 64, 'memory': '4g', 'write_bps': '/dev/md2:1gb'},
        ])
        requested = os.environ.get('SYQ_STRESS_CASES', 'writeback-pressure').split(',')
        indexed = {case['name']: case for case in cases}
        cases = [dict(indexed[name], protocol='http' if PLAIN_HTTP else 'https') for name in requested]
    if NETEM_MS:
        sender_tcp = network_command(['cat', '/proc/sys/net/ipv4/tcp_wmem'])
        (D / 'sender-tcp-wmem.txt').write_text(sender_tcp + '\n')
        if RECEIVER_NETEM:
            receiver = command(['docker', 'run', '--detach', '--rm',
                                '--add-host', 's3-spike.test:' + server_ip,
                                '--sysctl', 'net.ipv4.tcp_rmem=4096 131072 67108864',
                                NETLAB, 'sleep', '3600'])
            network_command(['ip', 'link', 'add', 'ifb0', 'type', 'ifb'], receiver)
            network_command(['ip', 'link', 'set', 'ifb0', 'up'], receiver)
            network_command(['tc', 'qdisc', 'add', 'dev', 'eth0', 'handle', 'ffff:', 'ingress'], receiver)
            network_command(['tc', 'filter', 'add', 'dev', 'eth0', 'parent', 'ffff:',
                             'protocol', 'ip', 'u32', 'match', 'ip', 'src', server_ip + '/32',
                             'action', 'mirred', 'egress', 'redirect', 'dev', 'ifb0'], receiver)
        network_command(['tc', 'qdisc', 'replace', 'dev', 'ifb0' if RECEIVER_NETEM else 'eth0',
                         'root', 'netem', 'limit', '100000', 'delay', str(NETEM_MS) + 'ms',
                         'rate', NETEM_RATE], receiver)
        placement = 'receiver ingress' if RECEIVER_NETEM else 'sender egress'
        print(f'Isolated {placement}: delay {NETEM_MS}ms, rate {NETEM_RATE}', flush=True)
        for case in cases:
            case.update(netem_ms=NETEM_MS, netem_rate=NETEM_RATE, netlab_image=NETLAB,
                        sender_tcp_wmem=sender_tcp, netem_placement=placement)
    if os.environ.get('SYQ_STRESS_RCVBUFS'):
        assert HEAP_PROBE
        cases = [dict(case, receive_buffer=int(value)) for case in cases
                 for value in os.environ['SYQ_STRESS_RCVBUFS'].split(',')]
    if os.environ.get('SYQ_STRESS_RCVBUDGETS'):
        assert HEAP_PROBE
        cases = [dict(case, receive_budget=int(value)) for case in cases
                 for value in os.environ['SYQ_STRESS_RCVBUDGETS'].split(',')]
    for case in cases:
        if HEAP_PROBE:
            case.update(heap_probe=True)
            case.setdefault('receive_buffer', int(os.environ.get('SYQ_STRESS_RCVBUF', 0)))
            if os.environ.get('SYQ_STRESS_RCVBUDGET'):
                case['receive_budget'] = int(os.environ['SYQ_STRESS_RCVBUDGET'])
            if os.environ.get('SYQ_STRESS_MALLOC_ARENAS'):
                case['malloc_arenas'] = int(os.environ['SYQ_STRESS_MALLOC_ARENAS'])
        if QUEUE_SWEEP:
            # Same sustained workloads as the previous experiment; never pilot-sized.
            repeats = {'writeback-pressure': 53, 'writeback-roomy': 64,
                       'single-stream': 32, 'two-core-fanout': 46,
                       'small-file-fanout': 400, 'many-cores': 64,
                       'cpu-quota': 32, 'disk-limited': 64, 'shared-writer': 64}[case['name']]
            repeats = int(os.environ.get('SYQ_STRESS_REPEATS', repeats))
            rounds = int(os.environ.get('SYQ_STRESS_ROUNDS', 2))
            label = os.environ.get('SYQ_STRESS_LABEL', 'measured')
            if os.environ.get('SYQ_STRESS_RCVBUFS'):
                label += '-rcv' + str(case['receive_buffer'])
            if os.environ.get('SYQ_STRESS_RCVBUDGETS'):
                label += '-budget' + str(case['receive_budget'])
            minimum = float(os.environ.get('SYQ_STRESS_MIN_SECONDS', 30))
            modes = [f'queue-{queue}' for queue in QUEUES]
            if os.environ.get('SYQ_STRESS_SYNC') == '1':
                modes.append('sync')
            for rep in range(rounds):
                for mode in (modes if rep % 2 == 0 else list(reversed(modes))):
                    row = run(case, mode, repeats, f'{label}-{rep}')
                    assert row.get('status') == 'oom' or row['elapsed'] >= minimum, 'trial too short for selected phase'
            continue
        unit = fixtures[case['fixture']]['count'] * fixtures[case['fixture']]['size']
        pilot_bytes = 8 * 1024**3 if case['fixture'] == 'large' else 512 * 1024**2
        pilot_repeats = max(1, pilot_bytes // unit)
        pilot = [run(case, mode, pilot_repeats, 'pilot') for mode in ('async', 'sync')]
        fastest = min(row['elapsed'] for row in pilot if row.get('status') != 'oom')
        repeats = max(pilot_repeats, math.ceil(pilot_repeats * 40 / fastest))
        repeats = min(repeats, (128 * 1024**3) // unit)
        measured = []
        for rep in range(2):
            for mode in (('async', 'sync') if rep == 0 else ('sync', 'async')):
                measured.append(run(case, mode, repeats, f'measured-{rep}'))
        completed = [row for row in measured if row.get('status') != 'oom']
        assert completed and min(row['elapsed'] for row in completed) >= 30, 'measured trial too short; enlarge workload'
        if case['name'] == 'writeback-pressure' and any(row.get('status') == 'oom' for row in measured):
            for limit in (8, 32):
                name = 'writeback-pressure-low-concurrency' if limit == 8 else 'writeback-pressure-concurrency-32'
                lower = dict(case, name=name, concurrency=limit)
                for rep in range(2):
                    row = run(lower, 'async', repeats, f'measured-{rep}')
                    assert row.get('status') == 'oom' or row['elapsed'] >= 30
finally:
    if active:
        remove_container(active)
    if receiver:
        remove_container(receiver)
    if server:
        remove_container(server)
