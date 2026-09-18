"""Sustained adversarial download comparison; owned containers and files only."""
import concurrent.futures
import datetime
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
import urllib.parse
import urllib.request

ROOT = Path.cwd()
assert subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip() == str(ROOT)
PLAIN_HTTP = os.environ.get('SYQ_STRESS_HTTP') == '1'
D = ROOT / ('target/transport-stress-http-v2' if PLAIN_HTTP else 'target/transport-stress-v2')
D.mkdir(exist_ok=True)
STAGE = D / 'stage'
STAGE.mkdir(exist_ok=True)
CERT = STAGE / 'cert'
CERT.mkdir(exist_ok=True)
IMAGE = 'ubuntu@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b'
MINIO = 'minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e'
BIN = ROOT / 'target/release/examples/s3_transport_spike'
shutil.copy2(BIN, STAGE / 'client')
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(CERT / 'private.key'), '-out', str(CERT / 'public.crt'),
                '-days', '1', '-subj', '/CN=localhost', '-addext', 'basicConstraints=critical,CA:FALSE',
                '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.environ.update(AWS_ACCESS_KEY_ID='syq-test-user', AWS_SECRET_ACCESS_KEY='syq-test-password',
                  AWS_REGION='us-east-1', AWS_EC2_METADATA_DISABLED='true', SYQ_TEST_BUCKET='transport-stress')
for key in ('AWS_SESSION_TOKEN', 'AWS_PROFILE'):
    os.environ.pop(key, None)
context = ssl.create_default_context(cafile=str(CERT / 'public.crt'))
original_urlopen = urllib.request.urlopen
urllib.request.urlopen = lambda *a, **k: original_urlopen(*a, context=context, **k)
server = None
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
                           'host:' + urllib.parse.urlsplit(endpoint).netloc + '\n',
                           'host', 'UNSIGNED-PAYLOAD'])
    signed = '\n'.join(['AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    secret = b'AWS4syq-test-password'
    for item in [day, 'us-east-1', 's3', 'aws4_request']:
        secret = hmac.new(secret, item.encode(), hashlib.sha256).digest()
    return endpoint + path + '?' + query + '&X-Amz-Signature=' + hmac.new(secret, signed.encode(), hashlib.sha256).hexdigest()

def remove_container(cid):
    command(['docker', 'rm', '-f', cid])
    assert not command(['docker', 'ps', '-aq', '--filter', 'id=' + cid])
    cleanup.append(cid)
    (D / 'cleanup.json').write_text(json.dumps(cleanup))

def run(case, mode, repeats, label):
    global active
    for row in results:
        if row['case'] == case and row['mode'] == mode and row['label'] == label:
            print(f"Reusing recorded {case['name']}-{mode}-{label} at {row['commit'][:8]}", flush=True)
            return row
    tag = f"{case['name']}-{mode}-{label}"
    out = D / (tag + '-output')
    out.mkdir()
    args = ['docker', 'create', '--network', 'host', '--cpuset-cpus', case['cpus'],
            '--memory', '1g', '--memory-swap', '1g', '--pids-limit', '512',
            '-v', str(STAGE) + ':/bench:ro', '-v', str(out) + ':/output:rw',
            IMAGE, '/bench/client', mode, '/bench/' + case['fixture'] + '.json',
            str(case['concurrency']), '/output', '/bench/cert/public.crt', 'auto', str(repeats)]
    active = command(args)
    process = subprocess.Popen(['docker', 'start', '-a', active], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    deadline = time.monotonic() + 600
    started = time.monotonic()
    try:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=10)
                break
            except subprocess.TimeoutExpired:
                print(f'{tag}: running {time.monotonic() - started:.0f}s', flush=True)
                if time.monotonic() > deadline:
                    raise TimeoutError(f'{tag}: 600s deadline exceeded')
        state = json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', active]))
        (D / (tag + '.state.json')).write_text(json.dumps(state))
        (D / (tag + '.stderr')).write_text(stderr)
        if state['OOMKilled']:
            row = {'case': case, 'mode': mode, 'label': label, 'repeats': repeats,
                   'commit': COMMIT, 'status': 'oom', 'elapsed': time.monotonic()-started,
                   'bytes': fixtures[case['fixture']]['count'] * fixtures[case['fixture']]['size'] * repeats}
            results.append(row)
            (D / 'results.json').write_text(json.dumps(results, indent=2))
            print(f'{tag}: OOM killed; not a completed transfer', flush=True)
            return row
        assert process.returncode == 0 and state['ExitCode'] == 0, (tag, state, stderr)
        row = json.loads(stdout)
        row.update(case=case, label=label, repeats=repeats, commit=COMMIT)
        (D / (tag + '.json')).write_text(json.dumps(row, indent=2))
        print(f"{tag}: {row['bytes']/2**30:.1f} GiB in {row['elapsed']:.2f}s, "
              f"CPU {row['user']+row['system']:.2f}s, RSS {row['rss_kib']/1024:.1f} MiB", flush=True)
        files = sorted(out.iterdir())
        assert len(files) == row['objects']
        verify_start = time.monotonic()
        next_progress = verify_start + 10
        def verify(path):
            with path.open('rb') as f:
                digest = hashlib.file_digest(f, 'sha256').hexdigest()
            assert digest == fixtures[case['fixture']]['sha256'], (tag, path)
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
        if process.poll() is None:
            command(['docker', 'kill', active])
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=30)
        remove_container(active)
        active = None
        shutil.rmtree(out)

try:
    server = command(['docker', 'run', '--detach', '--rm', '--cpuset-cpus', '8-15',
                      '--tmpfs', '/data:rw,size=2g', '-p', '127.0.0.1::9000',
                      '-v', str(CERT) + ':/certs:ro', '-e', 'MINIO_ROOT_USER=syq-test-user',
                      '-e', 'MINIO_ROOT_PASSWORD=syq-test-password', MINIO,
                      'server', '/data'] + ([] if PLAIN_HTTP else ['--certs-dir', '/certs']))
    port = command(['docker', 'inspect', '--format',
                    '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}', server])
    endpoint = ('http' if PLAIN_HTTP else 'https') + '://127.0.0.1:' + port
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
    for case in cases:
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
            lower = dict(case, name='writeback-pressure-low-concurrency', concurrency=8)
            for rep in range(2):
                row = run(lower, 'async', repeats, f'measured-{rep}')
                assert row.get('status') != 'oom' and row['elapsed'] >= 30
finally:
    if active:
        remove_container(active)
    if server:
        remove_container(server)
