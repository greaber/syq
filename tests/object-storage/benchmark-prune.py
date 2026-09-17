#!/usr/bin/env python3
"""Compare syq pruning and s5cmd sync against a disposable prefix.

Supply AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION,
AWS_ENDPOINT_URL_S3 and SYQ_TEST_BUCKET (an unversioned bucket). This does not
create buckets or change their configuration. Requires /usr/bin/time on Linux.
Example, from the repository root:
  python3 tests/object-storage/benchmark-prune.py --syq target/release/syq \
    --s5cmd /path/to/s5cmd --output target/prune-benchmark
Use --baseline to include an older syq binary. Increase --count/--size until
individual trials last at least --minimum-seconds; short trials are flagged,
not silently combined or discarded. Logs and raw measurements stay in --output.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--syq', required=True, type=Path)
    parser.add_argument('--s5cmd', required=True, type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--count', type=int, default=100000)
    parser.add_argument('--size', type=int, default=1024)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--minimum-seconds', type=float, default=10)
    parser.add_argument('--timeout', type=float, default=1800)
    parser.add_argument('--cases', nargs='+', choices=['delete', 'noop', 'mixed'], default=['delete', 'noop', 'mixed'])
    parser.add_argument('--directions', nargs='+', choices=['upload', 'download'], default=['upload', 'download'])
    args = parser.parse_args()
    if min(args.count, args.size, args.repeats, args.timeout) <= 0:
        parser.error('count, size, repeats and timeout must be positive')
    binaries = {'syq': args.syq.resolve(), 's5cmd': args.s5cmd.resolve()}
    if args.baseline:
        binaries['baseline'] = args.baseline.resolve()
    hashes = {name: hashlib.sha256(binary.read_bytes()).hexdigest() for name, binary in binaries.items()}
    args.output.mkdir(parents=True, exist_ok=False)
    # check.py only uses argv[1] to set its executable; its signed HTTP helpers
    # are independent of syq and own a fresh random prefix.
    sys.argv = [sys.argv[0], str(args.syq.resolve())]
    spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check.py'))
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
    _, body = c.request('GET', query={'versioning': ''})
    if any(n.tag.rsplit('}', 1)[-1] == 'Status' for n in ET.fromstring(body).iter()):
        raise RuntimeError('benchmark requires a bucket that has never enabled versioning')
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'benchmark received signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    rows = []
    report = dict(prefix=c.PREFIX, endpoint=c.ENDPOINT, bucket=c.BUCKET, region=c.REGION,
                  binary_sha256=hashes, settings={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                  host=os.uname().nodename, cpus=len(os.sched_getaffinity(0)), load=os.getloadavg(),
                  records=rows, complete=False, cleaned=False)

    def save():
        (args.output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')

    sequence = 0

    def run(command, label):
        nonlocal sequence
        sequence += 1
        stem = args.output / f'{sequence:04}-{label}'
        started = time.monotonic()
        ended = []
        with stem.with_suffix('.log').open('wb') as log:
            child = subprocess.Popen(['/usr/bin/time', '-f', '%U %S %M', '-o', str(stem.with_suffix('.usage')),
                                      *map(str, command)], stdout=log, stderr=log, start_new_session=True)
            def wait():
                child.wait()
                ended.append(time.monotonic())
            waiter = threading.Thread(target=wait)
            waiter.start()
            try:
                while waiter.is_alive():
                    waiter.join(10)
                    if waiter.is_alive():
                        print(f'{label}: running {time.monotonic() - started:.0f}s', flush=True)
                        if time.monotonic() - started >= args.timeout:
                            raise TimeoutError(f'{label}: see {stem}.log')
                if child.returncode:
                    raise RuntimeError(f'{label}: exit {child.returncode}; see {stem}.log')
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                waiter.join(timeout=10)
        user, system, rss = map(float, stem.with_suffix('.usage').read_text().split())
        return dict(seconds=ended[0] - started, user_cpu=user, system_cpu=system, max_rss_kib=rss,
                    command=list(map(str, command)), log=str(stem.with_suffix('.log')))

    def command(tool, direction, local, prefix, prune=True):
        remote = f's3://{c.BUCKET}/{prefix}/'
        if tool == 's5cmd':
            return [binaries[tool], '--endpoint-url', c.ENDPOINT, 'sync', *(['--delete'] if prune else []),
                    str(local) + '/' if direction == 'upload' else remote + '*',
                    remote if direction == 'upload' else str(local) + '/']
        return [binaries[tool], 'cp', '--no-progress',
                *(['--srcs-in', local, '--to', f's3://{c.BUCKET}', '--into', prefix] if direction == 'upload'
                  else ['--from', f's3://{c.BUCKET}', '--srcs-in', prefix, '--into', local]),
                *(['--prune'] if prune else [])]

    def remove(keys):
        for start in range(0, len(keys), 1000):
            batch = keys[start:start + 1000]
            assert all(k.startswith(c.PREFIX + '/') for k in batch)
            data = ('<Delete>' + ''.join(f'<Object><Key>{escape(k)}</Key></Object>' for k in batch) + '</Delete>').encode()
            # The independent signer supplies SHA256; Content-MD5 supports S3's
            # multi-delete requirement on general-purpose buckets.
            md5 = base64.b64encode(hashlib.md5(data).digest()).decode()
            _, body = c.request('POST', data=data, query={'delete': ''}, headers={'Content-MD5': md5})
            root = ET.fromstring(body)
            deleted = {n.text for d in root if d.tag.rsplit('}', 1)[-1] == 'Deleted'
                       for n in d if n.tag.rsplit('}', 1)[-1] == 'Key'}
            assert deleted == set(batch), 'cleanup response did not acknowledge every key'

    def verify(prefix, source):
        expected = {p.name for p in source.iterdir()}
        assert set(c.listing(prefix + '/')) == {prefix + '/' + name for name in expected}
        # Verify every newly copied body plus retained samples independently.
        samples = sorted(expected)[:16] + sorted(n for n in expected if n.startswith('new'))
        def check(name):
            assert c.request('GET', prefix + '/' + name)[1] == (source / name).read_bytes(), name
        with ThreadPoolExecutor(16) as pool:
            list(pool.map(check, samples))

    save()
    try:
        with tempfile.TemporaryDirectory(prefix='syq-prune-benchmark-') as temp:
            root = Path(temp)
            os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
            for case in args.cases:
                source, extras = root / (case + '-source'), root / (case + '-extras')
                source.mkdir(); extras.mkdir()
                keep = 1 if case == 'delete' else args.count
                extra = 0 if case == 'noop' else args.count if case == 'delete' else max(1, args.count // 10)
                new = max(1, args.count // 10) if case == 'mixed' else 0
                for label, count, directory in [('keep', keep, source), ('extra', extra, extras)]:
                    for i in range(count):
                        path = directory / f'{label}{i:08}'
                        path.write_bytes(bytes([i % 251]) * args.size)
                        os.utime(path, (1700000000, 1700000000))
                prefix = c.PREFIX + '/' + case
                run(command('syq', 'upload', source, prefix, False), 'seed-' + case)
                for i in range(new):
                    path = source / f'new{i:08}'
                    path.write_bytes(bytes([i % 251]) * args.size)
                    os.utime(path, (1700000000, 1700000000))
                for direction in args.directions:
                    seeds = {}
                    if direction == 'download':
                        run(command('syq', 'upload', source, prefix, False), 'download-source')
                        for tool in binaries:
                            seed = root / f'{case}-seed-{tool}'
                            seed.mkdir(); seeds[tool] = seed
                            run(command(tool, 'download', seed, prefix, False), 'download-seed-' + tool)
                            for path in seed.glob('new*'):
                                path.unlink()
                    for rep in range(args.repeats):
                        order = list(binaries)
                        order = order[rep % len(order):] + order[:rep % len(order)]
                        for tool in order:
                            local = source
                            if direction == 'upload':
                                if new:
                                    remove(c.listing(prefix + '/new'))
                                if extra:
                                    # A failed untimed restore can be retried safely;
                                    # preserve each attempt's log. Timed commands
                                    # are never retried or discarded.
                                    for attempt in range(3):
                                        try:
                                            run(command('s5cmd', 'upload', extras, prefix, False), 'restore-extras')
                                            break
                                        except RuntimeError:
                                            if attempt == 2:
                                                raise
                                            print('Untimed restore failed; retrying (see attempt log)', flush=True)
                                    assert len(c.listing(prefix + '/extra')) == extra
                            else:
                                local = root / 'download'
                                shutil.copytree(seeds[tool], local)
                                for path in extras.iterdir():
                                    shutil.copy2(path, local / path.name)
                            label = f'{case}-{direction}-{tool}-{rep}'
                            row = run(command(tool, direction, local, prefix), label)
                            row.update(case=case, direction=direction, tool=tool, repeat=rep,
                                       keep=keep, extra=extra, new=new, verified=False,
                                       long_enough=row['seconds'] >= args.minimum_seconds)
                            rows.append(row); save()
                            if direction == 'upload':
                                verify(prefix, source)
                            else:
                                assert {p.name for p in local.iterdir()} == {p.name for p in source.iterdir()}
                                assert all((local / p.name).read_bytes() == p.read_bytes() for p in source.iterdir())
                                shutil.rmtree(local)
                            row['verified'] = True; save()
                            print(json.dumps(row), flush=True)
                remove(c.listing(prefix + '/'))
            report['complete'] = True
    except BaseException as error:
        report['failure'] = f'{type(error).__name__}: {error}'
        save()
        raise
    finally:
        for key, upload in c.listing(uploads=True):
            assert key.startswith(c.PREFIX + '/')
            c.request('DELETE', key, query={'uploadId': upload})
        remove(c.listing())
        assert not c.listing() and not c.listing(uploads=True)
        report['cleaned'] = True
        save()


if __name__ == '__main__':
    main()
