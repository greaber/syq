#!/usr/bin/env python3
"""Compare syq with s5cmd on owned S3 objects: transfers and pruning.

Supply AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION,
AWS_ENDPOINT_URL_S3 and SYQ_TEST_BUCKET. This does not create buckets or change
their configuration; the pruning workloads require a bucket that has never
enabled versioning. Requires /usr/bin/time on Linux and Python 3.11 or newer.
Example, from the repository root:
  python3 tests/object-storage/benchmark.py --syq target/release/syq \\
    --s5cmd /path/to/s5cmd --output target/s3-benchmark
Omit --s5cmd to measure syq alone; use --baseline to include an older syq.
The default transfer workloads (large, medium, small) report throughput. The
opt-in pruning workloads (delete, noop, mixed) mirror many small objects with
--prune in both directions; select them with --workloads. Increase --count or
--size until individual trials last at least --minimum-seconds; short trials
are flagged, not silently combined or discarded.
Logs and raw measurements stay in --output.
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
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

TRANSFER = ['large', 'medium', 'small']
PRUNE = ['delete', 'noop', 'mixed']
STAMP = (1700000000, 1700000000)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--syq', required=True, type=Path, help='optimized syq executable')
    parser.add_argument('--s5cmd', type=Path, help='s5cmd executable; omit to measure syq alone')
    parser.add_argument('--s5cmd-quiet', action='store_true', help='Use s5cmd --log error to measure without per-object logging')
    parser.add_argument('--baseline', type=Path, help='older syq executable to include')
    parser.add_argument('--output', required=True, type=Path, help='new directory for logs and results.json')
    parser.add_argument('--workloads', nargs='+', choices=TRANSFER + PRUNE, default=TRANSFER,
                        help='transfer workloads by default; pruning workloads are opt-in')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--minimum-seconds', type=float, default=10)
    parser.add_argument('--timeout', type=float, default=1800)
    transfer = parser.add_argument_group('transfer workloads')
    transfer.add_argument('--workers', type=int, default=32, help='concurrent objects')
    transfer.add_argument('--concurrency', type=int, default=32, help='concurrent parts per object')
    transfer.add_argument('--part-size', type=int, default=64, help='MiB')
    transfer.add_argument('--large-mib', type=int, default=512)
    transfer.add_argument('--medium-count', type=int, default=64)
    transfer.add_argument('--small-count', type=int, default=1024)
    prune = parser.add_argument_group('pruning workloads')
    prune.add_argument('--count', type=int, default=100000, help='objects per tree')
    prune.add_argument('--size', type=int, default=1024, help='bytes per object')
    prune.add_argument('--directions', nargs='+', choices=['upload', 'download'], default=['upload', 'download'])
    prune.add_argument('--syq-tuning', help='Optional performance-tuning override for the syq binaries')
    args = parser.parse_args()
    if min(args.repeats, args.timeout, args.workers, args.concurrency, args.part_size, args.large_mib,
           args.medium_count, args.small_count, args.count, args.size) <= 0:
        parser.error('counts, sizes, repeats and timeout must be positive')
    binaries = {'syq': args.syq.resolve()}
    if args.s5cmd:
        binaries['s5cmd'] = args.s5cmd.resolve()
    if args.baseline:
        binaries['baseline'] = args.baseline.resolve()
    hashes = {name: hashlib.sha256(binary.read_bytes()).hexdigest() for name, binary in binaries.items()}
    args.output.mkdir(parents=True, exist_ok=False)
    # Reuse the trust store across independent verification requests. The
    # benchmarked binaries use their own HTTP clients and are unaffected.
    urllib.request.install_opener(urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context())))
    # check.py only uses argv[1] to set its executable; its signed HTTP helpers
    # are independent of syq and own a fresh random prefix.
    sys.argv = [sys.argv[0], str(args.syq.resolve())]
    spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check.py'))
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
    if any(w in PRUNE for w in args.workloads):
        _, body = c.request('GET', query={'versioning': ''})
        if any(n.tag.rsplit('}', 1)[-1] == 'Status' for n in ET.fromstring(body).iter()):
            raise RuntimeError('pruning workloads require a bucket that has never enabled versioning')
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'benchmark received signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    rows = []
    report = dict(prefix=c.PREFIX, endpoint=c.ENDPOINT, bucket=c.BUCKET, region=c.REGION,
                  harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  binary_sha256=hashes, settings={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                  host=os.uname().nodename, cpus=len(os.sched_getaffinity(0)), load=os.getloadavg(),
                  records=rows, complete=False, cleaned=False)
    header_flags = [flag for name, value in c.HEADERS.items() for flag in ['--s3-header', name + ': ' + value]]

    def save():
        (args.output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')

    sequence = 0

    def run(command, label, checked=True):
        nonlocal sequence
        sequence += 1
        report['phase'] = label
        save()
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
                if child.returncode and checked:
                    raise RuntimeError(f'{label}: exit {child.returncode}; see {stem}.log')
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                waiter.join(timeout=10)
        user, system, rss = map(float, stem.with_suffix('.usage').read_text().splitlines()[-1].split())
        return dict(seconds=ended[0] - started, exit_code=child.returncode, user_cpu=user, system_cpu=system, max_rss_kib=rss,
                    command=list(map(str, command)), log=str(stem.with_suffix('.log')))

    def measure(command, label, **fields):
        """Run one timed trial, record it, and fail after saving if it exited nonzero."""
        row = run(command, label, checked=False)
        row.update(fields, verified=False, long_enough=row['seconds'] >= args.minimum_seconds)
        rows.append(row)
        save()
        if row['exit_code']:
            raise RuntimeError(f'{label}: exit {row["exit_code"]}; see {row["log"]}')
        return row

    def verified(row):
        row['verified'] = True
        save()
        print(json.dumps(row), flush=True)

    def order(rep):
        names = list(binaries)
        return names[rep % len(names):] + names[:rep % len(names)]

    def s5cmd(*rest):
        return [binaries['s5cmd'], *(['--log', 'error'] if args.s5cmd_quiet else []), '--endpoint-url', c.ENDPOINT, *rest]

    def syq(tool, tuning, *rest):
        return [binaries[tool], 'cp', '--no-progress', *(['--performance-tuning', tuning] if tuning else []),
                *header_flags, *rest]

    def transfer_command(tool, direction, local, prefix):
        remote = f's3://{c.BUCKET}/{prefix}/'
        if tool == 's5cmd':
            base = s5cmd('--numworkers', str(args.workers), 'cp', '-c', str(args.concurrency), '-p', str(args.part_size))
            return base + ([str(local / '*'), remote] if direction == 'upload' else [remote + '*', str(local) + '/'])
        tuning = f's3-max-concurrent-objects={args.workers},s3-max-concurrent-parts-per-object={args.concurrency},s3-part-size={args.part_size}M'
        return syq(tool, tuning, *(['--srcs-in', local, '--to', f's3://{c.BUCKET}', '--into', prefix] if direction == 'upload'
                                   else ['--from', f's3://{c.BUCKET}', '--srcs-in', prefix, '--into', local]))

    def prune_command(tool, direction, local, prefix, prune=True):
        remote = f's3://{c.BUCKET}/{prefix}/'
        if tool == 's5cmd':
            return s5cmd('sync', *(['--delete'] if prune else []),
                         str(local) + '/' if direction == 'upload' else remote + '*',
                         remote if direction == 'upload' else str(local) + '/')
        return syq(tool, args.syq_tuning,
                   *(['--srcs-in', local, '--to', f's3://{c.BUCKET}', '--into', prefix] if direction == 'upload'
                     else ['--from', f's3://{c.BUCKET}', '--srcs-in', prefix, '--into', local]),
                   *(['--prune'] if prune else []))

    def remove(keys):
        report['phase'] = 'untimed cleanup'
        save()
        def batch_remove(batch):
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
            return len(batch)
        with ThreadPoolExecutor(10) as pool:
            removed = 0
            for count in pool.map(batch_remove, (keys[i:i + 1000] for i in range(0, len(keys), 1000))):
                removed += count
                if removed % 10000 == 0 or removed == len(keys):
                    print(f'Untimed cleanup: {removed}/{len(keys)} keys removed', flush=True)

    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').digest()

    def write_tree(directory, label, count, size):
        for i in range(count):
            path = directory / f'{label}{i:08}'
            path.write_bytes(bytes([i % 251]) * size)
            os.utime(path, STAMP)

    def verify_prefix(prefix, source):
        expected = {p.name for p in source.iterdir()}
        assert set(c.listing(prefix + '/')) == {prefix + '/' + name for name in expected}
        # Verify every newly copied body plus retained samples independently.
        samples = sorted(expected)[:16] + sorted(n for n in expected if n.startswith('new'))
        def check(name):
            assert c.request('GET', prefix + '/' + name)[1] == (source / name).read_bytes(), name
        with ThreadPoolExecutor(64) as pool:
            list(pool.map(check, samples))

    def transfer_workload(root, label):
        count, size = {'large': (1, args.large_mib * 2**20), 'medium': (args.medium_count, 8 * 2**20),
                       'small': (args.small_count, 64 * 1024)}[label]
        src = root / label
        src.mkdir()
        block = os.urandom(min(size, 8 * 2**20))
        for i in range(count):
            with (src / f'{i:05d}.bin').open('wb') as output:
                for _ in range(size // len(block)):
                    output.write(block)
        originals = {p.name: digest(p) for p in src.iterdir()}
        mib = count * size / 2**20
        for rep in range(args.repeats):
            for tool in order(rep):
                prefix = f'{c.PREFIX}/{label}/{tool}/{rep}'
                row = measure(transfer_command(tool, 'upload', src, prefix), f'{label}-upload-{tool}-{rep}',
                              workload=label, direction='upload', tool=tool, repeat=rep, count=count, bytes=size)
                row['MiB_s'] = mib / row['seconds']
                report['phase'] = f'verify-{label}-upload-{tool}-{rep}'
                save()
                assert set(c.listing(prefix + '/')) == {f'{prefix}/{name}' for name in originals}
                verified(row)
                dst = root / 'download'
                dst.mkdir()
                row = measure(transfer_command(tool, 'download', dst, prefix), f'{label}-download-{tool}-{rep}',
                              workload=label, direction='download', tool=tool, repeat=rep, count=count, bytes=size)
                row['MiB_s'] = mib / row['seconds']
                report['phase'] = f'verify-{label}-download-{tool}-{rep}'
                save()
                assert {p.name: digest(p) for p in dst.iterdir()} == originals, f'{tool} downloaded incorrect bytes'
                verified(row)
                shutil.rmtree(dst)
        remove(c.listing(f'{c.PREFIX}/{label}/'))
        shutil.rmtree(src)

    def prune_workload(root, case):
        source, extras = root / (case + '-source'), root / (case + '-extras')
        source.mkdir()
        extras.mkdir()
        keep = 1 if case == 'delete' else args.count
        extra = 0 if case == 'noop' else args.count if case == 'delete' else max(1, args.count // 10)
        new = max(1, args.count // 10) if case == 'mixed' else 0
        write_tree(source, 'keep', keep, args.size)
        write_tree(extras, 'extra', extra, args.size)
        prefix = c.PREFIX + '/' + case
        run(prune_command('syq', 'upload', source, prefix, False), 'seed-' + case)
        write_tree(source, 'new', new, args.size)
        for direction in args.directions:
            seeds = {}
            if direction == 'download':
                run(prune_command('syq', 'upload', source, prefix, False), 'download-source')
                for tool in binaries:
                    seed = root / f'{case}-seed-{tool}'
                    seed.mkdir()
                    seeds[tool] = seed
                    run(prune_command(tool, 'download', seed, prefix, False), 'download-seed-' + tool)
                    for path in seed.glob('new*'):
                        path.unlink()
            for rep in range(args.repeats):
                for tool in order(rep):
                    local = source
                    if direction == 'upload':
                        if new:
                            remove(c.listing(prefix + '/new'))
                        if extra:
                            restore_extras(extras, prefix, extra)
                    else:
                        local = root / 'download'
                        shutil.copytree(seeds[tool], local)
                        for path in extras.iterdir():
                            shutil.copy2(path, local / path.name)
                    label = f'{case}-{direction}-{tool}-{rep}'
                    row = measure(prune_command(tool, direction, local, prefix), label, workload=case,
                                  direction=direction, tool=tool, repeat=rep, keep=keep, extra=extra, new=new)
                    report['phase'] = 'verify-' + label
                    save()
                    if direction == 'upload':
                        verify_prefix(prefix, source)
                    else:
                        assert {p.name for p in local.iterdir()} == {p.name for p in source.iterdir()}
                        assert all((local / p.name).read_bytes() == p.read_bytes() for p in source.iterdir())
                        shutil.rmtree(local)
                    verified(row)
        remove(c.listing(prefix + '/'))

    def restore_extras(extras, prefix, extra):
        # A failed untimed restore can be retried safely; preserve each
        # attempt's log. Timed commands are never retried or discarded.
        for attempt in range(3):
            try:
                if 's5cmd' in binaries:
                    run(s5cmd('cp', str(extras) + '/*', f's3://{c.BUCKET}/{prefix}/'), 'restore-extras')
                else:
                    run(syq('syq', args.syq_tuning, '--srcs-in', extras, '--to', f's3://{c.BUCKET}', '--into', prefix),
                        'restore-extras')
                break
            except RuntimeError:
                if attempt == 2:
                    raise
                print('Untimed restore failed; retrying (see attempt log)', flush=True)
        assert len(c.listing(prefix + '/extra')) == extra

    save()
    try:
        with tempfile.TemporaryDirectory(prefix='syq-s3-benchmark-') as temp:
            root = Path(temp)
            os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
            for workload in args.workloads:
                if workload in TRANSFER:
                    transfer_workload(root, workload)
                else:
                    prune_workload(root, workload)
            report['complete'] = True
    except BaseException as error:
        report['failure'] = f'{type(error).__name__}: {error}'
        save()
        print('Benchmark failed: ' + report['failure'] + '; cleaning owned prefix', flush=True)
        raise
    finally:
        for key, upload in c.listing(uploads=True):
            assert key.startswith(c.PREFIX + '/')
            c.request('DELETE', key, query={'uploadId': upload})
        remove(c.listing())
        assert not c.listing() and not c.listing(uploads=True)
        report['cleaned'] = True
        save()
    for workload in args.workloads:
        for direction in ['upload', 'download']:
            parts = []
            for tool in binaries:
                trials = [r for r in rows if (r['workload'], r['direction'], r['tool']) == (workload, direction, tool)]
                if not trials:
                    continue
                if workload in TRANSFER:
                    parts.append(f'{tool} {statistics.median(r["MiB_s"] for r in trials):.1f} MiB/s')
                else:
                    parts.append(f'{tool} {statistics.median(r["seconds"] for r in trials):.1f}s')
                if not all(r['long_enough'] for r in trials):
                    parts[-1] += ' (short trials)'
            if parts:
                print(f'{workload} {direction}: ' + ', '.join(parts), flush=True)


if __name__ == '__main__':
    main()
