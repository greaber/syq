#!/usr/bin/env python3
"""Compare syq and s5cmd on owned S3 objects; see --help. Standard library only."""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import statistics
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('syq', help='optimized syq executable')
parser.add_argument('--s5cmd', required=True, help='s5cmd executable')
parser.add_argument('--repeats', type=int, default=3)
parser.add_argument('--workers', type=int, default=32)
parser.add_argument('--concurrency', type=int, default=32)
parser.add_argument('--part-size', type=int, default=64, help='MiB')
parser.add_argument('--large-mib', type=int, default=512)
parser.add_argument('--medium-count', type=int, default=64)
parser.add_argument('--small-count', type=int, default=1024)
parser.add_argument('--workloads', nargs='+', choices=['large', 'medium', 'small'], default=['large', 'medium', 'small'])
parser.add_argument('--output', type=Path, required=True, help='JSON measurements outside tracked documentation')
args = parser.parse_args()
if min(args.repeats, args.workers, args.concurrency, args.part_size, args.large_mib, args.medium_count, args.small_count) <= 0:
    parser.error('counts and sizes must be positive')
spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
executables = {'syq': str(Path(args.syq).resolve()), 's5cmd': str(Path(args.s5cmd).resolve())}
records = []


def timed(command, tool):
    start = time.monotonic()
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors, start_new_session=True)
        waiter = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        finished = waiter.submit(process.wait)
        try:
            while not finished.done():
                elapsed = time.monotonic() - start
                if elapsed >= 240:
                    raise TimeoutError(f'{tool} exceeded 240 seconds')
                try: finished.result(timeout=min(10, 240 - elapsed))
                except concurrent.futures.TimeoutError:
                    print(f'{tool} still transferring ({time.monotonic() - start:.0f}s)', flush=True)
            if process.returncode:
                errors.seek(0)
                raise RuntimeError(f'{tool} failed: {errors.read().decode(errors="replace")}')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            waiter.shutdown(wait=True)
    return time.monotonic() - start


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').digest()


with tempfile.TemporaryDirectory(prefix='syq-s3-bench-') as temp:
    root = Path(temp)
    os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
    try:
        for label, count, size in [('large', 1, args.large_mib * 2**20), ('medium', args.medium_count, 8 * 2**20), ('small', args.small_count, 64 * 1024)]:
            if label not in args.workloads: continue
            src = root / label
            src.mkdir()
            block = os.urandom(min(size, 8 * 2**20))
            for i in range(count):
                with (src / f'{i:05d}.bin').open('wb') as output:
                    for _ in range(size // len(block)): output.write(block)
            originals = {p.name: digest(p) for p in src.iterdir()}
            for repeat in range(args.repeats):
                for tool in (['s5cmd', 'syq'] if repeat % 2 == 0 else ['syq', 's5cmd']):
                    prefix = f'{c.PREFIX}/{label}/{tool}/{repeat}'
                    flags = [flag for name, value in c.HEADERS.items() for flag in ['--s3-header', name + ': ' + value]]
                    if tool == 's5cmd':
                        base = [executables[tool], '--endpoint-url', c.ENDPOINT, '--numworkers', str(args.workers), 'cp', '-c', str(args.concurrency), '-p', str(args.part_size)]
                        upload = base + [str(src / '*'), f's3://{c.BUCKET}/{prefix}/']
                    else:
                        base = [executables[tool], 'cp', '--no-progress', '--performance-tuning', f's3-object-workers={args.workers},s3-part-workers={args.concurrency},s3-part-size={args.part_size}M', *flags]
                        upload = base + ['--srcs-in', str(src), '--to', 's3://' + c.BUCKET, '--into', prefix]
                    seconds = timed(upload, tool)
                    row = dict(workload=label, direction='upload', tool=tool, repeat=repeat, seconds=seconds, MiB_s=count * size / 2**20 / seconds)
                    records.append(row)
                    print(json.dumps(row), flush=True)
                    dst = root / 'download'
                    dst.mkdir()
                    if tool == 's5cmd': download = base + [f's3://{c.BUCKET}/{prefix}/*', str(dst) + '/']
                    else: download = base + ['--from', 's3://' + c.BUCKET, '--srcs-in', prefix, '--into', str(dst)]
                    seconds = timed(download, tool)
                    assert {p.name: digest(p) for p in dst.iterdir()} == originals, f'{tool} downloaded incorrect bytes'
                    row = dict(workload=label, direction='download', tool=tool, repeat=repeat, seconds=seconds, MiB_s=count * size / 2**20 / seconds)
                    records.append(row)
                    print(json.dumps(row), flush=True)
                    shutil.rmtree(dst)
            c.clean()
            shutil.rmtree(src)
    finally:
        args.output.write_text(json.dumps({'workers': args.workers, 'concurrency': args.concurrency, 'part_size_mib': args.part_size, 'measurements': records}, indent=2) + '\n')
        c.clean()
for label in args.workloads:
    for direction in ['upload', 'download']:
        rates = {tool: statistics.median(r['MiB_s'] for r in records if (r['workload'], r['direction'], r['tool']) == (label, direction, tool)) for tool in executables}
        print(f'{label} {direction}: syq {rates["syq"]:.1f}, s5cmd {rates["s5cmd"]:.1f} MiB/s; ratio {rates["syq"] / rates["s5cmd"]:.2f}', flush=True)
