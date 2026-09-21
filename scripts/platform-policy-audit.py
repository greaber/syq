#!/usr/bin/env python3
"""One-off policy audit; warm-cache command timings, not durable-write throughput."""
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1 << 20), b''):
            h.update(data)
    return h.hexdigest()


def emit(value):
    print(json.dumps(value), flush=True)


def measure(binary, root, destination_root, volume, cases):
    for label, count, size in cases:
        source = root / 'source'
        source.mkdir()
        data = os.urandom(size)
        expected = hashlib.sha256(data).hexdigest()
        for n in range(count):
            (source / f'file-{n:05d}').write_bytes(data)
        for policy in ('auto', 'fixed8'):
            timings = {65536: [], 4194304: []}
            # Balanced ABBA/BAAB; eight samples per threshold.
            order = [65536, 4194304, 4194304, 65536,
                     4194304, 65536, 65536, 4194304] * 2
            for iteration, threshold in enumerate(order):
                destination = destination_root / 'destination'
                env = dict(os.environ, SYQ_TUNING_CACHE='', SYQ_TUNING_HISTORY='',
                           SYQ_AUDIT_BATCH_THRESHOLD=str(threshold), SYQ_DEBUG='1')
                command = [str(binary), 'cp', '--srcs-in', str(source), '--into',
                           str(destination), '--no-progress']
                if policy == 'fixed8':
                    command.append('--performance-tuning=workers=8')
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                start = time.perf_counter()
                result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=120)
                elapsed = time.perf_counter() - start
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                if result.returncode:
                    raise RuntimeError(result.stderr)
                files = list(destination.iterdir())
                if len(files) != count or any(digest(p) != expected for p in files):
                    raise RuntimeError('copied bytes differ')
                observed = next((json.loads(line.split(': ', 2)[2]) for line in result.stderr.splitlines()
                                 if line.startswith('syq: tuning observed: ')), None)
                if observed is None:
                    raise RuntimeError('copy-path observations missing')
                timings[threshold].append(elapsed)
                emit(dict(kind='sample', volume=volume, case=label, policy=policy,
                          iteration=iteration, threshold=threshold, seconds=elapsed,
                          user_cpu=after.ru_utime-before.ru_utime,
                          system_cpu=after.ru_stime-before.ru_stime, observed=observed))
                shutil.rmtree(destination)
            emit(dict(kind='summary', volume=volume, case=label, policy=policy,
                      count=count, bytes_per_file=size,
                      median={k: statistics.median(v) for k,v in timings.items()},
                      min={k: min(v) for k,v in timings.items()},
                      max={k: max(v) for k,v in timings.items()}))
        shutil.rmtree(source)


def main():
    binary = Path(sys.argv[1]).resolve(strict=True)
    emit(dict(kind='environment', system=platform.platform(),
              sha=subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip(),
              cache='warm, source written immediately before runs',
              timing='process startup through completion; excludes verification and cleanup'))
    with tempfile.TemporaryDirectory(prefix='syq-platform-audit-') as temp:
        root = Path(temp).resolve()
        measure(binary, root, root, platform.system(),
                [('tiny',2048,32768),('medium128k',4096,131072),
                 ('medium1m',512,1048576),('large5m',104,5<<20)])
        if platform.system() == 'Darwin':
            # The mount is separately owned: never recursively remove it if detach fails.
            volume_root = Path(tempfile.mkdtemp(prefix='syq-platform-volume-')).resolve()
            image = volume_root / 'exfat.dmg'
            mount = volume_root / 'mount'
            mount.mkdir()
            subprocess.run(['hdiutil','create','-size','1g','-fs','ExFAT','-volname','SYQAUDIT',str(image)],check=True,timeout=120)
            subprocess.run(['hdiutil','attach','-nobrowse','-mountpoint',str(mount),str(image)],check=True,timeout=120)
            try:
                measure(binary, root, mount, 'exfat-image',
                        [('medium128k',2048,131072),('medium1m',256,1048576)])
            finally:
                subprocess.run(['hdiutil','detach',str(mount)],check=True,timeout=120)
                shutil.rmtree(volume_root)


if __name__ == '__main__':
    main()
