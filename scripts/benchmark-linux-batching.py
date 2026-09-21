#!/usr/bin/env python3
"""Audit-only Linux batching/whole-file factorial comparison in disposable trees."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import statistics
import subprocess
import tempfile
import time


def emit(stream, value):
    line = json.dumps(value, sort_keys=True)
    print(line, flush=True)
    stream.write(line + '\n')
    stream.flush()


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda: f.read(1 << 20), b''):
            h.update(data)
    return h.hexdigest()


def cpus_for_test(count):
    selected, cores = [], set()
    for cpu in sorted(os.sched_getaffinity(0)):
        topology = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
        key = ((topology / 'physical_package_id').read_text().strip(),
               (topology / 'core_id').read_text().strip())
        if key not in cores:
            selected.append(cpu)
            cores.add(key)
        if len(selected) == count:
            return selected
    return selected


def run_copy(command, env, timeout):
    process = subprocess.Popen(command, env=env, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate()
        raise RuntimeError(f'timed out after {timeout}s: {err}')
    if process.returncode:
        raise RuntimeError(f'copy failed ({process.returncode}): {err}')
    return out, err


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/syq'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=4)
    parser.add_argument('--mib', type=int, default=512)
    parser.add_argument('--cpus', type=int, default=8)
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--count', type=int)
    parser.add_argument('--topologies', default='ext4,tmpfs,ext4-to-tmpfs')
    parser.add_argument('--sizes', default='131072,1048576')
    parser.add_argument('--policies', default='auto,fixed8')
    parser.add_argument('--paths', default='native,ranges')
    parser.add_argument('--trace-dir', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('Linux only')
    if args.rounds < 1 or args.mib < 1 or args.cpus < 1:
        parser.error('positive rounds, MiB and CPUs required')
    binary = args.binary.resolve(strict=True)
    cpus = cpus_for_test(args.cpus)
    os.sched_setaffinity(0, cpus)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    topologies = {'ext4': ('/tmp','/tmp'), 'tmpfs': ('/dev/shm','/dev/shm'),
                  'ext4-to-tmpfs': ('/tmp','/dev/shm'), 'tmpfs-to-ext4': ('/dev/shm','/tmp')}
    with args.output.open('w') as report:
        emit(report, dict(kind='environment', sha=subprocess.check_output(
            ['git','rev-parse','HEAD'], text=True).strip(), binary_sha256=digest(binary),
            platform=platform.platform(), cpus=cpus, load=os.getloadavg(),
            cache='warm; command completion only; no durability claim',
            filesystems={p: subprocess.check_output(['stat','-f','-c','%T',p], text=True).strip()
                         for p in ('/tmp','/dev/shm')}))
        for topology in args.topologies.split(','):
            srcbase, dstbase = topologies[topology]
            for size in map(int, args.sizes.split(',')):
                count = args.count or (8 if args.smoke else max(8, args.mib*(1 << 20)//size))
                with tempfile.TemporaryDirectory(prefix='syq-linux-batch-src-', dir=srcbase) as s, \
                     tempfile.TemporaryDirectory(prefix='syq-linux-batch-dst-', dir=dstbase) as d:
                    source, destination_root = Path(s).resolve(), Path(d).resolve()
                    payload = os.urandom(size)
                    expected_hash = hashlib.sha256(payload).hexdigest()
                    names = {f'file-{n:05d}' for n in range(count)}
                    for name in sorted(names):
                        (source/name).write_bytes(payload)
                    for policy in args.policies.split(','):
                        for path in args.paths.split(','):
                            samples = {65536: [], 4194304: []}
                            # Each round is a pair; alternate order for balance.
                            for round_no in range(args.rounds):
                                order = [65536,4194304] if round_no % 2 == 0 else [4194304,65536]
                                for threshold in order:
                                    destination = destination_root/'copy'
                                    env = dict(os.environ, SYQ_TUNING_CACHE='', SYQ_TUNING_HISTORY='',
                                               SYQ_AUDIT_BATCH_THRESHOLD=str(threshold), SYQ_DEBUG='1')
                                    env.pop('SYQ_AUDIT_NO_WHOLE_COPY', None)
                                    if path == 'ranges':
                                        env['SYQ_AUDIT_NO_WHOLE_COPY'] = '1'
                                    elif path != 'native':
                                        raise ValueError(path)
                                    command = [str(binary),'cp','--srcs-in',str(source),'--into',
                                               str(destination),'--no-progress']
                                    if policy == 'fixed8': command.append('--performance-tuning=workers=8')
                                    elif policy != 'auto': raise ValueError(policy)
                                    if args.trace_dir:
                                        args.trace_dir.mkdir(parents=True, exist_ok=True)
                                        trace=args.trace_dir/f'{topology}-{size}-{policy}-{path}-{threshold}-{round_no}.txt'
                                        command=['strace','-f','-c','-e','trace=ioctl,copy_file_range,pread64,pwrite64,read,write',
                                                 '-o',str(trace)]+command
                                    before=resource.getrusage(resource.RUSAGE_CHILDREN)
                                    load_before=os.getloadavg()
                                    start=time.perf_counter()
                                    _, err=run_copy(command,env,120)
                                    elapsed=time.perf_counter()-start
                                    after=resource.getrusage(resource.RUSAGE_CHILDREN)
                                    actual=list(destination.iterdir())
                                    if {f.name for f in actual} != names or any(digest(f)!=expected_hash for f in actual):
                                        raise RuntimeError('file names or contents differ')
                                    prefix='syq: tuning observed: '
                                    observed=next((json.loads(line[len(prefix):]) for line in err.splitlines()
                                                   if line.startswith(prefix)),None)
                                    if observed is None: raise RuntimeError('missing path counters')
                                    if path=='ranges' and observed['local_whole_files'] != 0:
                                        raise RuntimeError('whole-file bypass did not apply')
                                    sample=dict(kind='sample',topology=topology,size=size,count=count,
                                                policy=policy,path=path,threshold=threshold,round=round_no,
                                                seconds=elapsed,user_cpu=after.ru_utime-before.ru_utime,
                                                system_cpu=after.ru_stime-before.ru_stime,
                                                observed=observed,load_before=load_before,load_after=os.getloadavg(),
                                                traced=bool(args.trace_dir))
                                    samples[threshold].append(sample)
                                    emit(report,sample)
                                    shutil.rmtree(destination)
                            emit(report,dict(kind='summary',topology=topology,size=size,count=count,policy=policy,path=path,
                                             seconds={k:statistics.median(x['seconds'] for x in v) for k,v in samples.items()},
                                             cpu={k:statistics.median(x['user_cpu']+x['system_cpu'] for x in v)
                                                  for k,v in samples.items()}))
                emit(report,dict(kind='cleanup',source_removed=not Path(s).exists(),destination_removed=not Path(d).exists()))


if __name__=='__main__':
    main()
