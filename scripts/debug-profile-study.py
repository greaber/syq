#!/usr/bin/env python3
"""Temporary, manually dispatched profile experiment; not a CI policy."""
import json, os, pathlib, platform, statistics, subprocess, sys, tempfile, time
root = pathlib.Path.cwd()
assert root.name == 'syq' or root.name == 'debug-profile-study'
variant = sys.argv[1]
settings = {
 'current': [],
 'deps1': ['profile.dev.package."*".opt-level=1'],
 'all1': ['profile.dev.opt-level=1'],
 'all2': ['profile.dev.opt-level=2'],
}[variant]
# Specific BLAKE3 override remains level 3 in every variant.
env = os.environ.copy()
env['CARGO_TARGET_DIR'] = str(root / 'target' / ('study-' + variant))
cargo = ['cargo'] + [item for setting in settings for item in ('--config', setting)]
summary = {'variant':variant, 'machine':platform.platform(), 'cpus':os.cpu_count(), 'build':{}, 'workloads':{}}
def run(label, args, timeout=1200, capture=False, extra_env=None):
    print('START', label, flush=True)
    start = time.monotonic()
    result = subprocess.run(args, env=extra_env or env, timeout=timeout, check=True,
                            stdout=subprocess.PIPE if capture else None, text=True)
    seconds = time.monotonic()-start
    print('DONE', label, seconds, flush=True)
    return seconds, result.stdout
for label in ['fresh', 'noop', 'source_edit']:
    if label == 'source_edit':
        path = root / 'src/main.rs'
        original = path.read_bytes()
        path.write_bytes(original + b'\n// Temporary source edit for rebuild timing.\n')
    try:
        elapsed, _ = run(label, cargo + ['build','--locked','--bin','syq'])
        summary['build'][label] = elapsed
    finally:
        if label == 'source_edit': path.write_bytes(original)
run('build_probe', cargo + ['build','--locked','--bin','profile-probe'])
bindir = pathlib.Path(env['CARGO_TARGET_DIR'])/'debug'
_, output = run('primitive_workloads', [str(bindir/'profile-probe')], capture=True)
print(output, flush=True)
for line in output.splitlines():
    if line.startswith('PROBE '):
        row = json.loads(line[6:]); summary['workloads'][row['name']] = row['seconds']
with tempfile.TemporaryDirectory(prefix='syq-profile-study-') as tmp:
    tmp = pathlib.Path(tmp).resolve()
    source = tmp/'source'; source.write_bytes(bytes(range(256)) * 65536)
    isolated = env | {'HOME':str(tmp/'home'), 'XDG_CACHE_HOME':str(tmp/'cache'), 'XDG_CONFIG_HOME':str(tmp/'config')}
    for label, options in [('pipes',['--no-tcp']), ('tcp_encrypted',[]), ('tcp_plain',['--tcp-plain'])]:
        times=[]
        for i in range(3):
            destination=tmp/f'{label}-{i}'
            elapsed,_=run(label,[str(bindir/'syq'),'cp','--no-progress','--no-compress','--tcp-ports','0-0',
                '--performance-tuning','workers=2,copy-path=ranges',*options,str(source),'--as',str(destination)],extra_env=isolated)
            assert destination.read_bytes()==source.read_bytes()
            times.append(elapsed)
        summary['workloads'][label+'_16mib']=times
summary['binary_bytes']=(bindir/'syq').stat().st_size
path = root/'target'/f'profile-study-{variant}.json'
path.write_text(json.dumps(summary,indent=2)+'\n')
print('SUMMARY '+json.dumps(summary),flush=True)
