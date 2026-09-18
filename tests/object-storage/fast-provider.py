#!/usr/bin/env python3
"""Opt-in provider checks for the automatic transfer path; owns one key prefix."""
import hashlib, importlib.util, os, pathlib, subprocess, sys, tempfile
spec=importlib.util.spec_from_file_location('checks',pathlib.Path(__file__).with_name('check.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
binary=str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='syq-fast-check-') as tmp:
    root=pathlib.Path(tmp).resolve();source=root/'source';source.mkdir();cache=root/'cache'
    env={**os.environ,'XDG_CACHE_HOME':str(cache)}
    def run(*args):
        subprocess.run([binary,'cp','--no-progress',*map(str,args)],env=env,check=True,timeout=180)
    try:
        block=os.urandom(1024*1024)
        expected={}
        for size in [0,1,65536,9*2**20+17,257*2**20+19]:
            p=source/str(size)
            with p.open('wb') as f:
                left=size
                while left:
                    b=block[:min(left,len(block))];f.write(b);left-=len(b)
            expected[p.name]=hashlib.sha256(p.read_bytes()).digest()
        run('--srcs-in',source,'--to','s3://'+c.BUCKET,'--into',c.PREFIX)
        for name,digest in expected.items():
            headers,body=c.request('GET',c.PREFIX+'/'+name)
            assert hashlib.sha256(body).digest()==digest
            assert 'x-amz-meta-syq-blake3' not in {k.lower() for k in headers}
        target=root/'target'
        run('--from','s3://'+c.BUCKET,'--srcs-in',c.PREFIX,'--into',target)
        for name,digest in expected.items():
            p=target/name
            assert hashlib.sha256(p.read_bytes()).digest()==digest
            assert p.stat().st_mtime_ns==(source/name).stat().st_mtime_ns
        before={p.name:p.stat().st_ino for p in target.iterdir()}
        run('--from','s3://'+c.BUCKET,'--srcs-in',c.PREFIX,'--into',target)
        assert {p.name:p.stat().st_ino for p in target.iterdir()}==before
        assert not list((cache/'syq'/'s3').glob('*.json'))
        assert not list(target.glob('.syq-s3-*'))
        # Verification independently checks objects written without digests.
        subprocess.run([binary,'cp','--no-progress','--verify-only','--from','s3://'+c.BUCKET,'--srcs-in',c.PREFIX,'--into',str(target)],env=env,check=True,timeout=180)
        print('Automatic sizes, direct-I/O tail, quick check, metadata, and content verification passed',flush=True)
    finally:c.clean()
