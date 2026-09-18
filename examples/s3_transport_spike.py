import concurrent.futures, datetime, hashlib, hmac, importlib.util, json, os, pathlib, random, resource, shutil, signal, ssl, subprocess, sys, time, urllib.parse, urllib.request
ROOT=pathlib.Path.cwd(); D=ROOT/'target/transport-spike'; BIN=ROOT/'target/release/examples/s3_transport_spike'
assert subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip()==str(ROOT)
CERT=D/'cert'; CERT.mkdir(exist_ok=True)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(CERT/'private.key'),'-out',str(CERT/'public.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
os.environ.update(AWS_ACCESS_KEY_ID='syq-test-user',AWS_SECRET_ACCESS_KEY='syq-test-password',AWS_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',SYQ_TEST_BUCKET='transport-spike')
for k in ('AWS_SESSION_TOKEN','AWS_PROFILE'): os.environ.pop(k,None)
container=None; results=[]
ctx=ssl.create_default_context(cafile=str(CERT/'public.crt'))
# Independent Python signing/verification, using the repository's fixture helper.
original_open=urllib.request.urlopen
urllib.request.urlopen=lambda *a,**k: original_open(*a,context=ctx,**k)
def presign(key):
    now=datetime.datetime.now(datetime.timezone.utc); day=now.strftime('%Y%m%d'); stamp=now.strftime('%Y%m%dT%H%M%SZ'); scope=f'{day}/us-east-1/s3/aws4_request'
    path='/transport-spike/'+key
    q=urllib.parse.urlencode(sorted({'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Credential':'syq-test-user/'+scope,'X-Amz-Date':stamp,'X-Amz-Expires':'3600','X-Amz-SignedHeaders':'host'}.items()),quote_via=urllib.parse.quote)
    canonical='\n'.join(['GET',path,q,'host:'+urllib.parse.urlsplit(endpoint).netloc+'\n','host','UNSIGNED-PAYLOAD'])
    signed='\n'.join(['AWS4-HMAC-SHA256',stamp,scope,hashlib.sha256(canonical.encode()).hexdigest()]); secret=b'AWS4syq-test-password'
    for item in [day,'us-east-1','s3','aws4_request']: secret=hmac.new(secret,item.encode(),hashlib.sha256).digest()
    return endpoint+path+'?'+q+'&X-Amz-Signature='+hmac.new(secret,signed.encode(),hashlib.sha256).hexdigest()
try:
    container=subprocess.check_output(['docker','run','--detach','--rm','--tmpfs','/data:rw,size=2g','-p','127.0.0.1::9000','-v',str(CERT)+':/certs:ro','-e','MINIO_ROOT_USER=syq-test-user','-e','MINIO_ROOT_PASSWORD=syq-test-password','minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e','server','/data','--certs-dir','/certs'],text=True).strip()
    port=subprocess.check_output(['docker','inspect','--format','{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}',container],text=True).strip(); endpoint='https://127.0.0.1:'+port
    (D/'container.json').write_text(json.dumps({'id':container,'endpoint':endpoint}))
    os.environ['AWS_ENDPOINT_URL_S3']=endpoint
    deadline=time.monotonic()+60
    while True:
        try:
            with urllib.request.urlopen(endpoint+'/minio/health/ready',timeout=2) as r: assert r.status==200
            break
        except Exception as e:
            if time.monotonic()>deadline: raise RuntimeError(f'MinIO readiness timeout: {e}')
            print(f'Waiting for MinIO: {e}',flush=True); time.sleep(2)
    sys.argv=[sys.argv[0],str(BIN)]
    spec=importlib.util.spec_from_file_location('checks',ROOT/'tests/object-storage/check.py'); checks=importlib.util.module_from_spec(spec); spec.loader.exec_module(checks); checks.request('PUT')
    fixtures={}
    for name,count,size in [('small',1024,64*1024),('large',16,16*1024*1024)]:
        data=os.urandom(size); source=D/(name+'.source'); source.write_bytes(data)
        digest=subprocess.check_output([BIN,'digest',source],text=True).strip(); sha=hashlib.sha256(data).hexdigest()
        def put(i): checks.request('PUT',f'{name}/{i}',data)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool: list(pool.map(put,range(count)))
        manifest=[{'url':presign(f'{name}/{i}'),'size':size,'blake3':digest} for i in range(count)]
        (D/(name+'.json')).write_text(json.dumps(manifest)); fixtures[name]={'count':count,'size':size,'sha256':sha}
        print(f'Prepared {name}: {count} x {size} bytes',flush=True)
    jobs=[(name,sink,c) for name in fixtures for sink in ('memory','file') for c in (1,16,64)]
    random.Random(841).shuffle(jobs)
    for rep in range(3):
        for name,sink,c in jobs:
            modes=['async','sync'] if rep%2==0 else ['sync','async']
            for mode in modes:
                out=D/'output'; out.mkdir()
                timing=D/'timing.json'; command=['/usr/bin/time','-f','{"user":%U,"system":%S,"rss_kib":%M,"wall":%e,"voluntary":%w,"involuntary":%c}','-o',str(timing),str(BIN),mode,str(D/(name+'.json')),str(c),str(out) if sink=='file' else '-',str(CERT/'public.crt'),'32']
                p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
                try: stdout,stderr=p.communicate(timeout=180)
                except BaseException:
                    os.killpg(p.pid,signal.SIGKILL);p.wait();raise
                if p.returncode: raise RuntimeError(f'{command}: {stderr}')
                row=json.loads(stdout); row.update(json.loads(timing.read_text())); row.update(workload=name,sink=sink,rep=rep)
                if sink=='file':
                    files=list(out.iterdir()); assert len(files)==fixtures[name]['count']
                    for f in files: assert hashlib.sha256(f.read_bytes()).hexdigest()==fixtures[name]['sha256']
                shutil.rmtree(out)
                results.append(row); (D/'results.json').write_text(json.dumps(results,indent=2)); print(json.dumps(row),flush=True)
    (D/'fixtures.json').write_text(json.dumps(fixtures,indent=2))
finally:
    if container:
        subprocess.run(['docker','rm','-f',container],check=True)
        remaining=subprocess.check_output(['docker','ps','-aq','--filter','id='+container],text=True).strip(); assert not remaining
        (D/'cleanup.json').write_text(json.dumps({'container_removed':container,'verified_absent':True}))
