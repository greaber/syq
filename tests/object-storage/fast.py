#!/usr/bin/env python3
"""Local fault-injection checks for automatic S3 transfers. No cloud credentials."""
import base64, hashlib, shutil, http.server, json, os, pathlib, signal, subprocess, sys, tempfile, threading, time, urllib.parse
binary = str(pathlib.Path(sys.argv[1]).resolve())
events = []
scenario = "upload"
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def respond(self, status, body=b"", headers=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def do_HEAD(self):
        if scenario.startswith("download"):
            self.respond(200, b"x"*11, {"ETag": '"fixture"', "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT"})
        else: self.respond(404)
    def do_GET(self):
        if "list-type=" in self.path:
            self.respond(200,b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>")
        else:
            self.send_response(200); self.send_header("Content-Length","11"); self.send_header("ETag",'"fixture"'); self.end_headers()
            self.wfile.write(b"bad" if scenario=="download-truncated" else b"hello world")
            self.close_connection=True
    def do_POST(self):
        length=int(self.headers.get("Content-Length","0")); self.rfile.read(length)
        if "uploadId=" in self.path:
            events.append(("complete",time.monotonic())); self.respond(200,b'<CompleteMultipartUploadResult><ETag>"whole"</ETag></CompleteMultipartUploadResult>')
        else:
            events.append(("create",time.monotonic())); self.respond(200,b"<InitiateMultipartUploadResult><UploadId>fixture</UploadId></InitiateMultipartUploadResult>")
    def do_PUT(self):
        assert self.headers.get("x-amz-content-sha256")=="UNSIGNED-PAYLOAD"
        assert self.headers.get("x-amz-checksum-sha256")
        assert not self.headers.get("x-amz-meta-syq-blake3")
        part=int(urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("partNumber",[0])[0])
        events.append(("put-start",time.monotonic(),part))
        left=int(self.headers["Content-Length"])
        digest=hashlib.sha256()
        while left:
            block=self.rfile.read(min(left,1024*1024))
            if not block: break
            digest.update(block)
            left-=len(block)
        assert base64.b64encode(digest.digest()).decode()==self.headers["x-amz-checksum-sha256"]
        if part==2: time.sleep(.4)
        if scenario in ("upload-delayed", "upload-single-delayed"): time.sleep(7)
        events.append(("put-end",time.monotonic(),part))
        if (scenario=="upload-failure" and part==1) or scenario=="upload-single-failure":
            self.respond(400,b"<Error><Code>InvalidRequest</Code><Message>injected failure</Message></Error>")
        else: self.respond(200,headers={"ETag":'"part"'})
    def do_DELETE(self):
        events.append(("abort",time.monotonic())); self.respond(204)
server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
thread=threading.Thread(target=server.serve_forever);thread.start()
try:
    with tempfile.TemporaryDirectory(prefix="syq-s3-fast-") as temp:
        root=pathlib.Path(temp); source=root/"source"; source.write_bytes(os.urandom(11*2**20))
        env={**os.environ,"AWS_ACCESS_KEY_ID":"fixture","AWS_SECRET_ACCESS_KEY":"fixture","AWS_REGION":"us-east-1","AWS_EC2_METADATA_DISABLED":"true","AWS_ENDPOINT_URL_S3":"http://127.0.0.1:"+str(server.server_address[1]),"XDG_CACHE_HOME":str(root/"cache")}
        base=[binary,"cp","--no-progress","--performance-tuning", "s3-retries=0,s3-part-size=5M,s3-max-concurrent-parts-per-object=2"]
        for scenario in ["upload", "upload-delayed", "upload-single", "upload-single-delayed", "upload-single-failure", "upload-failure", "upload-interrupted", "download", "download-truncated"]:
            shutil.rmtree(root/"cache",ignore_errors=True)
            events.clear(); destination=root/"download"; destination.unlink(missing_ok=True)
            command=base+([str(source),"--to","s3://fixture","--as","object"] if scenario.startswith("upload") else ["--from","s3://fixture","object","--as",str(destination)])
            if scenario.startswith("upload-single"): command[command.index("--performance-tuning")+1]="s3-retries=0,s3-part-size=16M,s3-max-concurrent-parts-per-object=2"
            if scenario=="upload-interrupted":
                child=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                deadline=time.monotonic()+10
                while not any(e[0]=="put-start" for e in events) and time.monotonic()<deadline: time.sleep(.01)
                assert any(e[0]=="put-start" for e in events)
                child.send_signal(signal.SIGTERM);out,err=child.communicate(timeout=20);code=child.returncode
            else:
                result=subprocess.run(command,env=env,capture_output=True,timeout=30);code=result.returncode;err=result.stderr
            expected=scenario in ("upload","upload-delayed","upload-single","upload-single-delayed","download")
            assert (code==0)==expected,(scenario,code,err.decode())
            if scenario in ("upload-failure","upload-interrupted"):
                assert not any(e[0]=="abort" for e in events),events
                assert not any(e[0]=="complete" for e in events),events
                assert sorted(e[2] for e in events if e[0]=="put-start")==sorted(e[2] for e in events if e[0]=="put-end"),events
                assert list((root/"cache"/"syq"/"s3").glob("*.json"))
            if scenario.startswith("upload-single"):
                assert not any(e[0] in ("create","complete","abort") for e in events),events
                assert any(e[0]=="put-end" for e in events),events
            if scenario in ("upload-delayed", "upload-single-delayed"):
                expected_parts=[1,2,3] if scenario=="upload-delayed" else [0]
                assert sorted(e[2] for e in events if e[0]=="put-end")==expected_parts,events
                assert not any(e[0]=="abort" for e in events),events
                if scenario=="upload-delayed": assert sum(e[0]=="complete" for e in events)==1,events
            if scenario=="download": assert destination.read_bytes()==b"hello world"
            if scenario=="download-truncated": assert not destination.exists()
            assert not list(root.glob(".syq-s3-*.partial")),list(root.iterdir())
            if expected: assert not list((root/"cache"/"syq"/"s3").glob("*.json"))
            print(scenario,"passed",flush=True)
finally:
    server.shutdown();server.server_close();thread.join(timeout=5)
