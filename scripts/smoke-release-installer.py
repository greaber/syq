#!/usr/bin/env python3
"""Install the actual release over loopback HTTPS, then copy disposable data."""
import functools
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading


def smoke(dist):
    dist = Path(dist).resolve()
    manifest = json.loads((dist / "syq-release-manifest.json").read_text())
    with tempfile.TemporaryDirectory(prefix="syq-release-install.") as directory:
        work = Path(directory)
        cert, key = work / "cert.pem", work / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(dist))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        environment = {**os.environ, "XDG_CONFIG_HOME": str(work / "config"),
                       "SYQ_INSTALL_BASE_URL": f"https://127.0.0.1:{server.server_port}",
                       "CURL_CA_BUNDLE": str(cert), "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        try:
            subprocess.run(["sh", str(dist / "install.sh"), "--bin-dir", str(work / "bin")],
                           env=environment, check=True, timeout=60)
            binary = str(work / "bin" / "syq")
            for option, expected in [("--version", "syq " + manifest["version"]),
                                     ("--build-identity", manifest["tag"])]:
                actual = subprocess.check_output([binary, option], env=environment, text=True, timeout=10).strip()
                if actual != expected:
                    raise ValueError(f"installed {option}: {actual!r}, expected {expected!r}")
            source = work / "source"
            source.write_bytes(b"release installer smoke test\n")
            subprocess.run([binary, "cp", str(source), "--into", str(work / "destination")],
                           env=environment, check=True, timeout=30)
            if (work / "destination" / "source").read_bytes() != source.read_bytes():
                raise ValueError("installed binary produced different copy bytes")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print(f"Release installer and installed binary passed for {manifest['tag']}.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} DIST_DIR")
    smoke(sys.argv[1])
