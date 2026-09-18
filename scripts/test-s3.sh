#!/usr/bin/env bash
# Disposable, loopback-only S3 integration tests. No cloud credentials needed.
set -euo pipefail
cd "$(dirname "$0")/.."
_syq_s3_binary=${1:-target/debug/syq}
if [[ $# == 0 ]]; then cargo build --locked; fi
_syq_s3_image=minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e
_syq_s3_container=
cleanup() {
  if [[ -n $_syq_s3_container ]]; then docker rm -f "$_syq_s3_container" >/dev/null; fi
}
trap cleanup EXIT
export AWS_ACCESS_KEY_ID=syq-test-user AWS_SECRET_ACCESS_KEY=syq-test-password
export AWS_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true SYQ_TEST_BUCKET=syq-test
unset AWS_SESSION_TOKEN AWS_PROFILE SYQ_TEST_HEADERS
_syq_s3_container=$(docker run --detach --rm --tmpfs /data:rw,size=2g \
  -p 127.0.0.1::9000 -e MINIO_ROOT_USER="$AWS_ACCESS_KEY_ID" \
  -e MINIO_ROOT_PASSWORD="$AWS_SECRET_ACCESS_KEY" "$_syq_s3_image" server /data)
_syq_s3_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}' "$_syq_s3_container")
export AWS_ENDPOINT_URL_S3=http://127.0.0.1:$_syq_s3_port
python3 - "$_syq_s3_binary" <<'PY'
import importlib.util, os, time, urllib.request
endpoint = os.environ['AWS_ENDPOINT_URL_S3']
deadline = time.monotonic() + 60
last = 'not checked'
while time.monotonic() < deadline:
    try:
        with urllib.request.urlopen(endpoint + '/minio/health/ready', timeout=2) as response:
            if response.status == 200: break
            last = f'HTTP {response.status}'
    except OSError as error: last = str(error)
    print(f'Waiting for MinIO: {last}', flush=True)
    time.sleep(2)
else:
    raise SystemExit(f'MinIO readiness deadline exceeded; last state: {last}')
spec = importlib.util.spec_from_file_location('checks', 'tests/object-storage/check.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.request('PUT')
PY
python3 tests/object-storage/check.py "$_syq_s3_binary"
python3 tests/object-storage/selection.py "$_syq_s3_binary"

python3 tests/object-storage/remove.py "$_syq_s3_binary"
python3 tests/object-storage/prune.py "$_syq_s3_binary"

python3 tests/object-storage/fast.py "$_syq_s3_binary"
python3 tests/object-storage/fast-provider.py "$_syq_s3_binary"

python3 tests/object-storage/server-copy.py "$_syq_s3_binary"
