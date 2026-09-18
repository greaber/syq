"""Build a disposable HTTP read-buffer experiment without changing registry sources."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path.cwd()
assert subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip() == str(root)
assert '.worktrees' in root.parts, 'run in the task worktree'
lock = root / 'Cargo.lock'
assert not subprocess.check_output(['git', 'status', '--porcelain', '--', str(lock)], text=True)
original_lock = lock.read_bytes()
metadata = json.loads(subprocess.check_output(
    ['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], text=True))
crate = next(package for package in metadata['packages'] if package['name'] == 'aws-smithy-http-client')
source = Path(crate['manifest_path']).parent
run_name = os.environ.get('SYQ_HTTP_BUILD_RUN', 'http-read-build')
assert Path(run_name).name == run_name
run = root / 'target' / run_name
run.mkdir(exist_ok=True)
destination = run / 'aws-smithy-http-client'
assert not destination.exists(), 'choose a fresh build directory'
shutil.copytree(source, destination)
client = destination / 'src/client.rs'
text = client.read_text()
needle = 'let mut builder = hyper_util::client::legacy::Builder::new(TokioExecutor::new());'
assert text.count(needle) == 1
text = text.replace(needle, needle + '''
    if let Ok(value) = std::env::var("SYQ_SPIKE_HTTP_READ_MAX") {
        let limit = value.parse::<usize>().expect("invalid HTTP read cap");
        if limit > 0 { builder.http1_max_buf_size(limit); }
    }''')
client.write_text(text)
try:
    subprocess.run(['cargo', 'build', '--offline', '--release', '--example', 's3_transport_spike',
                    '--config', 'patch.crates-io.aws-smithy-http-client.path="' + str(destination) + '"'],
                   check=True)
    shutil.copy2(root / 'target/release/examples/s3_transport_spike', run / 'client')
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    sources = [root / 'examples/s3_transport_spike.rs', root / 'examples/support/s3_stage_metrics.rs',
               root / 'src/s3/writer.rs', Path(__file__).resolve()]
    (run / 'provenance.json').write_text(json.dumps({
        'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'crate_version': crate['version'], 'original_client_sha256': digest(source / 'src/client.rs'),
        'experimental_client_sha256': digest(client), 'binary_sha256': digest(run / 'client'),
        'source_sha256': {str(path.relative_to(root)): digest(path) for path in sources},
        'profile_environment': {key: value for key, value in os.environ.items() if key.startswith('CARGO_PROFILE_')},
        'change': 'Optional Hyper HTTP/1 max buffer size; production queue8 writer unchanged',
    }, indent=2))
finally:
    assert subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip() == str(root)
    lock.write_bytes(original_lock)
print('Built experimental client; Cargo.lock restored.', flush=True)
