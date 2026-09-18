"""Build an isolated queue-depth experiment, restoring production source afterward."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path.cwd()
assert subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip() == str(root)
assert '.worktrees' in root.parts, 'run in the task worktree'
writer = root / 'src/s3/writer.rs'
assert not subprocess.check_output(['git', 'status', '--porcelain', '--', str(writer)], text=True)
original = writer.read_text()
needle = 'let (send, mut recv) = mpsc::channel::<Message>(8);'
replacement = '''static CAPACITY: OnceLock<usize> = OnceLock::new();
            let capacity = *CAPACITY.get_or_init(|| {
                std::env::var("SYQ_SPIKE_QUEUE").unwrap().parse::<usize>().unwrap()
            });
            let (send, mut recv) = mpsc::channel::<Message>(capacity);'''
assert original.count(needle) == 1
modified = original.replace(needle, replacement)
# Only the explicit diagnostic environment can alter direct-I/O eligibility.
needle = 'if size >= 256 * 1024 * 1024 {'
assert modified.count(needle) == 1
modified = modified.replace(needle, 'if size >= std::env::var("SYQ_SPIKE_DIRECT_MIN").ok().map(|s| s.parse::<u64>().unwrap()).unwrap_or(256 * 1024 * 1024) {')
# Probe the otherwise unchanged production writer only in the disposable build.
for needle, replacement in [
    ('let result = tokio::task::spawn_blocking(move || {',
     'let submitted = super::diagnostics::start();\n                    let result = tokio::task::spawn_blocking(move || {\n                        super::diagnostics::elapsed(submitted, "dispatch", 0);'),
    ('self.sender()\n            .send(Message::Write(bytes, offset))',
     'let started = super::diagnostics::start();\n        let result = self.sender()\n            .send(Message::Write(bytes, offset))'),
    ('self.sender()\n            .send(Message::WriteBatch(bytes, offset))',
     'let started = super::diagnostics::start();\n        let result = self.sender()\n            .send(Message::WriteBatch(bytes, offset))'),
]:
    assert modified.count(needle) == 1
    modified = modified.replace(needle, replacement)
needle = '.context("S3 destination writer stopped")\n    }'
assert modified.count(needle) == 2
modified = modified.replace(needle, '.context("S3 destination writer stopped");\n        super::diagnostics::elapsed(started, "queue_send", 0);\n        result\n    }')
destination = root / 'target' / os.environ.get('SYQ_QUEUE_BUILD_RUN', 'transport-queue-build')
destination.mkdir(exist_ok=True)
(destination / 'writer.rs').write_text(modified)
try:
    writer.write_text(modified)
    subprocess.run(['cargo', 'build', '--locked', '--release', '--example', 's3_transport_spike'], check=True)
    shutil.copy2(root / 'target/release/examples/s3_transport_spike', destination / 'client')
    digest = lambda value: hashlib.sha256(value).hexdigest()
    (destination / 'provenance.json').write_text(json.dumps({
        'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'original_writer_sha256': digest(original.encode()),
        'experimental_writer_sha256': digest(modified.encode()),
        'binary_sha256': digest((destination / 'client').read_bytes()),
        'change': 'Writer queue capacity from SYQ_SPIKE_QUEUE; opt-in dispatch and queue-send probes; diagnostic direct-I/O size threshold',
        'source_sha256': {str(p.relative_to(root)): digest(p.read_bytes()) for p in [root / 'examples/s3_transport_spike.rs', root / 'examples/support/s3_stage_metrics.rs', Path(__file__).resolve()]},
        'profile_environment': {k: v for k, v in os.environ.items() if k.startswith('CARGO_PROFILE_')},
    }, indent=2))
finally:
    assert subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip() == str(root)
    writer.write_text(original)
print('Built experimental client; production writer restored.', flush=True)
