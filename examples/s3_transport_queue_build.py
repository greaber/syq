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
needle = 'let (send, mut recv) = mpsc::channel::<Message>(64);'
replacement = '''static CAPACITY: OnceLock<usize> = OnceLock::new();
            let capacity = *CAPACITY.get_or_init(|| {
                std::env::var("SYQ_SPIKE_QUEUE").unwrap().parse::<usize>().unwrap()
            });
            let (send, mut recv) = mpsc::channel::<Message>(capacity);'''
assert original.count(needle) == 1
modified = original.replace(needle, replacement)
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
        'change': 'Writer queue capacity read once from SYQ_SPIKE_QUEUE; no other source changes',
    }, indent=2))
finally:
    assert subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip() == str(root)
    writer.write_text(original)
print('Built experimental client; production writer restored.', flush=True)
