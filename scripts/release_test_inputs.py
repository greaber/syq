"""Compare release test inputs, allowing only version and prose preparation."""
import hashlib
import re
import subprocess


def git(*args):
    return subprocess.check_output(['git', *args])


def version_neutral(path, data):
    # Only the root package version is ignored, never dependency versions or
    # other package/build metadata. Keep all other bytes for comparison.
    if path == 'Cargo.toml':
        section = re.search(rb'(?ms)^\[package\]\n.*?(?=^\[|\Z)', data)
    else:
        section = re.search(rb'(?ms)^\[\[package\]\]\nname = "syq"\n.*?(?=^\[\[package\]\]|\Z)', data)
        if section and re.search(rb'(?m)^source = ', section[0]):
            return data
    if not section:
        return data
    neutral, count = re.subn(rb'(?m)^version = "[0-9]+\.[0-9]+\.[0-9]+"$',
                             b'version = "RELEASE"', section[0])
    if count != 1:
        return data
    return data[:section.start()] + neutral + data[section.end():]


def prose(path):
    return (path in {'README.md', 'CHANGELOG.md', 'RELEASING.md', 'CONTRIBUTING.md', 'AGENTS.md'}
            or path.startswith('.github/release-notes/') and path.endswith('.md')
            or path.startswith('docs/') and path.endswith('.md') and path != 'docs/mappings.md')


def fingerprint(commit):
    result = hashlib.sha256()
    for record in git('ls-tree', '-rz', commit).split(b'\0'):
        if not record:
            continue
        metadata, raw_path = record.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        path = raw_path.decode()
        if mode == b'100644' and kind == b'blob' and prose(path):
            continue
        if path in ('Cargo.toml', 'Cargo.lock') and kind == b'blob':
            oid = hashlib.sha256(version_neutral(path, git('cat-file', 'blob', oid.decode()))).hexdigest().encode()
        result.update(mode + b' ' + kind + b' ' + oid + b'\t' + raw_path + b'\0')
    return result.hexdigest()


def candidates(commit):
    """Contiguous first-parent ancestors with the same tested inputs, newest first."""
    expected = fingerprint(commit)
    for ancestor in git('rev-list', '--first-parent', commit).decode().splitlines():
        if fingerprint(ancestor) != expected:
            break
        yield ancestor


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('commit')
    parser.add_argument('--equivalent-to')
    args = parser.parse_args()
    if args.equivalent_to:
        raise SystemExit(0 if fingerprint(args.commit) == fingerprint(args.equivalent_to) else 1)
    print('\n'.join(candidates(args.commit)))
