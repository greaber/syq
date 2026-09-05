#!/usr/bin/env python3
"""Reproducible, local-only completion mini-fuzzer (Python standard library).

Run after `cargo build --bin syq`:
  python3 scripts/stress-completion.py --syq target/debug/syq --cases 1000 --seed 1

Checks expected candidates for every public command, source bases, selector
kinds, parser conflicts, source ordering, and symlink policy, then mutates shell
text. Exercises raw Bash requests, tokenized Bash/Zsh/fish requests, and repeated
calls to the generated Bash adapter. Every child has a process-group deadline.
Failures print the seed, case, and exact byte inputs for reproduction. This
checks the Bash function directly; it does not drive an interactive Readline
session or exercise the Zsh/fish shell adapters or remote connections.
"""

import argparse
import os
from pathlib import Path
import random
import shutil
import signal
import subprocess
import tempfile
import time


BASH = r'''
eval "$("$SYQ" completion bash)" || exit
COMP_LINE=$1
COMP_POINT=${#COMP_LINE}
COMP_WORDS=(syq "$2")
COMP_CWORD=1
for ((tab=0; tab<3; tab++)); do
    _syq_complete
    for candidate in "${COMPREPLY[@]}"; do
        printf '%s\0' "$candidate"
    done
    printf '\0'
done
'''


def run(argv, env, cwd):
    child = subprocess.Popen(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    try:
        stdout, stderr = child.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        stdout, stderr = child.communicate()
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError(f'process group {child.pid} survived timeout cleanup')
        raise AssertionError(f"timed out: {argv!r}; stderr={stderr!r}") from None
    assert child.returncode == 0, (argv, child.returncode, stderr)
    assert not stderr, (argv, stderr)
    return stdout


def records(data, tagged=True):
    assert not data or data.endswith(b'\0'), data
    result = data.split(b'\0')[:-1]
    if tagged:
        assert all(record[:1] in (b'f', b'p') for record in result), data
        result = [record[1:] for record in result]
    assert len(result) == len(set(result)), result
    return result


def quote(word):
    return b"'" + word.replace(b"'", b"'\\''") + b"'"


def semantic_cases():
    """Expected values come from fixture meaning, not another completion path."""
    for command in (b'cp', b'rm', b'map'):
        for base in ([b'--cwd', b'base'], [b'-C', b'base'], [b'--root', b'base'],
                     [b'--cwd=base'], [b'--root=base'], [b'-Cbase'], [b'-C=base']):
            yield [b'syq', command] + base + [b'in'], [b'inner-dir/', b'inside.txt']
        yield [b'syq', command, b'-Cba'], [b'-Cbase/']
        for selector in (b'--src-dir', b'--src-dirs', b'--srcs-in'):
            yield [b'syq', command, b'--cwd', b'base', selector, b'in'], [b'inner-dir/']
        yield [b'syq', command, b'--root', b'base', b'inner-dir//'], [b'inner-dir//nested.txt']
        yield [b'syq', command, b'--root', b'base', b'../'], []
        yield [b'syq', command, b'link/'], []
        yield [b'syq', command, b'--follow-src', b'link/in'], [b'link/inner-dir/', b'link/inside.txt']
    yield [b'syq', b'rm', b'--results', b'ba'], [b'base/']
    yield [b'syq', b'persist', b'status', b'--pscope=ba'], [b'--pscope=base/']
    yield [b'syq', b'receiver', b'e'], [b'enroll']
    yield [b'syq', b'receiver', b'enroll', b'--v'], [b'--via']
    yield [b'syq', b'help', b'receiver', b'e'], [b'enroll']
    yield [b'syq', b'completion', b'cache', b'f'], [b'forget']
    yield [b'syq', b'cp', b'--preserve', b'permissions,ow'], [b'permissions,ownership']
    yield [b'syq', b'rsync', b'--syq-ignore', b'--', b'--d'], [b'--delete', b'--delete-excluded', b'--dry-run']
    yield [b'syq', b'cp', b'alpha file', b'--into', b'base', b'--as'], []
    yield [b'syq', b'cp', b'--cwd', b'base', b'--root'], []
    yield [b'syq', b'cp', b'--mapping', b'manifest', b'a'], []
    yield [b'syq', b'map', b'--srcs-in', b'base', b'a'], []
    for destination in (b'--to', b'--into', b'--into-new', b'--into-existing',
                        b'--as', b'--as-new', b'--as-existing'):
        for placement in ([destination, b'target'], [destination + b'=target']):
            for fragment in (b'', b'--src', b'--cwd', b'--root', b'--mapping'):
                yield [b'syq', b'cp', b'alpha file'] + placement + [fragment], []


def cases(rng, count):
    # Include all command routes and state transitions before random mutation.
    for words, expected in semantic_cases():
        yield b' '.join(quote(word) for word in words), words[-1], words, expected
    # The original parser fails at the literal `--`.
    for fragment in [b'--', b'--co', b'--help', b'-h', b'help', b'--version',
                     b'', b'-', b'--coordinate-at=', b"'", b'"', b'\\']:
        yield b'syq ' + fragment, fragment, None, None
        yield b'syq cp ' + fragment, fragment, None, None
    for line, fragment in [(b"syq cp 'alpha", b'alpha'),
                           (b'syq cp "alpha', b'alpha'),
                           (b'syq cp alpha\\ ', b'alpha '),
                           (b'FOO=x syq --', b'--'),
                           (b'printf x | syq --', b'--'),
                           (b'syq cp --coordinate-at=sr', b'sr')]:
        yield line, fragment, None, None
    atoms = [b'-', b'--', b'help', b'co', b'=', b':', b'@', b"'", b'"',
             b'\\', b' ', b'\t', b'\n', b';', b'|', b'&', b'(', b')',
             b'$(touch injected)', b'`touch injected`', 'é'.encode(), b'\xff']
    for _ in range(count):
        fragment = b''.join(rng.choice(atoms) for _ in range(rng.randrange(9)))
        # Only local filenames or top-level commands: no generated request can
        # choose a remote endpoint or operate on the user's filesystem.
        words = rng.choice([[b'syq'], [b'syq', b'cp', b'--'],
                            [b'syq', b'rm', b'--'], [b'syq', b'map', b'--']])
        words = words + [fragment]
        yield b' '.join(quote(word) for word in words), fragment, words, None
        # Also stop midway through shell syntax, as a person typing would.
        line = b'syq cp -- ' + fragment
        cut = rng.randrange(len(line) + 1)
        yield line[:cut], fragment, None, None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--syq', type=Path, default=Path('target/debug/syq'))
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--cases', type=int, default=128,
                        help='generated cases (each also gets a truncated-line variant)')
    args = parser.parse_args()
    if args.cases < 0:
        parser.error('--cases must be nonnegative')
    syq = args.syq.resolve(strict=True)
    bash = shutil.which('bash')
    if bash is None:
        parser.error('bash is required')
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='syq-completion-stress-') as directory:
        root = Path(directory)
        (root / 'bin').mkdir()
        # Pin one executable for the whole run: a concurrent cargo build may
        # replace the supplied path between requests.
        snapshot = root / 'bin' / 'syq'
        shutil.copy2(syq, snapshot)
        syq = snapshot
        # C locale deliberately makes Bash cursor slicing operate on raw bytes.
        env = dict(os.environ, HOME=str(root / 'home'), LC_ALL='C',
                   XDG_CACHE_HOME=str(root / 'cache'), XDG_CONFIG_HOME=str(root / 'config'),
                   XDG_RUNTIME_DIR=str(root / 'runtime'), SYQ=str(syq),
                   SYQ_COMPLETION_DEBUG='1', PATH=f'{root / "bin"}:/usr/bin:/bin')
        env.pop('BASH_ENV', None)
        env.pop('ENV', None)
        for name in ['alpha file', '--help', "quote'file", 'éclair']:
            (root / name).write_text('fixture')
        (root / 'alpine').mkdir()
        (root / 'base' / 'inner-dir').mkdir(parents=True)
        (root / 'base' / 'inside.txt').write_text('inside')
        (root / 'base' / 'inner-dir' / 'nested.txt').write_text('nested')
        (root / 'link').symlink_to('base', target_is_directory=True)
        backend = [os.fsencode(syq), b'completion']
        for number, (line, fragment, words, semantic_expected) in enumerate(cases(random.Random(args.seed), args.cases)):
            try:
                data = run(backend + [b'__complete-bash', fragment, b'--', line], env, root)
                values = records(data)
                if semantic_expected is not None:
                    assert sorted(values) == sorted(semantic_expected), (values, semantic_expected)
                if line == b'syq --':
                    assert b'--help' in values and b'--version' in values, values
                if line == b'syq cp --co':
                    assert b'--coordinate-at' in values, values
                if words is not None:
                    for shell in (b'bash', b'zsh', b'fish'):
                        tokenized = run(backend + [b'__complete', shell,
                                        str(len(words) - 1).encode(), b'--'] + words, env, root)
                        assert records(tokenized, shell != b'fish') == values, (shell, tokenized, data)
                actual = run([os.fsencode(bash), b'--noprofile', b'--norc', b'-c',
                              BASH.encode(), b'bash', line, fragment], env, root)
                expected = (b''.join(value + b'\0' for value in values) + b'\0') * 3
                assert actual == expected, (actual, expected)
                assert not (root / 'injected').exists(), 'shell text was executed'
            except (AssertionError, OSError):
                print(f'FAIL seed={args.seed} case={number} line={line!r} fragment={fragment!r}', flush=True)
                raise
            if number % 100 == 0:
                print(f'seed={args.seed}: {number + 1} cases passed', flush=True)
        print(f'PASS seed={args.seed}: {number + 1} cases, three Bash calls each, '
              f'{time.monotonic() - started:.1f}s', flush=True)


if __name__ == '__main__':
    main()
