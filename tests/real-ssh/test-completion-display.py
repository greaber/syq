#!/usr/bin/env python3
"""Exercise completion display and insertion in a disposable interactive shell."""
import argparse
import os
from pathlib import Path
import pty
import re
import select
import signal
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--syq', required=True)
    parser.add_argument('--shell', choices=['bash', 'zsh', 'fish'], default='bash')
    args = parser.parse_args()
    binary = Path(args.syq).resolve()
    with tempfile.TemporaryDirectory(prefix='syq-completion-display-') as temporary:
        root = Path(temporary)
        (root / 'alpha').write_bytes(b'x' * 2048)
        (root / 'alpine').mkdir()
        pid, terminal = pty.fork()
        if pid == 0:
            os.chdir(root)
            os.environ['PATH'] = str(binary.parent) + os.pathsep + os.environ['PATH']
            os.environ['TERM'] = 'xterm'
            os.environ['HOME'] = temporary
            os.environ['XDG_CONFIG_HOME'] = str(root / 'config')
            os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
            os.environ['SYQ_NO_UPDATE_CHECK'] = '1'
            options = {'bash': ['--noprofile', '--norc', '-i'], 'zsh': ['-f', '-i'], 'fish': ['--no-config', '-i']}
            os.execvp(args.shell, [args.shell, *options[args.shell]])
        transcript = bytearray()

        def receive(duration=0.5):
            deadline = time.monotonic() + duration
            output = bytearray()
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], min(0.05, max(0, deadline - time.monotonic())))[0]:
                    try:
                        data = os.read(terminal, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output.extend(data)
            transcript.extend(output)
            return bytes(output)

        def send(data):
            os.write(terminal, data)
            return receive()

        try:
            receive()
            setup = {
                'bash': b'''PS1='PROMPT> '; eval "$(syq completion bash)"\n''',
                'zsh': b'''PROMPT='PROMPT> '; autoload -Uz compinit; compinit -D; source <(syq completion zsh)\n''',
                'fish': b'''function fish_prompt; printf 'PROMPT> '; end; syq completion fish | source\n''',
            }
            output = send(setup[args.shell])
            deadline = time.monotonic() + 15
            while b'PROMPT> ' not in output:
                if time.monotonic() >= deadline:
                    raise AssertionError(f'{args.shell} startup timed out: {bytes(transcript)!r}')
                output += receive()
            print(f'{args.shell}: checking the expanded listing', flush=True)
            output = send(b'syq cp al\t') + send(b'\t') + send(b'\t')
            plain = re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', output)
            assert b'2.0 KiB' in plain and b'UTC' in plain, output
            # Clear the menu/line, then test insertion independently. Running
            # an echo-only function records the actual argument, not the display.
            send(b'\x03')
            definition = {
                'bash': b'''syq() { printf 'ARG=<%s>\\n' "$@"; }\n''',
                'zsh': b'''syq() { printf 'ARG=<%s>\\n' "$@"; }\n''',
                'fish': b'''function syq; printf 'ARG=<%s>\\n' $argv; end\n''',
            }
            send(definition[args.shell])
            send(b'syq cp alph\t')
            output = send(b'\n')
            assert b'ARG=<alpha>' in output, output
            assert b'KiB' not in output and b'UTC' not in output, output
            print(f'{args.shell}: detailed display and path-only insertion passed', flush=True)
        finally:
            # The PTY shell owns a separate process group, including its helpers.
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
            os.close(terminal)


if __name__ == '__main__':
    main()
