# syq exec

Run a command on a connected receiving machine, with approval on that machine:

```sh
syq exec --on @laptop --cwd work/project -- cargo test
```

Put `--` before the program and its arguments; use `sh -c` for shell syntax.
The program runs with the receiving user's permissions. See
[Run commands on your receiving machine](../exec.md) for setup, output, and cancellation.

<!-- CLI: exec -->
```text
syq exec [OPTIONS] --on <@NAME> -- <PROGRAM>...
```

## Arguments

| Argument / option | Meaning |
|---|---|
| `<PROGRAM>...` | Program and literal arguments; use sh -c explicitly for shell syntax |

## Options

| Argument / option | Meaning |
|---|---|
| `--on <@NAME>` | Receiving name; requires a live return connection (never falls back to SSH) |
| `-C, --cwd <DIR>` | Working directory on that machine, relative to its receiving directory<br><br>[default: .] |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Execution details

Requests allow up to 256 arguments (16 KiB total) and a 4096-byte working-directory
path. Each server connection permits one pending approval and eight active
commands.

If the command is killed by a signal, syq returns `128 + signal`. Setup and
connection failures return nonzero; losing the exit status is an error.
Interrupting the request, stopping or changing receiving, or losing the
connection forcibly stops the command's process group. Cleanup handlers do not
run. Remaining children in that group are also stopped when the foreground
program exits. Detached processes and applications launched through macOS
`open` can survive this cleanup. Commands do not emit copy receipts or copy
automation records.
