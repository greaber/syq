<a id="run-commands-on-your-receiving-machine"></a>

# syq exec

Run a command on a connected receiving machine, with approval on that machine:

```sh
syq exec --on @laptop --cwd work/project -- cargo test
```

Put `--` before the program and its arguments; use `sh -c` for shell syntax.
The program runs with the receiving user's permissions. See
[Run commands on your laptop](../receive.md#run-commands-on-your-laptop)
for setup and examples.

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

## Approve each command locally

Every command requires approval on the receiving machine, even if copies are
approved automatically. Review the program, arguments, requesting server, and
working directory. If the desktop prompt is missing or truncated, inspect and
answer the request from a local terminal:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

Requests expire after five minutes. Commands run with your local user's
permissions; the receiving `--root` and copy limits do not contain them.
See [Commands on your laptop](../security.md#running-commands-on-your-laptop) for the
trust boundary.

## Arguments and working directories

Put `--` before the program. Everything after it is passed as a literal
argument, including strings starting with `--`. There is no implicit shell
expansion on the receiving machine. To use shell syntax, request a shell:

```sh
syq exec --on @laptop --cwd work/project -- sh -c 'cargo build && ./target/debug/demo'
```

`--cwd DIR` (or `-C DIR`) is relative to the directory selected by `persist receive on
--cwd` or `persist receive on --root`. Its default is that directory. Absolute paths and
`..` can select elsewhere. The directory must exist. Syq does not expand `~`
on the receiving machine; use a relative path or an absolute path instead.

The command inherits the receiving service's local environment, including
`PATH` and its desktop session. It does not inherit the server's environment.
Restart receiving from a terminal in the desired desktop session when those
values change. Stdin is closed and there is no interactive terminal.

## Output, completion and cancellation

Stdout and stderr stream back to your terminal, and syq returns the command's
exit code. A lost connection is an error; the command is not retried automatically.
Completed changes to files are not rolled back.

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
