<a id="run-commands-on-your-receiving-machine"></a>

# syq exec

Run a command on a connected receiving machine, with approval on that machine:

```sh
syq exec --on @laptop --cwd work/project -- cargo test
```

See [Run commands on your laptop](../receive.md#run-commands-on-your-laptop)
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
| `--on <@NAME>` | Receiving name of the machine to run on; it must be connected to this server now, and syq never uses SSH instead |
| `-C, --cwd <DIR>` | Working directory on that machine, relative to its receiving profile's starting directory<br><br>[default: .] |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## Approve each command locally

Every command needs approval on the receiving machine, even when copies are
approved automatically. Review the program, arguments, requesting server, and
working directory. If the desktop prompt is missing or truncated, answer the
request from a local terminal:

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
argument, including strings starting with `--`, and no shell runs on the
receiving machine. To use shell syntax, run a shell:

```sh
syq exec --on @laptop --cwd work/project -- sh -c 'cargo build && ./target/debug/demo'
```

`--cwd DIR` (or `-C DIR`) is relative to the receiving profile's starting
directory, which `persist receive status` shows, and defaults to it. Absolute
paths and `..` can select elsewhere, but `~` is not expanded. The directory
must exist.

The command inherits the receiving service's environment, including `PATH` and
its desktop session, not the server's. To change them, restart receiving from a
terminal in the session you want. Stdin is closed and there is no terminal.

## Output, completion and cancellation

Stdout and stderr stream back to your terminal, and syq returns the command's
exit code, or `128 + signal` if a signal killed it. Setup failures, and losing
the connection before the status arrives, also exit nonzero. Commands are not
retried, and completed file changes are not rolled back.

Interrupting the request, stopping or changing receiving, or losing the
connection kills the command's process group without running its cleanup
handlers. Processes left in that group are also stopped when the program exits,
but detached processes and applications started through macOS `open` can
survive.

## Execution details

A request allows up to 256 arguments (16 KiB in total) and a 4096-byte working
directory path. Each server connection allows one pending approval and eight
running commands.
