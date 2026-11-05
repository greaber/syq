<a id="run-commands-on-your-receiving-machine"></a>

# syq exec

Run a command on your laptop from a server, with approval on the laptop:

```sh
syq exec --on @laptop --cwd work/project -- cargo test
```

See [Run commands on your laptop](../receive.md#run-commands-on-your-laptop)
for setup.

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

Every command needs approval on the laptop, even when copies are approved
automatically. If the desktop prompt is missing or truncated, answer from a
terminal on the laptop:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

A request expires after five minutes. Approved commands run with your full
user permissions: the receiving `--root` and copy limits do not restrict them.
See [Commands on your laptop](../security.md#running-commands-on-your-laptop).

## Arguments and working directories

Put `--` before the program. Everything after it is passed as given, with no
shell, so run a shell when you need shell syntax:

```sh
syq exec --on @laptop --cwd work/project -- sh -c 'cargo build && ./target/debug/demo'
```

The command starts in the receiving profile's directory, which
`syq persist receive status` shows; a relative `--cwd` starts there, and `~` is
not expanded. The command gets the environment of the receiving service on the
laptop, including its `PATH`, not the server's; to change it, restart
receiving from a terminal in the session you want. It has no terminal and no
standard input.

## Output, completion and cancellation

Output streams back to your terminal, and `syq exec` exits with the command's
exit code, or `128 + signal` if a signal killed it. Setup failures and a lost
connection also exit nonzero.

Interrupting the request, stopping or changing receiving, or losing the
connection kills the command's process group at once, without cleanup
handlers. When the command exits, syq also stops anything left in its process
group. Detached processes and applications started with macOS `open` can keep
running.

## Execution details

A request allows up to 256 arguments (16 KiB in total). Each server connection
allows one pending approval and eight running commands.
