# Run commands on your receiving machine

From a server shell, ask your Mac or Linux desktop to run a command:

```sh
syq exec --on @laptop --cwd work/project -- cargo test
syq exec --on @laptop --cwd work/project -- open report.html
```

The second command uses macOS's `open` program to display an artifact. Any
program installed on the receiving machine can be requested, including a
native application or a version of syq you have just built there.

Commands use the same background connection as [return copies](receive.md).
Turn on persistence on the receiving machine and connect to the server with
syq. No SSH server or incoming network port is needed on the receiving machine.
Requests work from independent server shells, including existing tmux sessions.

`--on` selects a receiving name. Both `laptop` and `@laptop` require a live
return connection; neither falls back to DNS or an SSH connection. If the server
command is a different build, it automatically invokes the matching helper
registered by the receiving machine before requesting approval. Names and
options complete from local information; completion does not contact the
receiving machine or request approval.

## Approve each command locally

Each command waits for approval on the receiving machine. Its desktop prompt
shows the server account, program and literal arguments, working directory,
and the permission being granted. Desktop notifications may truncate long
commands and hide trailing arguments. Use `syq persist receive pending` on the receiving
machine to inspect the complete request before approving a command whose full
text is not visible. You can inspect and decide requests from a terminal there:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

Command requests are available whenever receiving is enabled. Every command
requires its own decision, even with `syq persist receive on --approve always` for copies.
Approving a copy does not approve commands. A missing or dismissed desktop
prompt never grants permission; use the local terminal commands. Pending
requests expire after five minutes and are cancelled when the requester
disconnects or receiving restarts or stops.

An approved command runs with your local user's permissions, including access
to files and credentials. **The receiving `--root` and copy limits do not
contain commands.** Build tools and scripts can execute code from their input
files; approving a displayed command does not establish that those files are
safe. Commands have a separate approval type in `persist receive pending --json`, with
`kind: "command"`, `argv`, `cwd`, and `permission` fields. Argument and directory
strings in that summary are escaped for display.

Older clients that only understand copies cannot approve command requests.
Use the matching new binary to list and approve them; old clients omit command
requests from their pending list. They can still list and approve copies from
other server connections, and their stop request still works.

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

A request supports at most 256 arguments, including the program, with at most
16 KiB of argument bytes and a working-directory path of at most 4096 bytes.
Each server connection permits one pending approval and eight active commands.
Active commands do not prevent a new approval or an ordinary copy.

## Output, completion and cancellation

Stdout and stderr stream back separately without text conversion. Syq returns
the command's exit code; when the command is killed by a signal it reports the
signal and returns `128 + signal`. A setup error or connection failure is a
nonzero result. A connection that closes before delivering the exit status is
an error even if some output arrived successfully.

Interrupting the requesting syq process, losing the connection, changing
receiving settings, `persist receive off`, or `persist off` cancels execution. Syq kills
the command's process group with `SIGKILL` and reaps its leader. It also kills
remaining processes in that group when the foreground program exits, without
giving them time to run cleanup handlers. A program that deliberately creates a
separate process session, or an application launched through macOS `open`, can
outlive that group. Syq does not manage detached jobs.

A command may already have changed files when interrupted. It is never retried
automatically after a lost connection. Inspect the outcome before requesting
it again. Commands do not produce copy receipts or copy automation records.

Python callers can use the SDK's existing raw process interface with their
chosen executable:

```python
import syq

result = syq.run(
    ["exec", "--on", "@laptop", "--cwd", "work/project", "--", "cargo", "test"],
    executable="/path/to/syq",
    timeout=600,
)
print(result.stdout.decode())
```

The raw SDK call captures byte output and raises on a nonzero exit by default.
The async client's `run` method accepts the same command arguments. For live
terminal output, invoke the CLI directly or use a subprocess with inherited
stdout and stderr.
