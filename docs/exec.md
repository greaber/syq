# Run commands on your receiving machine

From a server shell, ask your Mac or Linux desktop to run a command:

```sh
syq exec --on @laptop --cwd work/project -- cargo test
syq exec --on @laptop --cwd work/project -- open report.html
```

The second command uses macOS's `open` program to display an artifact. Any
program installed on the receiving machine can be requested, including a
native application or a version of syq you have just built there.

If you have already set up [receiving files](receive.md), you can request
commands through the same connection. Otherwise, run `syq persist connect server`
on your desktop first. Your desktop needs no SSH server or incoming network
port, and you can make requests from any shell on the server, including an
existing tmux session.

Replace `@laptop` with your desktop's receiving name. You can find it by running
`syq persist destinations list` on the server or `syq persist receive status`
on your desktop. The desktop must be connected: both `--on laptop` and
`--on @laptop` fail while it is offline.

## Approve each command locally

Each command waits for approval on the receiving machine. Review the program,
arguments, requesting server, and working directory. Desktop notifications may
truncate long commands; inspect the complete request from a local terminal:

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
safe.

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

Interrupting the request, losing the connection, changing receiving settings,
or stopping receiving cancels execution. Syq forcibly stops the command's
process group, including remaining children when the foreground program exits;
cleanup handlers do not run. Detached processes and applications launched
through macOS `open` can outlive the request. Syq does not manage detached jobs.

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
