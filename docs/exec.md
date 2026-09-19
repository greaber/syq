# Run commands on your receiving machine

From a server shell, ask your Mac or Linux desktop to run a command:

```sh
syq exec --on @laptop --cwd work/project -- cargo test
syq exec --on @laptop --cwd work/project -- open report.html
```

The second command uses macOS's `open` program to open the report. Replace
it with any program installed on your receiving machine.

If you have already set up [receiving files](receive.md), you can request
commands through the same connection. Otherwise, run `syq persist connect server`
on your desktop first. Your desktop needs no SSH server or incoming network
port, and you can make requests from any shell on the server, including an
existing tmux session.

Replace `@laptop` with your desktop's receiving name. You can find it by running
`syq persist destinations list` on the server or `syq persist receive status`
on your desktop. Use `--on @laptop`; the desktop must be connected.

## Approve each command locally

Each command waits for approval on the receiving machine. Review the program,
arguments, requesting server, and working directory. Desktop notifications may
truncate long commands; inspect the complete request from a local terminal:

```sh
syq persist receive pending
syq persist receive approve REQUEST_ID
syq persist receive deny REQUEST_ID
```

Every command requires approval, even if copies are approved automatically.
If the desktop prompt is missing, use the terminal commands above. Requests
expire after five minutes.

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

## Output, completion and cancellation

Stdout and stderr stream back to your terminal, and syq returns the command's
exit code. A lost connection is an error; the command is not retried automatically.

Interrupting the request or stopping receiving stops the command. Completed
changes to files are not rolled back. See [Execution details](commands/exec.md#execution-details)
for cancellation behavior and limits.

See [`syq exec`](commands/exec.md) for all options, or
[Guide and examples](python-guide.md) for Python calls.
