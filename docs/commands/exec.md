# syq exec

Request a command on a connected receiving machine. Every command needs approval
on that machine, even when copies are automatically approved. See
[Run commands on your receiving machine](../exec.md) for setup and cancellation.

```sh
syq exec --on @laptop --cwd work/project -- cargo test
```

`--on` is required. Put `--` before the program and its literal arguments; request
`sh -c` explicitly for shell syntax. The program inherits the receiving service's
environment and has closed stdin. It runs with the receiving user's permissions;
receiving roots and copy limits do not confine it.

Output streams back on stdout and stderr. Syq returns the program's exit code
(or `128 + signal`), and reports setup or connection failures as nonzero.
A lost connection cancels the command's process group, but detached processes
can survive. Completed effects are not rolled back or retried. All options follow.

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

