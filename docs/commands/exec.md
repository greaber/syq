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
