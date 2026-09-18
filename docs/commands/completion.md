# syq completion

Print a shell completion adapter or manage learned endpoint suggestions. See
[shell setup](../install.md#shell-completion) for where to put the adapter.
The cache stores endpoint suggestions, not paths, credentials, or transfer history;
it is safe to clear. Every public nested command and its options follow.

<!-- CLI: completion -->
```text
syq completion <COMMAND>
```

| Command | Purpose |
|---|---|
| [`completion bash`](#syq-completion-bash) | Print the Bash completion adapter |
| [`completion zsh`](#syq-completion-zsh) | Print the Zsh completion adapter |
| [`completion fish`](#syq-completion-fish) | Print the fish completion adapter |
| [`completion cache`](#syq-completion-cache) | Inspect or clear cached endpoint suggestions |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq completion bash

Print the Bash adapter to stdout. Load it with `eval "$(syq completion bash)"`.

<!-- CLI: completion bash -->
```text
syq completion bash
```

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq completion zsh

Print the Zsh adapter to stdout. After initializing `compinit`, load it with `source <(syq completion zsh)`.

<!-- CLI: completion zsh -->
```text
syq completion zsh
```

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq completion fish

Print the fish adapter to stdout. Load it with `syq completion fish | source`.

<!-- CLI: completion fish -->
```text
syq completion fish
```

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq completion cache

Inspect or remove cached SSH endpoint suggestions. Clearing suggestions does not close connections.

<!-- CLI: completion cache -->
```text
syq completion cache <COMMAND>
```

| Command | Purpose |
|---|---|
| [`completion cache list`](#syq-completion-cache-list) | List learned endpoint suggestions, most recently used first |
| [`completion cache forget`](#syq-completion-cache-forget) | Forget one exact native endpoint spelling |
| [`completion cache clear`](#syq-completion-cache-clear) | Remove all learned endpoint suggestions |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq completion cache list

List learned endpoint spellings, most recently used first.

<!-- CLI: completion cache list -->
```text
syq completion cache list
```

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq completion cache forget

`ENDPOINT` is the exact native spelling to forget, such as `alice@server:2222`.

<!-- CLI: completion cache forget -->
```text
syq completion cache forget <ENDPOINT>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ENDPOINT>` | Endpoint to forget: [USER@]HOST[:PORT], e.g. alice@nas:2222 |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq completion cache clear

Remove all learned endpoint suggestions. Successful connections can add new suggestions later.

<!-- CLI: completion cache clear -->
```text
syq completion cache clear
```

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

