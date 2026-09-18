# syq completion

Generate shell completion and manage cached endpoint suggestions.
See [shell setup](../install.md#shell-completion) to enable completion.

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

**Help (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq completion bash

<!-- CLI: completion bash -->
```text
syq completion bash
```

<!-- /CLI -->

## syq completion zsh

<!-- CLI: completion zsh -->
```text
syq completion zsh
```

<!-- /CLI -->

## syq completion fish

<!-- CLI: completion fish -->
```text
syq completion fish
```

<!-- /CLI -->

## syq completion cache

<!-- CLI: completion cache -->
```text
syq completion cache <COMMAND>
```

| Command | Purpose |
|---|---|
| [`completion cache list`](#syq-completion-cache-list) | List learned endpoint suggestions, most recently used first |
| [`completion cache forget`](#syq-completion-cache-forget) | Forget one exact native endpoint spelling |
| [`completion cache clear`](#syq-completion-cache-clear) | Remove all learned endpoint suggestions |

<!-- /CLI -->

## syq completion cache list

<!-- CLI: completion cache list -->
```text
syq completion cache list
```

<!-- /CLI -->

## syq completion cache forget

<!-- CLI: completion cache forget -->
```text
syq completion cache forget <ENDPOINT>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ENDPOINT>` | Endpoint to forget: [USER@]HOST[:PORT], e.g. alice@nas:2222 |

<!-- /CLI -->

## syq completion cache clear

<!-- CLI: completion cache clear -->
```text
syq completion cache clear
```

<!-- /CLI -->
