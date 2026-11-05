# syq tuning-cache

Inspect how past filesystem copies chose their worker counts.
[Tuning history](../tuning.md#inspect-tuning-history) explains what is
recorded.

<!-- CLI: tuning-cache -->
```text
syq tuning-cache <COMMAND>
```

| Command | Purpose |
|---|---|
| [`tuning-cache list`](#syq-tuning-cache-list) | List recent transfers, newest first |
| [`tuning-cache show`](#syq-tuning-cache-show) | Show a transfer's measurements and decisions |
| [`tuning-cache export`](#syq-tuning-cache-export) | Export history as NDJSON; omit ID for every transfer |
| [`tuning-cache clear`](#syq-tuning-cache-clear) | Delete recorded history, so later copies choose their starting worker counts afresh |

**Help (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq tuning-cache list

List recent transfers, newest first. The `WORKERS` column shows `?` for
transfers recorded by this version; use `show` to see their worker counts.

<!-- CLI: tuning-cache list -->
```text
syq tuning-cache list [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--limit <N>` | Show at most N transfers<br><br>[default: 50] |

<!-- /CLI -->

## syq tuning-cache show

Print one transfer's context and timestamped events. With `--html`, redirect
stdout to a file and open it in a browser for an interactive timeline.

<!-- CLI: tuning-cache show -->
```text
syq tuning-cache show [OPTIONS] <ID>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ID>` | Transfer ID shown by tuning-cache list |

**Options**

| Argument / option | Meaning |
|---|---|
| `--html` | Write a standalone interactive timeline to stdout |

<!-- /CLI -->

## syq tuning-cache export

Print transfers as NDJSON, each followed by its events.

<!-- CLI: tuning-cache export -->
```text
syq tuning-cache export [ID]
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `[ID]` | Transfer ID shown by tuning-cache list; omit to export every transfer |

<!-- /CLI -->

## syq tuning-cache clear

Delete the history and the starting worker counts learned from it.

<!-- CLI: tuning-cache clear -->
```text
syq tuning-cache clear
```

<!-- /CLI -->
