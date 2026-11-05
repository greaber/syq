# syq tuning-cache

Inspect the measurements and decisions recorded by filesystem transfers.
See [tuning history](../tuning.md#inspect-tuning-history) for privacy,
retention, and startup behavior.

<!-- CLI: tuning-cache -->
```text
syq tuning-cache <COMMAND>
```

| Command | Purpose |
|---|---|
| [`tuning-cache list`](#syq-tuning-cache-list) | List recent transfers |
| [`tuning-cache show`](#syq-tuning-cache-show) | Show a transfer's measurements and decisions |
| [`tuning-cache export`](#syq-tuning-cache-export) | Export history as NDJSON; omit ID for every transfer |
| [`tuning-cache clear`](#syq-tuning-cache-clear) | Delete recorded history and filesystem startup hints |

**Help (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq tuning-cache list

List recent transfers, newest first. The worker column shows `?` for new
transfers; only older records have a count.

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

Each transfer record is followed by its event records.

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

Delete recorded history and the startup hints learned from it, so later
copies choose their starting worker counts afresh. `clear` leaves alone
`~/.cache/syq/tuning.json`, which older versions used; you can delete it.

<!-- CLI: tuning-cache clear -->
```text
syq tuning-cache clear
```

<!-- /CLI -->
