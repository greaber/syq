# syq tuning

Inspect the measurements and decisions recorded by filesystem transfers.
See [tuning history](../tuning.md#inspect-tuning-history) for privacy,
retention, and startup behavior.

<!-- CLI: tuning -->
```text
syq tuning <COMMAND>
```

| Command | Purpose |
|---|---|
| [`tuning list`](#syq-tuning-list) | List recent transfers |
| [`tuning show`](#syq-tuning-show) | Show a transfer's measurements and decisions |
| [`tuning export`](#syq-tuning-export) | Export history as NDJSON; omit ID for every transfer |
| [`tuning clear`](#syq-tuning-clear) | Delete recorded history and filesystem startup hints |

**Help (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq tuning list

List recent transfers, newest first. The worker column shows the count saved
as a startup hint; `?` means the transfer did not supply a recommendation.

<!-- CLI: tuning list -->
```text
syq tuning list [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--limit <limit>` | [default: 50] |

<!-- /CLI -->

## syq tuning show

Print one transfer's context and timestamped events. With `--html`, redirect
stdout to a file and open it in a browser for an interactive timeline.

<!-- CLI: tuning show -->
```text
syq tuning show [OPTIONS] <id>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<id>` | See the command description above. |

**Options**

| Argument / option | Meaning |
|---|---|
| `--html` | Write a standalone interactive timeline to stdout |

<!-- /CLI -->

## syq tuning export

Export one transfer, or all retained transfers when the ID is omitted, as
NDJSON. Each transfer record is followed by its event records.

<!-- CLI: tuning export -->
```text
syq tuning export [id]
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `[id]` | See the command description above. |

<!-- /CLI -->

## syq tuning clear

Delete the local history and its filesystem startup hints. The older
connection-count cache remains unchanged.

<!-- CLI: tuning clear -->
```text
syq tuning clear
```

<!-- /CLI -->
