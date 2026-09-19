# syq persist

Manage reusable SSH connections and receiving profiles. Start with
[Send files home from a server](../receive.md) for setup, or see
[Persistence details](../persistence-reference.md) for profiles and limits.

<!-- CLI: persist -->
```text
syq persist <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist receive`](#syq-persist-receive) | Configure receiving and decide incoming copy or command requests |
| [`persist destinations`](#syq-persist-destinations) | Inspect or recover named return destinations |
| [`persist connect`](#syq-persist-connect) | Connect to an SSH server and wait until enabled receiving is ready |
| [`persist on`](#syq-persist-on) | Enable persistent connections for later syq commands |
| [`persist off`](#syq-persist-off) | Disable persistence and close its live SSH control connections |
| [`persist status`](#syq-persist-status) | Show connection readiness and any receiving problem |

**Help (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist receive

<!-- CLI: persist receive -->
```text
syq persist receive <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist receive pending`](#syq-persist-receive-pending) | Show incoming copy and command requests awaiting approval on this machine |
| [`persist receive approve`](#syq-persist-receive-approve) | Allow one pending request using the ID from persist receive pending |
| [`persist receive deny`](#syq-persist-receive-deny) | Deny one pending request using the ID from persist receive pending |
| [`persist receive on`](#syq-persist-receive-on) | Enable or configure a receiving profile (without --name, use the first profile) |
| [`persist receive off`](#syq-persist-receive-off) | Disable receiving and stop its background connections; keep ordinary persistence |
| [`persist receive remove`](#syq-persist-receive-remove) | Remove a saved receiving profile and stop its connections |
| [`persist receive status`](#syq-persist-receive-status) | Show receiving settings and background connection state |
| [`persist receive wait`](#syq-persist-receive-wait) | Wait for a connection with a deadline |

<!-- /CLI -->

## syq persist receive pending

`--json` prints structured requests. `--wait` waits for a request, up to `--timeout` seconds (default 30). Use the returned request ID with `approve` or `deny`.

<!-- CLI: persist receive pending -->
```text
syq persist receive pending [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | See the command description above. |
| `--wait` | Wait for an incoming request, with a deadline |
| `--timeout <TIMEOUT>` | [default: 30] |

<!-- /CLI -->

## syq persist receive approve

`ID` is a pending request ID from `persist receive pending` on this machine. Approval applies to that request only.

<!-- CLI: persist receive approve -->
```text
syq persist receive approve <ID>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ID>` | See the command description above. |

<!-- /CLI -->

## syq persist receive deny

`ID` is a pending request ID from `persist receive pending` on this machine.

<!-- CLI: persist receive deny -->
```text
syq persist receive deny <ID>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ID>` | See the command description above. |

<!-- /CLI -->

## syq persist receive on

Omitted settings keep saved values. New profiles ask for approval with desktop
prompts and use the home directory. Set `--root` to confine copies to a directory.
Changing settings cancels the profile’s active requests. See
[profile settings](../persistence-reference.md#names-and-profiles) and
[copy limits](../persistence-reference.md#copy-limits).

<!-- CLI: persist receive on -->
```text
syq persist receive on [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--auto-approve-root <AUTO_APPROVE_ROOT>` | Automatically approve downloads confined to this directory |
| `--no-auto-approve-root` | Require approval for every download again |
| `--server <SERVERS>` | Limit this profile to these SSH destinations (repeat to allow several) |
| `--all-servers` | Make this profile available through every connected server |
| `--notify <NOTIFICATIONS>` | Show desktop prompts, or use only local pending/approve/deny commands<br><br>[possible values: desktop, off] |
| `--name <NAME>` | Create or update this named profile; omitted means the first profile |
| `-C, --cwd <CWD>` | Default destination directory; absolute paths and .. may select elsewhere |
| `--auto-cwd` | Choose cwd from root, auto-approve-root, then HOME |
| `--root <ROOT>` | Confinement boundary for every download, even with approval |
| `--no-root` | Remove the hard download boundary |
| `--max-bytes <MAX_BYTES>` | Maximum bytes one transfer may reserve/write (default: 100G) |
| `--max-entries <MAX_ENTRIES>` | Maximum entries one transfer may touch (default: 1000000) |
| `--max-delete <MAX_DELETE>` | Permit pruning up to N entries per transfer (default: 0) |

<!-- /CLI -->

## syq persist receive off

Disable the named profile, or all profiles when `--name` is omitted. This stops incoming requests while leaving forward SSH persistence available.

<!-- CLI: persist receive off -->
```text
syq persist receive off [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--name <NAME>` | Stop only this profile; without --name, stop all profiles |

<!-- /CLI -->

## syq persist receive remove

`NAME` identifies the saved profile to remove. Its connections and requests stop. The last profile can be disabled but cannot be removed; server-side name assignments remain until explicitly forgotten.

<!-- CLI: persist receive remove -->
```text
syq persist receive remove <NAME>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<NAME>` | See the command description above. |

<!-- /CLI -->

## syq persist receive status

Show all profiles, or select one with `--name`. Use `--json` for structured output.

<!-- CLI: persist receive status -->
```text
syq persist receive status [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | See the command description above. |
| `--name <NAME>` | See the command description above. |

<!-- /CLI -->

## syq persist receive wait

`HOST` is the SSH server endpoint. Wait for the selected profile, or every enabled profile when `--name` is omitted. `--timeout` is in seconds; failure or timeout exits nonzero. This command does not start a connection.

<!-- CLI: persist receive wait -->
```text
syq persist receive wait [OPTIONS] <HOST>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<HOST>` | See the command description above. |

**Options**

| Argument / option | Meaning |
|---|---|
| `--name <NAME>` | Wait for this profile; otherwise wait for every enabled profile |
| `--timeout <TIMEOUT>` | [default: 30] |

<!-- /CLI -->

## syq persist destinations

<!-- CLI: persist destinations -->
```text
syq persist destinations <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist destinations list`](#syq-persist-destinations-list) | Print registrations and whether their receiving laptop responds |
| [`persist destinations forget`](#syq-persist-destinations-forget) | Remove an offline destination name so another laptop can register it |
| [`persist destinations wait`](#syq-persist-destinations-wait) | Wait for a connection with a deadline |

<!-- /CLI -->

## syq persist destinations list

<!-- CLI: persist destinations list -->
```text
syq persist destinations list
```

<!-- /CLI -->

## syq persist destinations forget

`NAME` is an offline receiving name to release before replacing its machine. Forgetting a live connection is refused.

<!-- CLI: persist destinations forget -->
```text
syq persist destinations forget <NAME>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<NAME>` | See the command description above. |

<!-- /CLI -->

## syq persist destinations wait

`NAME` is a receiving name without `@`. Wait up to `--timeout` seconds for it to respond; timeout exits nonzero.

<!-- CLI: persist destinations wait -->
```text
syq persist destinations wait [OPTIONS] <NAME>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<NAME>` | See the command description above. |

**Options**

| Argument / option | Meaning |
|---|---|
| `--timeout <TIMEOUT>` | [default: 30] |

<!-- /CLI -->

## syq persist connect

Connect to `HOST` and wait for receiving to be ready. `--timeout` applies to
the receiving wait after SSH and helper setup. `--syq-path` and `--no-bootstrap`
cannot combine. Use `--pscope` for an existing ephemeral scope.

<!-- CLI: persist connect -->
```text
syq persist connect [OPTIONS] <HOST>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<HOST>` | SSH endpoint ([USER@]HOST[:PORT]); receiving names are not accepted |

**Options**

| Argument / option | Meaning |
|---|---|
| `--syq-path <PATH>` | Use this remote syq executable instead of installing a matching helper |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a matching helper |
| `--timeout <TIMEOUT>` | Wait this many seconds for receiving after SSH/helper setup<br><br>[default: 30] |
| `--pscope <PATH>` | Reuse forward SSH in an existing ephemeral scope, without enabling receiving |

<!-- /CLI -->

## syq persist on

<!-- CLI: persist on -->
```text
syq persist on [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--ephemeral` | Create an ephemeral scope and print its path instead of changing the user setting |

<!-- /CLI -->

## syq persist off

<!-- CLI: persist off -->
```text
syq persist off [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--pscope <PATH>` | Operate on this ephemeral persistence scope instead of the user setting |

<!-- /CLI -->

## syq persist status

Inspect connections without starting them. `--json` uses the [connection-status contract](../automation.md#connection-status). `--pscope` selects an ephemeral scope.

<!-- CLI: persist status -->
```text
syq persist status [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | Print structured connection state |
| `--pscope <PATH>` | Inspect this ephemeral persistence scope instead of the user setting |

<!-- /CLI -->
