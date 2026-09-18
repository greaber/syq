# syq persist

Manage reusable SSH connections and receiving profiles. Every public nested
command and its options are listed here. For setup, start with
[Send files home from a server](../receive.md); see
[Persistence details](../persistence-reference.md) for names, limits, and upgrades.

Durable persistence also enables receiving by default, with local approval for
incoming requests. Connections have no idle expiry. Ephemeral scopes reuse only
forward SSH logins; they do not enable receiving or command requests.

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist receive

Run these commands on the receiving machine. Profiles control incoming copies and command requests.

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist receive deny

`ID` is a pending request ID from `persist receive pending` on this machine. The requester receives the refusal.

<!-- CLI: persist receive deny -->
```text
syq persist receive deny <ID>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ID>` | See the command description above. |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist receive on

Create, enable, or update a profile. Omitted settings keep saved values. New profiles ask for approval, use desktop prompts, and start in the home directory without confinement. `--cwd` and `--root` cannot combine. The directory must exist. Changing settings cancels that profile’s active requests. See [profile settings](../persistence-reference.md#names-and-profiles) and [copy limits](../persistence-reference.md#copy-limits).

<!-- CLI: persist receive on -->
```text
syq persist receive on [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--approve <APPROVAL>` | Require local approval for each copy, or explicitly trust connected servers<br><br>[possible values: ask, always] |
| `--notify <NOTIFICATIONS>` | Show desktop prompts, or use only local pending/approve/deny commands<br><br>[possible values: desktop, off] |
| `--name <NAME>` | Create or update this named profile; omitted means the first profile |
| `-C, --cwd <CWD>` | Default destination directory; absolute paths and .. may select elsewhere |
| `--root <ROOT>` | Default directory and confinement boundary; refuse paths escaping it |
| `--max-bytes <MAX_BYTES>` | Maximum bytes one transfer may reserve/write (default: 100G) |
| `--max-entries <MAX_ENTRIES>` | Maximum entries one transfer may touch (default: 1000000) |
| `--max-delete <MAX_DELETE>` | Permit pruning up to N entries per transfer (default: 0) |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist receive status

Show all profiles, or select one with `--name`. `--json` requests structured output without starting a connection.

<!-- CLI: persist receive status -->
```text
syq persist receive status [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | See the command description above. |
| `--name <NAME>` | See the command description above. |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist destinations

Run these commands on the server that receives the laptop’s connection. Names identify receiving machines, not SSH aliases.

<!-- CLI: persist destinations -->
```text
syq persist destinations <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist destinations list`](#syq-persist-destinations-list) | Print registrations and whether their receiving laptop responds |
| [`persist destinations forget`](#syq-persist-destinations-forget) | Remove an offline destination name so another laptop can register it |
| [`persist destinations wait`](#syq-persist-destinations-wait) | Wait for a connection with a deadline |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist destinations list

List assigned receiving names and whether their receiving machines respond.

<!-- CLI: persist destinations list -->
```text
syq persist destinations list
```

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist destinations forget

`NAME` is an offline receiving name to release before replacing its machine. Forgetting a live connection is refused. This does not remove a local receiving profile.

<!-- CLI: persist destinations forget -->
```text
syq persist destinations forget <NAME>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<NAME>` | See the command description above. |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist connect

Enable persistence and connect to `HOST`. With receiving enabled, wait until it is ready. `--timeout` limits that wait after SSH and helper setup; it does not limit authentication or installation. `--syq-path` and `--no-bootstrap` cannot combine. `--pscope` selects an existing ephemeral scope without enabling receiving.

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist on

Enable persistence for future SSH connections. With `--ephemeral`, print a new scope path instead of changing the durable user setting. Pass that path with `--pscope` and close it with `persist off --pscope PATH` when finished.

<!-- CLI: persist on -->
```text
syq persist on [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--ephemeral` | Create an ephemeral scope and print its path instead of changing the user setting |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist off

Close durable connections and disable persistence, or close only the ephemeral scope named by `--pscope`. Active requests using those connections are interrupted.

<!-- CLI: persist off -->
```text
syq persist off [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--pscope <PATH>` | Operate on this ephemeral persistence scope instead of the user setting |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

