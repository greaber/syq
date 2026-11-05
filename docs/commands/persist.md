# syq persist

Manage reusable SSH connections and receiving profiles. Start with
[Use your laptop from a server](../receive.md) for setup, or see
[Persistence details](../persistence-reference.md) for profiles and limits.

<!-- CLI: persist -->
```text
syq persist [OPTIONS] <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist auth-from`](#syq-persist-auth-from) | Choose default authorization for server copies and SSH sessions |
| [`persist ssh-config`](#syq-persist-ssh-config) | Export native OpenSSH configuration for one already approved account connection |
| [`persist receive`](#syq-persist-receive) | Configure receiving and decide incoming copy or command requests |
| [`persist destinations`](#syq-persist-destinations) | Inspect shared receiving names; --pscope does not filter them |
| [`persist connect`](#syq-persist-connect) | Connect with native SSH or request approved account access |
| [`persist on`](#syq-persist-on) | Enable persistent connections for later syq commands |
| [`persist off`](#syq-persist-off) | Disable persistence and close its live SSH control connections |
| [`persist status`](#syq-persist-status) | Show connection readiness and any receiving problem |

**Options (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `--pscope <PATH>` | Select an isolated persistence domain instead of the default domain |

**Help (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq persist auth-from

Choose or show [authorization defaults](../persistence-reference.md#authorization-defaults).

<!-- CLI: persist auth-from -->
```text
syq persist auth-from [OPTIONS] [auto|ssh|@NAME|HOST]
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `[auto\|ssh\|@NAME\|HOST]` | Authorization for later commands; omit to show saved defaults |

**Options**

| Argument / option | Meaning |
|---|---|
| `--for <HOST>` | Apply to this exact destination hostname or SSH alias, for any login/port |
| `--reset` | Remove the selected override so it inherits the default |

<!-- /CLI -->

## syq persist ssh-config

Export an existing [approved account connection](../persistence-reference.md#approved-account-connections)
for native SSH tools. Save the output to a file and pass it through `-F`.

<!-- CLI: persist ssh-config -->
```text
syq persist ssh-config [OPTIONS] <HOST>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<HOST>` | Approved SSH endpoint: [USER@]HOST[:PORT] |

**Options**

| Argument / option | Meaning |
|---|---|
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Select existing approval; omitted uses SYQ_AUTH_FROM, then the saved preference, then auto |

<!-- /CLI -->

## syq persist receive

Configure receiving and approve its requests. See the
[three uses of receiving](../receive.md) for file copies to your
machine, commands on it, and authorizing copies between servers.

<!-- CLI: persist receive -->
```text
syq persist receive [OPTIONS] <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist receive pending`](#syq-persist-receive-pending) | Show incoming copy and command requests awaiting approval on this machine |
| [`persist receive approve`](#syq-persist-receive-approve) | Allow one pending request using the ID from persist receive pending |
| [`persist receive permissions`](#syq-persist-receive-permissions) | List or remove account permissions remembered on this machine |
| [`persist receive deny`](#syq-persist-receive-deny) | Deny one pending request using the ID from persist receive pending |
| [`persist receive on`](#syq-persist-receive-on) | Enable or configure a receiving profile (without --name, use the first profile) |
| [`persist receive off`](#syq-persist-receive-off) | Disable receiving and stop its background connections; keep ordinary persistence |
| [`persist receive remove`](#syq-persist-receive-remove) | Remove a saved receiving profile and stop its connections |
| [`persist receive status`](#syq-persist-receive-status) | Show receiving settings and background connection state |
| [`persist receive wait`](#syq-persist-receive-wait) | Wait for a connection with a deadline |

<!-- /CLI -->

## syq persist receive pending

Use a returned request ID with `approve` or `deny`.

<!-- CLI: persist receive pending -->
```text
syq persist receive pending [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | Print the requests as JSON |
| `--wait` | Wait for an incoming request, with a deadline |
| `--timeout <SECONDS>` | With --wait, give up after this many seconds<br><br>[default: 30] |

<!-- /CLI -->

## syq persist receive approve

Copy and command approvals apply once. SSH account requests grant
[session access](../persistence-reference.md#account-permissions); add `--remember`
to permit future account authentications too.

<!-- CLI: persist receive approve -->
```text
syq persist receive approve [OPTIONS] <ID>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ID>` | Request ID shown by persist receive pending |

**Options**

| Argument / option | Meaning |
|---|---|
| `--remember` | Remember this SSH account permission for future receiving connections or provider logins |

<!-- /CLI -->

## syq persist receive deny

<!-- CLI: persist receive deny -->
```text
syq persist receive deny [OPTIONS] <ID>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ID>` | Request ID shown by persist receive pending |

<!-- /CLI -->

## syq persist receive permissions

Manage [remembered account permissions](../persistence-reference.md#account-permissions)
on the laptop. These commands do not need a running receiving service.

<!-- CLI: persist receive permissions -->
```text
syq persist receive permissions [OPTIONS] <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist receive permissions list`](#syq-persist-receive-permissions-list) | Show remembered SSH account permissions |
| [`persist receive permissions remove`](#syq-persist-receive-permissions-remove) | Stop future authentications; already authenticated sessions may continue |

<!-- /CLI -->

## syq persist receive permissions list

Show remembered account permissions, both for servers connected to this
machine and for logins through it as an SSH authorization provider, including
each destination's trusted name and connection route. Use `--json`
for [structured permission records](../automation.md#remembered-account-permissions).

<!-- CLI: persist receive permissions list -->
```text
syq persist receive permissions list [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | Print the permissions as JSON |

<!-- /CLI -->

## syq persist receive permissions remove

<!-- CLI: persist receive permissions remove -->
```text
syq persist receive permissions remove [OPTIONS] <ID>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ID>` | Permission ID shown by persist receive permissions list |

<!-- /CLI -->

## syq persist receive on

Omitted settings keep their saved values. A new profile asks for approval with
desktop prompts and uses your home directory; set `--root` to confine copies to
a directory. Without `--connection`, the profile applies to existing and future
connections. Changing access settings cancels the profile's active requests.
See [profile settings](../persistence-reference.md#names-and-profiles) and
[copy limits](../persistence-reference.md#copy-limits).

<!-- CLI: persist receive on -->
```text
syq persist receive on [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--auto-approve-root <DIR>` | Automatically approve downloads confined to this directory |
| `--no-auto-approve-root` | Require approval for every download again |
| `--connection <ENDPOINT>` | Replace the allowed connection list and connect these endpoints now (repeat for several) |
| `--all-connections` | Make this profile available through every connected SSH account |
| `--notify <MODE>` | Show desktop prompts, or use only local pending/approve/deny commands<br><br>[possible values: desktop, off] |
| `--name <NAME>` | Create or update this named profile; omitted means the first profile |
| `-C, --cwd <DIR>` | Default destination directory; absolute paths and .. may select elsewhere |
| `--auto-cwd` | Choose cwd from root, auto-approve-root, then HOME |
| `--root <DIR>` | Confinement boundary for every download, even with approval |
| `--no-root` | Remove the hard download boundary |
| `--max-bytes <SIZE>` | Maximum bytes one transfer may write (default: 100G) |
| `--max-entries <N>` | Maximum entries one transfer may touch (default: 1000000) |
| `--max-delete <N>` | Permit pruning up to N entries per transfer (default: 0) |

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

The last profile can be disabled but not removed. Names it registered on
servers remain until you [forget them](#syq-persist-destinations-forget).

<!-- CLI: persist receive remove -->
```text
syq persist receive remove [OPTIONS] <NAME>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<NAME>` | Profile to remove |

<!-- /CLI -->

## syq persist receive status

<!-- CLI: persist receive status -->
```text
syq persist receive status [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | Print the settings and state as JSON |
| `--name <NAME>` | Show only this profile |

<!-- /CLI -->

## syq persist receive wait

Failure or timeout exits nonzero. This command does not start a connection.

<!-- CLI: persist receive wait -->
```text
syq persist receive wait [OPTIONS] <HOST>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<HOST>` | SSH server whose receiving connection to wait for |

**Options**

| Argument / option | Meaning |
|---|---|
| `--name <NAME>` | Wait for this profile; otherwise wait for every enabled profile |
| `--timeout <SECONDS>` | Give up after this many seconds<br><br>[default: 30] |

<!-- /CLI -->

## syq persist destinations

Receiving names are shared by this OS account across persistence domains.
`--pscope` does not filter this registry; forgetting an offline name releases it
for every domain. See [shared names](../persistence-reference.md#isolated-script-scopes).

<!-- CLI: persist destinations -->
```text
syq persist destinations [OPTIONS] <COMMAND>
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
syq persist destinations list [OPTIONS]
```

<!-- /CLI -->

## syq persist destinations forget

Use this before replacing the laptop that registered a name. Forgetting a name
whose laptop is still connected is refused.

<!-- CLI: persist destinations forget -->
```text
syq persist destinations forget [OPTIONS] <NAME>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<NAME>` | Receiving name to release, without @ |

<!-- /CLI -->

## syq persist destinations wait

<!-- CLI: persist destinations wait -->
```text
syq persist destinations wait [OPTIONS] <NAME>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<NAME>` | Receiving name to wait for, without @ |

**Options**

| Argument / option | Meaning |
|---|---|
| `--timeout <SECONDS>` | Give up after this many seconds<br><br>[default: 30] |

<!-- /CLI -->

## syq persist connect

Connect to `HOST` and wait up to `--timeout` seconds for receiving to be ready.

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
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Authorize a reusable destination-account login through @NAME or an SSH provider |
| `--syq-path <PATH>` | Use this remote syq executable instead of installing a matching helper |
| `--no-bootstrap` | Use syq on the remote PATH instead of installing a matching helper |
| `--timeout <SECONDS>` | Wait this many seconds for receiving after connecting<br><br>[default: 30] |

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

<!-- /CLI -->

## syq persist status

Show connections without starting them. `--json` prints the
[connection-status contract](../automation.md#connection-status), with the
[approved account](../persistence-reference.md#approved-account-connections)
fields. If some approved-account records cannot be read, status still shows the
healthy connections, reports the errors, and exits nonzero.

<!-- CLI: persist status -->
```text
syq persist status [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | Print structured connection state |

<!-- /CLI -->
