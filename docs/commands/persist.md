# syq persist

Keep SSH connections open between commands, and let servers send copies and
requests to your laptop. Start with
[Use your laptop from a server](../receive.md);
[Persistence details](../persistence-reference.md) covers profiles and limits.

<!-- CLI: persist -->
```text
syq persist [OPTIONS] <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist auth-from`](#syq-persist-auth-from) | Save the --auth-from choice that later commands use by default |
| [`persist ssh-config`](#syq-persist-ssh-config) | Print an OpenSSH config that lets ssh, scp, or Git use an approved connection |
| [`persist receive`](#syq-persist-receive) | Set up receiving, and approve or deny incoming copy and command requests |
| [`persist destinations`](#syq-persist-destinations) | On a server, list or release receiving names |
| [`persist connect`](#syq-persist-connect) | Connect to a server now and keep the connection open for later commands |
| [`persist on`](#syq-persist-on) | Keep SSH connections open for later syq commands |
| [`persist off`](#syq-persist-off) | Turn persistence off and close its open SSH connections, including receiving; for an |
| [`persist status`](#syq-persist-status) | Show connection readiness and any receiving problem |

**Options (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `--pscope <PATH>` | Use the isolated connections and settings at PATH instead of the default ones |

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
| `[auto\|ssh\|@NAME\|HOST]` | Value to save, as for --auth-from; omit to show the saved choices |

**Options**

| Argument / option | Meaning |
|---|---|
| `--for <HOST>` | Apply to this exact destination hostname or SSH alias, for any login/port |
| `--reset` | Remove the saved choice for --for HOST, or without --for, reset the default to auto |

<!-- /CLI -->

## syq persist ssh-config

Export an existing [approved account connection](../persistence-reference.md#approved-account-connections)
as an OpenSSH configuration for `ssh -F FILE` and other SSH tools.

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
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Which approval to export: the one from @NAME or HOST, or with auto, the only one there is (default: SYQ_AUTH_FROM, then the saved choice, then auto; ssh is not accepted) |

<!-- /CLI -->

## syq persist receive

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
| [`persist receive off`](#syq-persist-receive-off) | Turn receiving off and close its connections; other persistent connections stay open |
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

Approving a copy or command allows that one request. Approving an SSH account
request grants [session access](../persistence-reference.md#account-permissions);
add `--remember` to allow later logins too.

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
| [`persist receive permissions remove`](#syq-persist-receive-permissions-remove) | Remove a remembered permission; sessions already logged in can continue |

<!-- /CLI -->

## syq persist receive permissions list

`--json` prints [structured records](../automation.md#remembered-account-permissions).

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

Settings you leave out keep their saved values. A new profile asks for
approval with desktop prompts, starts relative paths in your home directory
without confining copies to it, and accepts requests through every connection.
Use `--root` to confine copies to one directory and `--connection` to limit
which servers can use the profile. Changing access settings cancels the
profile's active requests. See
[profile settings](../persistence-reference.md#names-and-profiles) and
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
| `-C, --cwd <DIR>` | Starting directory for downloads and commands; absolute paths and .. can still reach elsewhere |
| `--auto-cwd` | Choose the starting directory automatically: the --root directory, else --auto-approve-root, else your home directory |
| `--root <DIR>` | Allow downloads only inside DIR, even approved ones |
| `--no-root` | Remove the --root restriction |
| `--max-bytes <SIZE>` | Maximum bytes one transfer may write (default: 100G) |
| `--max-entries <N>` | Maximum entries one transfer may change (default: 1000000) |
| `--max-delete <N>` | Permit pruning up to N entries per transfer (default: 0) |

<!-- /CLI -->

## syq persist receive off

Turn off the named profile, or every profile without `--name`. Your
persistent SSH connections keep working.

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

Exits nonzero on failure or timeout. It does not start a connection.

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

Run these on a server. Receiving names belong to the whole OS account, so
`--pscope` does not filter them, and forgetting one releases it in every
persistence domain.

<!-- CLI: persist destinations -->
```text
syq persist destinations [OPTIONS] <COMMAND>
```

| Command | Purpose |
|---|---|
| [`persist destinations list`](#syq-persist-destinations-list) | List the receiving names registered here and whether each machine responds |
| [`persist destinations forget`](#syq-persist-destinations-forget) | Release a disconnected machine's receiving name so another machine can claim it |
| [`persist destinations wait`](#syq-persist-destinations-wait) | Wait for a connection with a deadline |

<!-- /CLI -->

## syq persist destinations list

<!-- CLI: persist destinations list -->
```text
syq persist destinations list [OPTIONS]
```

<!-- /CLI -->

## syq persist destinations forget

Run this before you replace the laptop that registered a name, so the new
one can claim it.

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
| `--auth-from <auto\|ssh\|@NAME\|HOST>` | Whose SSH access to connect with: this machine's own (auto or ssh), or access approved by a receiving machine (@NAME) or SSH authorization provider (HOST) |
| `--syq-path <PATH>` | Run the syq at PATH on the remote machine instead of the matching copy syq installs automatically |
| `--no-bootstrap` | Run syq from the remote machine's PATH instead of the matching copy syq installs automatically |
| `--timeout <SECONDS>` | After connecting, wait up to this many seconds for receiving to be ready<br><br>[default: 30] |

<!-- /CLI -->

## syq persist on

<!-- CLI: persist on -->
```text
syq persist on [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--ephemeral` | Create a new isolated set of connections and settings and print its path for --pscope, instead of turning persistence on for your user |

<!-- /CLI -->

## syq persist off

<!-- CLI: persist off -->
```text
syq persist off [OPTIONS]
```

<!-- /CLI -->

## syq persist status

Show connections without starting them. `--json` prints
[machine-readable status](../automation.md#connection-status).

<!-- CLI: persist status -->
```text
syq persist status [OPTIONS]
```

**Options**

| Argument / option | Meaning |
|---|---|
| `--json` | Print the status as JSON |

<!-- /CLI -->
