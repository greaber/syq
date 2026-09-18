# syq receiver

Manage restricted destinations for direct server-to-server copies. See
[access management](../remote-to-remote.md#first-copy-and-access-management)
and [enrollment details](../remote-reference.md#enrollment) for setup and upgrades.

<!-- CLI: receiver -->
```text
syq receiver <COMMAND>
```

| Command | Purpose |
|---|---|
| [`receiver enroll`](#syq-receiver-enroll) | Manually enroll or refresh a receiver |
| [`receiver list`](#syq-receiver-list) | List local active and pending enrollments |
| [`receiver revoke`](#syq-receiver-revoke) | Stop active receivers and remove their enrollment from both machines |

**Help (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq receiver enroll

The destination’s parent must exist. Repeating enrollment updates the receiver;
stop active copies before updating it.

<!-- CLI: receiver enroll -->
```text
syq receiver enroll [OPTIONS] <[USER@]HOST:DESTINATION>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<[USER@]HOST:DESTINATION>` | Remote destination, e.g. alice@nas:/backup/photos |

**Options**

| Argument / option | Meaning |
|---|---|
| `--via <ENDPOINT>` | Retry through this SSH jump host if the direct management connection fails |

<!-- /CLI -->

## syq receiver list

<!-- CLI: receiver list -->
```text
syq receiver list
```

<!-- /CLI -->

## syq receiver revoke

<!-- CLI: receiver revoke -->
```text
syq receiver revoke [OPTIONS] <ENROLLMENT-ID>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<ENROLLMENT-ID>` | Enrollment ID printed by syq receiver list |

**Options**

| Argument / option | Meaning |
|---|---|
| `--via <ENDPOINT>` | Retry through this SSH jump host if the direct management connection fails |

<!-- /CLI -->
