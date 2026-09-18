# syq receiver

Manage restricted destinations for direct server-to-server copies. Normal copies
can enroll automatically; use these commands to prepare, refresh, inspect, or
revoke access. See [access management](../remote-to-remote.md#first-copy-and-access-management)
and [enrollment details](../remote-reference.md#enrollment) for prerequisites and upgrades.

These enrollments are separate from the named receiving profiles managed by
[`syq persist receive`](persist.md#syq-persist-receive). Every nested command
and its options follow.

<!-- CLI: receiver -->
```text
syq receiver <COMMAND>
```

| Command | Purpose |
|---|---|
| [`receiver enroll`](#syq-receiver-enroll) | Manually enroll or refresh a receiver |
| [`receiver list`](#syq-receiver-list) | List local active and pending enrollments |
| [`receiver revoke`](#syq-receiver-revoke) | Stop active receivers and remove their enrollment from both machines |

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq receiver enroll

`[USER@]HOST:DESTINATION` names the destination to prepare. Its parent must exist. Repeating enrollment refreshes the receiver to match the local build; stop active copies before updating it. `--via` is an SSH jump host for management, not a receiving name.

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq receiver list

List active and pending enrollments saved on this machine, including the IDs used for revocation.

<!-- CLI: receiver list -->
```text
syq receiver list
```

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq receiver revoke

`ENROLLMENT-ID` comes from `receiver list`. Revocation stops active copies and removes access on both machines; completed writes remain. If cleanup fails, the enrollment remains revoked: rerun the command to finish cleanup.

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

**Help and version**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

