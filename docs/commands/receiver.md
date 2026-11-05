# syq receiver

Restricted copying lets one server
[copy into your account on another server](../remote-to-remote.md) without
being given your SSH access to that account. See
[access management](../remote-to-remote.md#first-copy-and-access-management)
and [enrollment details](../remote-reference.md#enrollment).

<!-- CLI: receiver -->
```text
syq receiver <COMMAND>
```

| Command | Purpose |
|---|---|
| [`receiver enroll`](#syq-receiver-enroll) | Manually enroll or refresh a server account |
| [`receiver list`](#syq-receiver-list) | List local active and pending enrollments |
| [`receiver revoke`](#syq-receiver-revoke) | Stop active receivers and remove their enrollment from both machines |

**Help (also available on subcommands)**

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

## syq receiver enroll

Copies enroll an account automatically, so use this to set one up ahead of
time or to refresh it. It installs the receiver for this syq build and trusts
the key you log in with; copies already running continue.

<!-- CLI: receiver enroll -->
```text
syq receiver enroll [OPTIONS] <[USER@]HOST>
```

**Arguments**

| Argument / option | Meaning |
|---|---|
| `<[USER@]HOST>` | Server account, e.g. alice@nas |

**Options**

| Argument / option | Meaning |
|---|---|
| `--via <ENDPOINT>` | Retry through this SSH jump host if the connection along your SSH configuration's route fails |

<!-- /CLI -->

## syq receiver list

Prints one tab-separated line per enrollment: its ID, `active` or `pending`,
and the account. Active enrollments add the receiver's release and the
fingerprint of the login key it trusts.

<!-- CLI: receiver list -->
```text
syq receiver list
```

<!-- /CLI -->

## syq receiver revoke

Stops copies running through the enrollment, removes syq's `authorized_keys`
line and state from the server account, then removes this machine's record. If
the server cannot be reached, nothing is removed; run it again later.

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
| `--via <ENDPOINT>` | Retry through this SSH jump host if the connection along your SSH configuration's route fails |

<!-- /CLI -->
