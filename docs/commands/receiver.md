# syq receiver

Manage restricted copying on server accounts, for direct server-to-server
copies. See [access management](../remote-to-remote.md#first-copy-and-access-management)
and [enrollment details](../remote-reference.md#enrollment) for setup, key
changes, and upgrades.

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

Sets up restricted copying on a server account, or refreshes it: it installs
the receiver for this syq build and trusts the key you log in with. Copies do
this automatically when needed. Copies already running continue.

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

Enrollments made by syq 0.7.1 and earlier are not listed, and this version
cannot use or revoke them. When this account still holds their files, `list`
prints a notice. To remove them, revoke them with the older version, or delete
syq's old lines in the server's `authorized_keys` and its old files on both
machines as [Enrollments from older versions](../remote-reference.md#enrollments-from-older-versions)
describes.

<!-- CLI: receiver list -->
```text
syq receiver list
```

<!-- /CLI -->

## syq receiver revoke

Stops copies running through the enrollment, removes syq's line and state from
the server account, and then removes this machine's record. If the server
cannot be reached, nothing is removed; run the command again.

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
