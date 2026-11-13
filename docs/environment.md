# Environment and local files

Syq has no configuration file of its own: it uses your SSH configuration for
SSH and your AWS configuration for S3 (see
[S3 options](object-storage.md#s3-options)). Commands without an `--rsh`
option, such as `syq rm`, `syq receiver`, and `syq persist`, as well as
completion and [receiving](receive.md), always run your `ssh`, so put per-host
keys, ports, and jump hosts in your SSH configuration.

## Add options through the environment

To add options to a script's syq commands without editing the script, set
`SYQ_CP_OPTIONS`, `SYQ_RSYNC_OPTIONS`, or `SYQ_RM_OPTIONS`:

```sh
SYQ_CP_OPTIONS='--resource-limits bandwidth=10M' ./nightly-backup.sh
```

The value is split with shell-style quoting and inserted before the command's
other arguments.

<a id="choose-authorization-through-the-environment"></a>

## Other variables

| Variable | Purpose |
|---|---|
| `SYQ_AUTH_FROM` | Set `--auth-from` for a shell or script, as in `SYQ_AUTH_FROM=@laptop ./agent-task.sh`; see [Authorization defaults](persistence-reference.md#authorization-defaults) |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Replace the system CA roots for HTTPS; see [HTTPS certificates](security.md#https-certificates) |
| `SYQ_NO_UPDATE_CHECK`, `DO_NOT_TRACK` | Disable update reminders; see [Updates](install.md#updates) |
| `SYQ_TUNING_CACHE` | Base path for tuning history; empty turns history off, even when `SYQ_TUNING_HISTORY` is set. See [Remembered connection counts](tuning.md#remembered-connection-counts) |
| `SYQ_TUNING_HISTORY` | Tuning history file to use instead; empty turns history off. See [Tuning history](tuning.md#inspect-tuning-history) |
| `SYQ_TUNING_HISTORY_SIZE` | Size to keep tuning history to; default and minimum `10M` |
| `SYQ_DEBUG` | Add internal diagnostics to stderr |
| `SYQ_S3_DIAGNOSTICS=1` | Add S3 request diagnostics to stderr |
| `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR` | Move cache, preference, and runtime files, but not [stored releases](#stored-releases-and-helpers); relative values are ignored |

Diagnostic output can change between versions; scripts should use
[automation results](automation.md). Standard variables such as `HOME`,
`TMPDIR`, and `SSH_AUTH_SOCK` also apply.

Inside tmux, a shell keeps the `SSH_AUTH_SOCK` it started with, which stops
working when you reattach from a new SSH login. When that socket is gone, syq
uses the tmux session's current agent, if one you own answers. To fix the
shell itself, run `eval "$(tmux show-environment -s SSH_AUTH_SOCK)"`.

## Local state

| Default location | Contents |
|---|---|
| `~/.cache/syq/tuning.history-v1.sqlite` | Tuning timelines and filesystem startup hints |
| `~/.cache/syq/completion-endpoints.json` | Hosts offered by completion |
| `~/.config/syq/persistence.json`, `receive.json` | Persistence setting and receiving profiles |
| `~/.config/syq/auth-from.json` | Choices saved with [`syq persist auth-from`](commands/persist.md#syq-persist-auth-from) |
| `~/.config/syq/account-permissions-v1.json` | [Account permissions](persistence-reference.md#account-permissions) you chose to remember |
| `~/.syq-receiver-identity/` | The key your [receiving names](persistence-reference.md#back-up-the-receiving-identity) are tied to; keep it in private backups |
| `~/.config/syq/install.json`, `last-update-check` | Install receipt and update-check timing |
| `~/.local/lib/syq/` | [Stored releases and helpers](#stored-releases-and-helpers) |
| `$XDG_RUNTIME_DIR/syq-persist-UID/` | Persistent connection sockets |
| `$XDG_RUNTIME_DIR/syq-UID/` | Sockets of copies that are running |
| `~/.syq-destinations-v3/` | Registered receiving names on a server |
| `~/.local/state/syq/enrollments/` | Your [restricted-copy enrollments](remote-reference.md#enrollment), with their entry keys |
| `~/.local/share/syq/enrollments/` | A server's enrollment state |

Copies still work when caches cannot be written, but each machine needs a
little space for the private sockets in `syq-persist-UID` and `syq-UID`.
Without a private `XDG_RUNTIME_DIR`, these go in the temporary directory:
`TMPDIR`, or `/tmp` when it is unset, except on macOS, where `syq-UID` then goes
in your own temporary directory (the one `getconf DARWIN_USER_TEMP_DIR`
prints). On macOS, persistent connection sockets use `/tmp` rather than
`TMPDIR`.
Then all your SSH logins to a machine must see the same `TMPDIR`, and if
another user creates `syq-UID` there first, copies stop and say so; set
`TMPDIR` to a directory of your own to get around it. When syq can't keep
persistent connection sockets, a copy warns and connects without persistence.

## Stored releases and helpers

Syq keeps exact releases at paths such as
`~/.local/lib/syq/v0.10.0/linux-x86_64/syq`: releases you select with
[`--use-version`](install.md#choose-a-version-for-a-script), helpers (the
copies of syq that run on SSH servers) that it uploads, and, on a server, the
helper installed there, which also receives restricted copies.

Syq never removes old releases. To remove one you no longer use, or replace a
damaged one, delete its directory, such as `~/.local/lib/syq/v0.10.0`; syq
downloads or installs it again when needed. On a server that accepts
restricted copies, keep every release that a syq line in
`~/.ssh/authorized_keys` names.

Before starting a release you selected with `--use-version`, syq checks that
its files and directories are yours and that nobody else can write them. See
[Downloaded executables](security.md#downloaded-executables) for what the
store trusts.

## SSH helper installation

Syq [installs its helper](install.md#automatic-installation-on-ssh-servers)
under `~/.local/lib/syq/` on the server. If that directory cannot be created,
point to an installed helper with `--syq-path`, or use `--no-bootstrap` when a
matching syq is on the server's `PATH`. Syq installs the `syq` command on the
server only together with the helper, so if the command goes missing later,
use the standalone installer.
