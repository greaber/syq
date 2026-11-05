# Environment and local files

Syq has no general configuration file. It uses your SSH configuration for SSH
connections and AWS configuration for S3; see [S3 options](object-storage.md#s3-options).
Commands without an `--rsh` option, such as `syq rm`, `syq receiver`, and
`syq persist`, as well as shell completion and [receiving](receive.md), always
run your `ssh`, so set per-host keys, ports, and jump hosts in your SSH
configuration.

## Add options through the environment

`SYQ_CP_OPTIONS`, `SYQ_RSYNC_OPTIONS`, and `SYQ_RM_OPTIONS` supply extra
arguments to their respective commands. They are useful when a script does
not let you change the syq command it runs:

```sh
SYQ_CP_OPTIONS='--resource-limits bandwidth=10M' ./nightly-backup.sh
```

The value is parsed with shell-style quoting and inserted before the command's
other arguments. Syq does not pass these variables on to the programs it
starts.

## Choose authorization through the environment

`SYQ_AUTH_FROM` sets `--auth-from` for SSH endpoints in a shell or script,
with the same values; see [Authorization defaults](persistence-reference.md#authorization-defaults)
for how it combines with saved choices.

```sh
SYQ_AUTH_FROM=@laptop ./agent-task.sh
```

## Other variables

| Variable | Purpose |
|---|---|
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Replace the system CA roots for HTTPS; see [HTTPS certificates](security.md#https-certificates) |
| `SYQ_NO_UPDATE_CHECK`, `DO_NOT_TRACK` | Disable update reminders; see [Updates](install.md#updates) |
| `SYQ_TUNING_CACHE` | Base path for tuning history; an empty value turns history off, even when `SYQ_TUNING_HISTORY` is set. See [Remembered connection counts](tuning.md#remembered-connection-counts) |
| `SYQ_TUNING_HISTORY` | Tuning history file to use instead; empty disables history. See [Tuning history](tuning.md#inspect-tuning-history) |
| `SYQ_TUNING_HISTORY_SIZE` | History retention target, default and minimum `10M` |
| `SYQ_DEBUG` | Add internal diagnostics to stderr |
| `SYQ_S3_DIAGNOSTICS=1` | Add S3 request diagnostics to stderr |
| `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR` | Relocate cache, preference, and runtime files, but not [stored releases](#stored-releases-and-helpers); relative values are ignored |

Diagnostic formats can change between versions. For scripts, use
[automation results](automation.md). Usual system variables such as `HOME`,
`TMPDIR`, and `SSH_AUTH_SOCK` also apply.

Inside tmux, a shell keeps the `SSH_AUTH_SOCK` it started with, which stops
working when you reattach from a new SSH login. When that socket no longer
exists, syq uses the tmux session's current agent, if one you own answers, for
the programs it starts. To fix the shell itself,
run `eval "$(tmux show-environment -s SSH_AUTH_SOCK)"`.

## Local state

Default locations include:

| Location | Contents |
|---|---|
| `~/.cache/syq/tuning.json` | Connection counts saved by older versions; no longer used, and safe to delete |
| `~/.cache/syq/helpers/` | Helpers saved by older versions; safe to delete unless you still run those releases, including with `--use-version` |
| `~/.cache/syq/tuning.history-v1.sqlite` | Local tuning timelines and filesystem startup hints |
| `~/.cache/syq/completion-endpoints.json` | Hosts offered by completion |
| `~/.config/syq/persistence.json` | Whether persistence is enabled |
| `~/.config/syq/receive.json` | Receiving profiles |
| `~/.config/syq/install.json`, `last-update-check` | Install receipt and update-check timing |
| `~/.local/lib/syq/` | [Stored releases and helpers](#stored-releases-and-helpers) |
| `$XDG_RUNTIME_DIR/syq-persist-UID/` | Persistent connection sockets |
| `~/.syq-destinations-v3/` | Registered receiving names on a server |
| `~/.local/state/syq/enrollments/` | Your restricted-copy enrollments, with their entry keys |
| `~/.local/share/syq/enrollments/` | A server's enrollment state |

Copies proceed when optional caches cannot be written, but they need a little
space for private sockets in the temporary directory on each machine: `TMPDIR`
when it is set, otherwise `/tmp`. Persistent connections need a writable
runtime directory; without one, a copy warns and connects without persistence.
See [Enrollment](remote-reference.md#enrollment) for receiver state and
[Names and profiles](persistence-reference.md#names-and-profiles) for backing
up or replacing a receiving identity.

## Stored releases and helpers

Syq keeps the executables of exact releases in `~/.local/lib/syq`, with one
directory per release and one below it per platform:

```text
~/.local/lib/syq/v0.7.1/linux-x86_64/syq
```

That covers releases you select with
[`--use-version`](install.md#choose-a-version-for-a-script), helpers syq
uploads to SSH servers, and, on a server, the helper syq installs there, which
also receives [restricted copies](remote-reference.md#enrollment).

Syq does not remove old releases. To remove one you no longer use, or replace
a damaged one, delete its directory, such as `~/.local/lib/syq/v0.7.1`; syq
downloads or installs it again if needed. On a server that accepts restricted
copies, keep any release that a syq line in `~/.ssh/authorized_keys` names; see
[Enrollment](remote-reference.md#enrollment).

Syq starts a stored release only when its files and directories are yours and
nobody else can write them. See
[Downloaded executables](security.md#downloaded-executables) for what the
store trusts.

## SSH helper installation

Syq [installs its helper](install.md#automatic-installation-on-ssh-servers)
under `~/.local/lib/syq/` on the server. If that directory cannot be created,
select an installed helper with `--syq-path`, or use `--no-bootstrap` when a
matching syq is on the server's `PATH`; neither installs the `syq` command on
the server. Syq tries to install that command only along with the helper, so
use the standalone installer if it goes missing later.
