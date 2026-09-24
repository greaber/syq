# Environment and local files

Syq has no general configuration file. It uses your SSH configuration for SSH
connections and AWS configuration for S3; see [S3 options](object-storage.md#s3-options).

## Add options through the environment

`SYQ_CP_OPTIONS`, `SYQ_RSYNC_OPTIONS`, and `SYQ_RM_OPTIONS` supply extra
arguments to their respective commands. They are useful when a script does
not let you change the syq command it runs:

```sh
SYQ_CP_OPTIONS='--resource-limits bandwidth=10M' ./nightly-backup.sh
```

The value is parsed with shell-style quoting and inserted before the command's
other arguments. Repeating an option follows the same rules as repeating it
on the command line. Syq removes these three variables before launching SSH,
helpers, or other programs; the rest of the environment is passed through.

## Other variables

| Variable | Purpose |
|---|---|
| `SYQ_NO_UPDATE_CHECK`, `DO_NOT_TRACK` | Disable update reminders; see [Updates](install.md#updates) |
| `SYQ_TUNING_CACHE` | Select the connection-count cache; an empty value disables it. See [Remembered connection counts](tuning.md#remembered-connection-counts) |
| `SYQ_TUNING_HISTORY` | Select the local tuning history; empty disables it. See [Tuning history](tuning.md#inspect-tuning-history) |
| `SYQ_TUNING_HISTORY_SIZE` | History retention target, default `10M` |
| `SYQ_DEBUG` | Add internal diagnostics to stderr |
| `SYQ_S3_DIAGNOSTICS=1` | Add S3 request diagnostics to stderr |
| `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR` | Relocate cache, preference, and runtime files |

Diagnostic formats can change between versions. For scripts, use
[automation results](automation.md). Usual system variables such as `HOME`,
`TMPDIR`, and `SSH_AUTH_SOCK` also apply.

## Local state

Default locations include:

| Location | Contents |
|---|---|
| `~/.cache/syq/tuning.json` | Learned connection counts in the legacy format |
| `~/.cache/syq/tuning.history-v1.sqlite` | Local tuning timelines and filesystem startup hints |
| `~/.cache/syq/completion-endpoints.json` | Hosts offered by completion |
| `~/.cache/syq/helpers/` | Downloaded SSH helpers |
| `~/.config/syq/persistence.json` | Whether persistence is enabled |
| `~/.config/syq/receive.json` | Receiving profiles |
| `~/.config/syq/install.json`, `last-update-check` | Install receipt and update-check timing |
| `$XDG_RUNTIME_DIR/syq-persist-UID/` | Persistent connection sockets |
| `~/.syq-destinations-v3/` | Registered receiving names on a server |
| `~/.local/share/syq/restricted/` | Receiver enrollment state |

Copies can proceed when optional caches cannot be written. Persistent
connections need a writable runtime directory. See [Enrollment](remote-reference.md#enrollment)
for receiver state and [Names and profiles](persistence-reference.md#names-and-profiles)
for backing up or replacing a receiving identity.

## SSH helper installation

SSH helpers are installed under `~/.cache/syq/helpers/` on the server too.
If that directory cannot be created, select an installed helper with
`--syq-path`, or use `--no-bootstrap` when a matching syq is on the server's
`PATH`.

When an official release installs a helper, it also tries to install the command
at `~/.local/bin/syq`. Completion and background connections can trigger this
step. Failure to install the command does not stop the copy. Reusing a cached
helper does not repeat the command installation; use the standalone installer
if the command is missing. Development builds and connections using
`--syq-path` or `--no-bootstrap` do not install the command.
