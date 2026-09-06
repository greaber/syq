# Copy between servers

Copy directly between servers without putting private keys on either server
or giving one server unrestricted access to your SSH agent. Your machine
authorizes the copy and shows the results; the file data bypasses it.

```sh
# Copy the contents of hostA's big directory into hostB's big directory.
syq cp --from hostA --srcs-in big --to hostB --into big
```

```text
Your machine ── authorizes the copy and displays results
                       │
                    hostA ───── file data ─────▶ hostB
```

HostA gets permission for this transfer only. HostB checks that permission
and reports what it changed. See [Security](security.md#a-compromised-source-server)
for what this protects against.

## Start a copy from the source server

If your laptop has a [return connection](receive.md) to the source server,
you can inspect files in any server shell and send them to another SSH host:

```sh
# Run on hostA, including in an existing tmux shell.
ls -lh results
syq cp results --to hostB --via @laptop --into /archive
```

The laptop asks for approval before contacting hostB. Approve with the desktop
prompt or `syq recv pending` and `syq recv approve REQUEST_ID` on the laptop.
These requests require a decision even when `recv --approve always` permits
automatic copies onto the laptop itself. `--via laptop` also works; both forms
require a live return connection and never fall back to an SSH host named laptop.

The laptop uses its own SSH configuration, credentials, and trusted host keys
to connect to hostB and install the matching syq helper. Connect to hostB with
ordinary SSH from the laptop first if its host key is not yet trusted. The
source server receives no SSH credentials or agent access. The control stream
passes through the laptop; file data goes directly from hostA to hostB over
encrypted TCP. HostB must expose a [reachable data port](server-tuning.md#make-tcp-reachable)
to hostA. Failure to reach it fails the copy without switching to SSH data.

The prompt shows the requested SSH endpoint and destination path. Relative
destination paths start in that account's home directory on hostB. Receiving
`--cwd` and `--root` govern copies onto the laptop; they do not describe hostB's
filesystem. Receiving byte, entry, and deletion ceilings still apply. The
helper on hostB checks the approved copy permissions and protects its own
control and SSH authority files. The source verifies its signed receipt before
reporting success. No durable receiver enrollment or reusable grant is created.

All three machines must use the same syq build. Keep the source command and
the laptop's return connection alive until completion. Stopping receiving or
losing that connection cancels the copy. Retry with a new approval to resume
eligible partial files. This route accepts local sources and an ordinary SSH
`--to` endpoint. It does not accept `--detach`, custom `--rsh`/`--syq-path`,
`--no-bootstrap`, `--pscope`, alternative `--peer-auth`/`--coordinate-at`,
`--no-tcp`, or `--tcp-plain`. Copy permissions and supported filesystem options
match [return copies](receive.md#copy-permissions-and-limits).

## What you need

- SSH access from your machine to both servers, with their host keys already
  trusted. Connect with ordinary SSH once if either server is new to you.
- An SSH agent on your machine, and OpenSSH 8.9 or newer on your machine,
  hostA's SSH client, and hostB's SSH server.
- A [reachable TCP data port](server-tuning.md#make-tcp-reachable) on hostB,
  normally in `47600–47699`. This direct mode cannot send data over SSH instead.
- An existing parent directory for the destination.

Keep your command running until the copy finishes. Use native `syq cp`;
`syq rsync` does not accept two remote endpoints.

## First copy and access management

The first copy sets up a restricted receiver on hostB automatically. It adds
a restricted key to `authorized_keys`; the private key stays on your machine.
Later copies reuse this setup.

To prepare `/archive` on hostB ahead of time, including before a dry run:

```sh
syq receiver enroll hostB:/archive
syq cp --dry-run -v --from hostA --srcs-in data --to hostB --into /archive
```

Inspect or remove this access with:

```sh
syq receiver list
syq receiver revoke ID
```

Use the ID from `list`. Revocation blocks new sessions; an ongoing copy may
finish. If your machine reaches hostB through hostA, add `--via hostA` to
`enroll` or `revoke`.

## Mirror a directory

Include a deletion limit when pruning:

```sh
syq cp --prune --max-delete 100 --from hostA --srcs-in data --to hostB --into-existing /archive
```

This updates `/archive` and removes extras. If more than 100 removals are
planned, none are performed and the command exits 25. Preview first with
`--dry-run -v`.

## Other routes and authentication

If the servers cannot connect directly, relay through your machine:

```sh
syq cp --coordinate-at local --from hostA --srcs-in data --to hostB --into /archive
```

This uses your machine's bandwidth and ordinary SSH access to each endpoint.
Syq never switches to it silently.

Other authentication modes can use server-held credentials, a destination-
restricted SSH agent, or full agent forwarding. They grant different authority;
see the [advanced reference](remote-reference.md) before choosing one.
That page also covers detached copies, signed results, and direct-mode limits.
