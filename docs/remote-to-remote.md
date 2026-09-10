# Copy between servers

Copy directly between servers without putting private keys on either server
or giving one server unrestricted access to your SSH agent. Your machine
authorizes the copy and shows the results; the file data bypasses it.

```sh
# Copy the contents of hostA's big directory into hostB's big directory.
syq cp --from hostA --srcs-in big --to hostB --into big
```

<figure class="transfer-flow" aria-label="Your machine authorizes the copy and displays results. File data goes directly from hostA to hostB.">
<div class="flow-machine"><strong>Your machine</strong><span>Authorize · see results</span></div>
<div class="flow-control" aria-hidden="true">│</div>
<div class="flow-data"><div class="flow-machine"><strong>hostA</strong><span>Source</span></div><div class="flow-arrow"><span>File data</span><b aria-hidden="true">⟶</b></div><div class="flow-machine"><strong>hostB</strong><span>Destination</span></div></div>
<figcaption>The files travel directly between the servers.</figcaption>
</figure>

HostA gets permission for this transfer only. HostB checks that permission
and reports what it changed. See [Security](security.md#a-compromised-source-server)
for what this protects against.

## Start a copy from the source server

If your laptop has a [return connection](receive.md) to the source server,
you can inspect files in any server shell and send them to another SSH host:

```sh
# Run on hostA, including in an existing tmux shell.
ls -lh results
syq cp results --to hostB --into /archive
```

Syq uses the first available receiving machine in alphabetical name order.
If none is available, or the requested options are unsupported on this route,
it uses hostA's SSH access. A copy addressed to a live receiving name goes to
that machine itself.

Use `--auth-from @laptop` to choose your laptop explicitly, or `--auth-from ssh`
to use hostA's SSH access. The default is `--auth-from auto`. `--via @NAME` is
an alias for choosing a receiving machine. See
[authorization selection](remote-reference.md#authorization-selection) for
name rules and route restrictions.

The selected laptop asks for approval before contacting hostB. Approve with the desktop
prompt or `syq persist receive pending` and `syq persist receive approve REQUEST_ID` on the laptop.
These requests require a decision even when `persist receive on --approve always` permits
automatic copies onto the laptop itself. Once an approval request is sent,
a refusal, interrupted connection, setup failure, or copy failure ends that
attempt; syq does not try another authorizer or SSH. Explicit receiving names
require a live return connection and never fall back to DNS lookup.

The laptop uses its own SSH configuration, credentials, and trusted host keys
to connect to hostB and install the matching syq helper. Connect to hostB with
ordinary SSH from the laptop first if its host key is not yet trusted. The
source server receives no SSH credentials or agent access. The control stream
passes through the laptop; file data goes directly from hostA to hostB over
encrypted TCP. HostB must expose a [reachable data port](server-tuning.md#make-tcp-reachable)
to hostA. Failure to reach it fails the copy without switching to SSH data.

The prompt shows the requested SSH endpoint and destination path. Relative
paths start in that account's home directory on hostB. Your laptop's receiving
root does not contain this copy, but its byte, entry, and deletion limits still
apply.

Keep the source command and your laptop's connection alive until completion.
Stopping receiving or losing that connection cancels the copy. Retry with a
new approval to resume it. Supported copy options match
[return copies](receive.md#copy-permissions-and-limits), with additional
[route restrictions](remote-reference.md#authorization-selection).

## What you need

- SSH access from your machine to both servers, with their host keys already
  trusted. Connect with ordinary SSH once if either server is new to you.
- An SSH agent on your machine, and OpenSSH 8.9 or newer on your machine,
  hostA's SSH client, and hostB's SSH server.
- SSH connectivity from hostA to hostB. A [reachable TCP data port](server-tuning.md#make-tcp-reachable)
  on hostB, normally in `47600–47699`, enables encrypted TCP workers. Otherwise
  the copy uses SSH workers on the same hostA-to-hostB route. `--no-tcp` selects
  SSH directly.
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

Use the ID from `list`. Revocation stops all active restricted receivers for
that enrollment and blocks new sessions. It waits for their shutdown before
reporting success, then removes the enrollment from both machines. Other
enrollments keep running. Revocation does not undo completed writes; interrupted
copies fail and can leave partial files. Enroll again to authorize a new copy
that can resume them.

If receivers have not stopped within ten seconds, revocation reports failure
and keeps the enrollment marked revoked. Retry `receiver revoke` to finish
cleanup; an enrollment with unfinished revocation cannot be refreshed.

For upgrading or sharing a receiver between installations, see
[enrollment details](remote-reference.md#enrollment).

If your machine reaches hostB through hostA, add `--via hostA` to `enroll` or
`revoke`.

## Mirror a directory

Include a deletion limit when pruning:

```sh
syq cp --prune --max-delete 100 --from hostA --srcs-in data --to hostB --into-existing /archive
```

This updates `/archive` and removes extras. If more than 100 removals are
planned, none are performed and the command exits 25. Preview first with
`--dry-run -v`.

## Other routes and authentication

Syq may switch between encrypted TCP and SSH on the selected route. It never
silently relays file data through your machine when a direct connection fails.
If the servers cannot connect directly, explicitly relay through your machine:

```sh
syq cp --coordinate-at local --from hostA --srcs-in data --to hostB --into /archive
```

This uses your machine's bandwidth and ordinary SSH access to each endpoint.
Syq never switches to it silently.

Other authentication modes can use server-held credentials, a destination-
restricted SSH agent, or full agent forwarding. They grant different authority;
see the [advanced reference](remote-reference.md) before choosing one.
That page also covers detached copies, signed results, and direct-mode limits.
