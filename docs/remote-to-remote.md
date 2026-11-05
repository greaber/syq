# Copy between servers

Copy directly between servers without copying your private keys to either server
or giving one server unrestricted access to your SSH agent. Your machine
authorizes the copy and shows the results; the file data bypasses it.

## Run the copy from your laptop

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
and reports what it changed. See [A compromised source server](security.md#a-compromised-source-server)
for what this protects against. Keep the command on your laptop running until
the copy finishes; the copy stops if it ends.

### What you need

- SSH access from your machine to both servers. HostA checks hostB's host key
  with its own SSH configuration; see
  [how hostA checks hostB's key](security.md#how-hosta-checks-hostbs-key).
- A login to hostB with an SSH key your machine can sign with: a key in your
  SSH agent, or a key file without a passphrase. Password and multi-factor
  logins cannot authorize these copies.
- OpenSSH 7.2 or newer on hostB, with a writable `~/.ssh/authorized_keys`.
- SSH connectivity from hostA to hostB. Copies are faster when hostA can also
  reach a TCP data port on hostB; see [Make TCP reachable](server-tuning.md#make-tcp-reachable).
- An existing parent directory for the destination.
- A hostB login other than root.

### First copy and access management

The first copy to your hostB account sets up restricted copying there, using
your usual SSH login: it adds one line to hostB's `~/.ssh/authorized_keys` whose
key can only start syq's receiver, and installs syq in `~/.local/lib/syq`.
After that, your machine signs each copy with the key you log in with, and
hostB checks the signature before writing anything. With a FIDO key, each copy
needs one touch, and a copy that sets up or refreshes restricted copying needs
about three.

To set up hostB ahead of time, including before a dry run:

```sh
syq receiver enroll hostB
syq cp --dry-run -v --from hostA --srcs-in data --to hostB --into /archive
```

Inspect or remove this access with:

```sh
syq receiver list
syq receiver revoke ID
```

Use the ID from `list`. Revocation stops active copies for that enrollment
and removes its access; completed writes remain. See
[Enrollment](remote-reference.md#enrollment) for which keys can sign, key
changes, and updates. Enrollments made by syq 0.7.1 and earlier do not appear
in `list`; see [Enrollments from older versions](remote-reference.md#enrollments-from-older-versions)
to remove them.

Setting up and revoking log in to hostB the way your SSH configuration routes
`ssh` there. If that cannot connect, a copy started on your machine tries
again through hostA; for `enroll` or `revoke`, add `--via hostA`.

<a id="start-a-copy-from-the-source-server"></a>

## Run the copy from a server

You can also start a copy in the source server's shell and use your laptop's
SSH credentials to authorize it. This uses a receiving connection from your
laptop; see [Authorize copies between servers](receive.md#authorize-copies-between-servers)
for setup, approval, and connectivity requirements.

From a third server, first request reusable account access to both endpoints:

```sh
syq persist connect hostB --auth-from @laptop
syq persist connect hostC --auth-from @laptop
syq cp --from hostB --srcs-in data --to hostC --into /archive --auth-from @laptop
```

Approve each account on the laptop. The requesting server has full access to
those accounts while the approvals remain open. HostB receives only permission
for the current copy to hostC, and file data goes directly from hostB to hostC.
Keep the copy and the laptop's receiving connection open until it finishes.

HostB's SSH server must allow remote Unix-socket forwarding, and on OpenSSH
7.8 and later remote TCP forwarding too. Copying over SSH needs a writable
`~/.ssh/authorized_keys` on hostC. See
[Approved account copies](remote-reference.md#approved-account-copies)
for option support.

## Mirror a directory

From your laptop:

```sh
syq cp --prune --max-delete 100 --from hostA --srcs-in data --to hostB --into-existing /archive
```

This updates `/archive` and removes extras. If more than 100 removals are
planned, none are performed and the command exits 25. Preview first with
`--dry-run -v`.

## Other routes and authentication

Syq never silently relays file data through your machine when the servers
cannot connect directly. To relay explicitly:

```sh
syq cp --coordinate-at local --from hostA --srcs-in data --to hostB --into /archive
```

This uses your machine's bandwidth and ordinary SSH access to each endpoint.

Other authentication modes can use server-held credentials, a destination-
restricted SSH agent, or full agent forwarding. They grant different authority;
see the [Remote copy reference](remote-reference.md) before choosing one.
That page also covers detached copies, results from the destination, and direct-mode limits.
