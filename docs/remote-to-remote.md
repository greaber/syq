# Copy between servers

Copy directly between servers without copying your private keys to either server
or giving one server unrestricted access to your SSH agent. Your machine
authorizes the copy and shows the results, but the file data doesn't pass
through it.

Most copies need only the first section. The others cover starting a copy in
a server's shell, and what to do when the servers can't connect directly.

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

<a id="mirror-a-directory"></a>

Most copy options work as usual, including `--prune` to mirror a directory;
see [Limits and unsupported options](remote-reference.md#limits-and-unsupported-options)
for the exceptions.

### What you need

- SSH access from your machine to both servers. HostA checks hostB's host key
  with its own SSH configuration; see
  [how hostA checks hostB's key](security.md#how-hosta-checks-hostbs-key).
- A login to hostB with an SSH key your machine can sign with: a key in your
  SSH agent, or a key file without a passphrase. Password and multi-factor
  logins cannot authorize these copies.
- OpenSSH 7.2 or newer on hostB, with a writable `~/.ssh/authorized_keys`.
- Direct SSH connectivity from hostA to hostB; a `ProxyJump` or
  `ProxyCommand` in hostA's configuration is not used. Copies are faster when
  hostA can also reach a TCP data port on hostB; see
  [Make TCP reachable](server-tuning.md#make-tcp-reachable).
- An existing parent directory for the destination.
- A hostB login other than root.

### First copy and access management

The first copy to your hostB account sets up restricted copying there, using
your usual SSH login: it adds one line to hostB's `~/.ssh/authorized_keys` whose
key can only start syq's receiver, and installs syq in `~/.local/lib/syq`.
After that, your machine signs each copy with the key you log in with, and
hostB checks the signature before writing anything.

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

Use the ID from `list`. Revoking stops active copies for that enrollment and
removes its access; completed writes remain. See
[Enrollment](remote-reference.md#enrollment) for which keys can sign and what
to do when you change keys.

If your machine cannot reach hostB, a copy tries again through hostA; for
`enroll` or `revoke`, add `--via hostA`.

<a id="start-a-copy-from-the-source-server"></a>

## Run the copy from a server

When you're working in the source server's shell, you can start the copy
there and have your laptop authorize it; see
[Authorize copies between servers](receive.md#authorize-copies-between-servers).

To copy between two other servers from a third one, have your laptop approve
the copy:

```sh
syq cp --from hostB --srcs-in data --to hostC --into /archive --auth-from @laptop
```

Your laptop asks once. The first copy sets up restricted copying on both
servers, as a copy started on your laptop does. HostB then runs the copy and
sends file data directly to hostC; the server you started it on gets no other
access to either account. The copy stops if you interrupt the command, and it
needs nothing more from your laptop once it starts. An
[SSH authorization provider](receive.md#use-an-ssh-authorization-provider)
can approve it instead, with `--auth-from` and the provider's SSH address. See
[Copies between two other servers](remote-reference.md#copies-between-two-other-servers)
for requirements.

## Other routes and authentication

Syq never silently relays file data through your machine when the servers
cannot connect directly. To relay explicitly:

```sh
syq cp --coordinate-at local --from hostA --srcs-in data --to hostB --into /archive
```

This sends the data through your machine, using its bandwidth and your usual
SSH logins to both servers.

Other ways to authenticate use credentials kept on a server, an SSH agent
restricted to the destination, or full agent forwarding. Each grants different
authority; see the [Remote copy reference](remote-reference.md) before
choosing one. That page also covers detached copies, results from the
destination, and limits on direct copies.
