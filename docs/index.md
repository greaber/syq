<h1 class="landing-title" id="copy-files-with-syq" aria-label="syq: Fast, programmable file transfer">
<span class="landing-wordmark">syq</span>
<span class="landing-subtitle">Fast, programmable file transfer.</span>
</h1>

Copy, reorganize, and remove files across local filesystems, remote machines,
and [S3-compatible storage](object-storage.md). Choose which files to copy and
where they should land, preview the changes, and rerun interrupted copies to resume.

<nav class="landing-actions" aria-label="Explore syq">
<a class="landing-primary" href="install.html">Install syq</a>
<a href="https://greaber.github.io/syq-bench/">Benchmarks ↗</a>
<a href="receive.html">Send files to your laptop</a>
<a href="exec.html">Run commands on your laptop</a>
<a href="remote-to-remote.html">Copy directly between servers without forwarding your SSH agent</a>
<a href="mappings.html">Rename and reorganize files during a copy</a>
<a href="automation.html">Structured results</a>
<a href="python.html">Python SDK</a>
</nav>

## Try a copy

Start with a local directory named `project`. The same copy can go to a local
folder, an SSH server, or an S3 bucket:

```sh
syq cp project --into backup
syq cp project --to server --into backup
syq cp project --to s3://backups --into backup
```

Each command puts `project` inside `backup`. Replace `server` with an SSH
hostname or alias you normally use, or `backups` with an existing bucket.
A relative SSH destination starts in your home directory on that server.
See [S3 setup](object-storage.md#s3-options) for credentials and other providers.

`--from` and `--to` choose the source and destination machines or buckets.
Without them, paths are local. `--into` puts selected names inside a directory;
`--as` chooses an exact destination name.

To copy the contents of `project` directly into `backup`, use `--srcs-in`:

```sh
syq cp --srcs-in project --to server --into backup
```

Use `--dry-run` to preview a summary without copying, or `--dry-run -v`
to list the planned changes by path.
Existing destination files are updated when needed. Unrelated files stay
unless you request `--prune`.

<a id="already-use-rsync"></a>

## Start with a tool you know

{{#include assets/tool-examples.html}}

## Put syq in your workflow

Scripts can [choose files and destination names](mappings.md), preview a copy
with `--dry-run`, and read [structured results](automation.md).
The [Python SDK](python.md) provides copy and removal calls with typed results.

Working in a server shell? [Send files to your laptop](receive.md) or
[run a command there](exec.md), with approval on your laptop. It needs no SSH
server or incoming network port. You can also [copy directly between servers](remote-to-remote.md)
without forwarding your SSH agent.

## Common tasks

| I want to… | Start here |
|---|---|
| Look up commands and options | [Command reference](commands/index.md) |
| Choose exactly where files land | [Copy and placement](reference.md) |
| Preview changes | [Dry runs](reference.md#preview-changes) |
| Skip build files or use `.gitignore` | [Ignoring paths](reference.md#ignoring-paths) |
| Mirror a directory | [Mirroring](reference.md#mirror-a-directory) |
| Remove files in parallel | [Removal](remove.md) |
| Send files to my laptop from a server’s shell | [Receiving files](receive.md) |
| Run a build or open an artifact on my desktop from a server | [Commands on your receiving machine](exec.md) |
| Copy between two servers | [Remote-to-remote transfers](remote-to-remote.md) |
| Rename or reorganize files during a copy | [Mappings](mappings.md) |
| Use syq from Python | [Python SDK](python.md) |
| Read results from a script | [Automation results](automation.md) |
| Make copies faster | [Speed](speed.md) |
