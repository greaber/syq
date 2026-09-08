<h1 class="landing-title" id="copy-files-with-syq" aria-label="syq: Fast, programmable file operations">
<span class="landing-wordmark">syq</span>
<span class="landing-subtitle">Fast, programmable file operations.</span>
</h1>

Copy, reorganize and remove files—locally or across machines. Resume interrupted
transfers, send files to your laptop or run commands there from a server’s
remote shell, and use syq from scripts or Python. Your laptop needs no SSH
server or incoming network port.

<nav class="landing-actions" aria-label="Explore syq">
<a class="landing-primary" href="install.html">Install syq</a>
<a href="https://greaber.github.io/syq-bench/">Benchmarks ↗</a>
<a href="receive.html">Send files to your laptop</a>
<a href="exec.html">Run commands on your laptop</a>
<a href="remote-to-remote.html">Copy between servers</a>
<a href="mappings.html">Rename and reorganize files during a copy</a>
<a href="automation.html">Use syq from scripts</a>
<a href="python.html">Use syq from Python</a>
</nav>

## Try a copy

Replace `server` with an SSH hostname or alias you normally connect to,
and `project` with a local directory:

```sh
syq cp project --to server --into backup
```

This creates or updates `backup/project` in your home directory on the server.
To copy the contents of `project` directly into `backup`, use `--srcs-in`:

```sh
syq cp --srcs-in project --to server --into backup
```

Use `--dry-run` to preview a summary without copying, or `--dry-run -v`
to list the planned changes by path.
Existing destination files are updated when needed. Unrelated files stay
unless you request `--prune`.

## Already use rsync?

Start with your usual command, prefixed by `syq`:

```sh
syq rsync -av project/ server:backup/project/
syq rsync -av server:data/ ./data/
```

Syq supports common rsync options, but uses its own protocol. Rsync filter
rules, hard links, ACLs, xattrs, sparse files, and rolling-checksum deltas
are not supported. Check [rsync compatibility](rsync-compat.md) before
substituting it in an existing script.

## Common tasks

| I want to… | Start here |
|---|---|
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
