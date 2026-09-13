# Install

Syq runs on Linux and macOS, on x86-64 and ARM64.

## Standalone installer

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Installs into `~/.local/bin` without `sudo`. Make sure that directory is on your
`PATH`. To choose another directory, download the script and run
`sh install.sh --bin-dir DIR`.

## Automatic installation on SSH servers

When an official syq release installs its helper on an SSH server, it also
tries to install the same version at `~/.local/bin/syq` for use on that server.
Existing files and symlinks there are left alone; shell startup files are
never edited. Syq reports installation or failure unless `--quiet` is set.
Shell completion and background connections can also trigger installation,
without printing a notice. Failure to install this command does not stop the
transfer.

Use `syq --self-update` on the server to update this command. Its installation
receipt is `~/.local/bin/.syq-install.json`. If you delete the command but leave
the receipt, syq leaves it absent. Remove both files to allow installation the
next time a helper is installed. Removing the command does not prevent helper
setup.

Reusing a cached helper does not repeat this installation step. Development
builds and connections using `--syq-path` or `--no-bootstrap` do not install
the command.

## Homebrew

```sh
brew install greaber/tap/syq
```

## Try a benchmark

Compare syq with rsync on your own machines, or with rsync and cp locally:

```sh
curl --proto '=https' --tlsv1.2 -fLsS https://raw.githubusercontent.com/greaber/syq/master/scripts/try-benchmark.sh | bash
```

The default sends 1,024 small throwaway files to an SSH host you choose and
compares syq with rsync over three rounds, following an untimed tuning warm-up
(`--warmup off` skips it). Local copies, large files, and
automatic sizing are optional. The script checks the copied contents and cleans up afterward.
If syq is missing, it offers to install it. See [quick comparison](speed.md#quick-comparison)
to download the script and run it again.

<figure class="benchmark-example">
<table>
<caption>Published example: Germany → US East Coast</caption>
<thead><tr><th scope="col">Tool</th><th scope="col">Average speed</th></tr></thead>
<tbody>
<tr><th scope="row">syq</th><td>159.1 MB/s</td></tr>
<tr><th scope="row">syq over SSH</th><td>87.2 MB/s</td></tr>
<tr><th scope="row">rsync</th><td>18.0 MB/s</td></tr>
</tbody>
</table>
<figcaption>One 1.07 GB file, held in memory at both ends; three runs per tool.
From the separate <a href="https://greaber.github.io/syq-bench/all-results.html#public-wan-forward">syq-bench project</a>,
which provides more extensive benchmarks. Your results will depend on your machines and connection.</figcaption>
</figure>

## Updates

Use `syq --self-update` for a standalone installation, or `brew upgrade syq`
for Homebrew.

Self-update uses an installation receipt, usually `.syq-install.json` beside
the executable. Keep this file so syq can recognize the installation.

Standalone installs may print update reminders in a terminal; nothing updates
automatically. Set `SYQ_NO_UPDATE_CHECK=1` to disable reminders.

## Shell completion

Add the line for your shell to its startup file:

```bash
# Bash (~/.bashrc)
eval "$(syq completion bash)"

# Zsh (~/.zshrc), after autoload -Uz compinit && compinit
source <(syq completion zsh)

# fish (~/.config/fish/config.fish)
syq completion fish | source
```

Completion suggests options, hosts, and paths, with file details beside path
matches. In Bash, press Tab again to list matches. Remote paths use your usual
SSH login. Open a new shell after adding the setup line or upgrading syq.

## Keep connections open

Keep an SSH connection ready for repeated copies:

```sh
syq persist connect server
```

This enables persistence and connects without copying files. It also lets you
[send files back from the server](receive.md), with approval on your machine.
Connections stay open until you close them with `syq persist off`.
Use `syq persist status` to see them.

See [background connections](receive.md#background-connections) for reconnecting,
turning receiving off, and using persistence in scripts.
