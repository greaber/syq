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

When an official syq release installs its matching helper in an SSH server's
cache, it also tries to install that version at `~/.local/bin/syq` for use on
the server. Reusing a cached helper does not run this installation step.

Any existing entry at `~/.local/bin/syq`, including a symlink, is left alone.
If you delete the command but leave its adjacent update receipt, later helper
installations leave it absent. Removing both allows automatic installation
again. A missing cached helper is recreated when needed, regardless of the
command or its receipt. Syq does not fetch a newer command or check for copies
elsewhere on your `PATH`.

New `.local` and `.local/bin` directories allow only their owner to write,
and respect stricter permissions from your umask. Existing directories must
be owned by your account or root and must not be world-writable. Existing
group-write permissions are accepted; directory permissions are not changed.

Syq reports installing this command, or failing to do so, unless `--quiet` is
set. Failure to install this command does not fail the transfer. Syq never
edits shell startup files. Ensure
`~/.local/bin` is on your shell's `PATH` to use the command. The command is an
independent copy of the helper, with filesystem cloning used when available.
It is registered for `syq --self-update`, which leaves the version-specific
helper cache unchanged. If registration fails, the notice explains how to
enable updates. Development builds and connections using `--syq-path` or
`--no-bootstrap` do not install the command.

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

New standalone installations keep their update receipt beside the executable
(`.syq-install.json` for `syq`). Existing receipts under the configured syq
configuration directory remain supported. Preferences still respect
`XDG_CONFIG_HOME`; changing it does not affect receipts beside executables.

Standalone installs check for updates at most once a day after a successful
command when stderr is a terminal and `--quiet` is not set. They print a
reminder when a newer release is available; nothing updates automatically.
Set `SYQ_NO_UPDATE_CHECK=1` to disable reminders.

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
