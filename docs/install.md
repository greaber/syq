# Install

Syq runs on Linux and macOS, on x86-64 and ARM64.

## Standalone installer

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Installs into `~/.local/bin` without `sudo`. Make sure that directory is on your
`PATH`. To choose another directory, download the script and run
`sh install.sh --bin-dir DIR`.

## Homebrew

```sh
brew install greaber/tap/syq
```

## Try a benchmark

Compare syq with rsync on your own machines, or with rsync and cp locally:

```sh
curl --proto '=https' --tlsv1.2 -fLsS https://raw.githubusercontent.com/greaber/syq/master/scripts/try-benchmark.sh | bash
```

Choose a local or SSH copy and a workload. The script automatically sizes
throwaway data with syq and cleans up afterward. No syq-bench install is needed;
if syq is missing, it offers to install it.

<figure class="benchmark-example">
<div class="benchmark-example-grid">
<section aria-label="Example benchmark choices">
<div class="visual-step">1 <span>Choose your test</span></div>
<dl class="benchmark-choices">
<dt>Copy where?</dt><dd>local</dd>
<dt>Workloads?</dt><dd>both</dd>
<dt>Test size</dt><dd>automatic by default</dd>
</dl>
<p class="visual-note">Results pictured: fixed-size sample<br>64 MiB + 1,024 files of 8 KiB</p>
</section>
<section aria-label="Example benchmark results">
<div class="visual-step">2 <span>Compare the results</span></div>
<table>
<caption>Mean MB/s · higher is faster · 3 trials</caption>
<thead><tr><th scope="col">Tool</th><th scope="col">Large file</th><th scope="col">Small files</th></tr></thead>
<tbody>
<tr><th scope="row">syq</th><td>710.0</td><td>50.1</td></tr>
<tr><th scope="row">rsync</th><td>567.3</td><td>71.1</td></tr>
<tr><th scope="row">cp</th><td>1379.1</td><td>160.4</td></tr>
</tbody>
</table>
<p class="visual-note">✓ Copied contents checked</p>
</section>
</div>
<figcaption>Speeds from a fixed-size local sample, not a speed promise. Your results will differ.</figcaption>
</figure>

For requirements, options and how to read the results, see
[the benchmark guide](speed.md#quick-comparison).

## Updates

Use `syq --self-update` for a standalone installation, or `brew upgrade syq`
for Homebrew.

Standalone installs print an update reminder; nothing updates automatically.
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
