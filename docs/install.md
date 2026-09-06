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

Path completion also shows file details. In Bash, press Tab again until the
match list appears (or press Alt+? to list matches directly). Zsh shows one
entry per line; fish shows details in its completion pager. Completing or
selecting an entry still inserts only its path.

The listing shows permissions, owner, group, human-readable file size, and
modification time in UTC. Symlinks include their targets. A directory's size
is shown as `—`: completion does not scan its contents or calculate tree totals.
Owner and group names come from the machine holding the files, with numeric
IDs when names are unavailable. Files that disappear or cannot be inspected
are marked `[metadata unavailable]`. If fetching details takes more than two
seconds after the names arrive, completion keeps the names and marks their
metadata unavailable.

Bash fetches metadata only when listing matches. Zsh and fish fetch it while
preparing their menus. Remote completion uses the same SSH login as copying;
connection persistence is optional. After upgrading, open a new shell or
source the completion adapter again to use the new display.

## Keep connections open

Avoid repeated logins when running several network copies:

```sh
syq persist on
syq persist status
syq persist off
```

Persistence also enables [background receiving](receive.md) from the server
accounts syq connects to. Incoming copies require approval on your machine;
the default destination is your home directory. Use `syq recv off` to keep only ordinary connection reuse, or
`syq recv on --root DIRECTORY` to contain receiving in an existing directory.

Ordinary SSH connections can stay reusable for up to ten minutes after your last command.
During that window, other processes running as your user can reuse the login
without another key touch or agent approval. Return connections stay available
until stopped. `persist off` closes both.
