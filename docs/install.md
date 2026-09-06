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
```

```fish
# fish (~/.config/fish/config.fish)
syq completion fish | source
```

## Keep connections open

Avoid repeated logins when running several network copies:

```sh
syq persist on
syq persist status
syq persist off
```

Persistence also enables [background receiving](receive.md) from the server
accounts syq connects to. Those accounts can send files to your home directory
automatically. Use `syq recv off` to keep only ordinary connection reuse, or
`syq recv on --root DIRECTORY` to contain receiving in an existing directory.

Ordinary SSH connections can stay reusable for up to ten minutes after your last command.
During that window, other processes running as your user can reuse the login
without another key touch or agent approval. Return connections stay available
until stopped. `persist off` closes both.
