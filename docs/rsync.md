# Use rsync-style commands

Use `syq rsync` for familiar rsync flags and source/destination syntax with
syq's transfer engine. It supports local copies, SSH pushes, and SSH pulls:

```sh
syq rsync -av project/ backup/project/
syq rsync -av project/ server:backup/project/
syq rsync -av server:project/ backup/project/
```

`-a` selects archive mode; `-v` lists files. A trailing slash on the source
copies the directory's contents. Without it, the directory itself is copied.

Add `-n` to preview a copy without changing source or destination files:

```sh
syq rsync -avn project/ server:backup/project/
```

Remote copies use syq's protocol and helper, installed automatically over SSH;
see [Automatic installation on SSH servers](install.md#automatic-installation-on-ssh-servers).
They cannot communicate with an rsync server or daemon. To copy between two
servers, use [native `syq cp`](remote-to-remote.md).

Before adapting an existing command or script, check
[Rsync compatibility](rsync-compat.md): some options are unsupported, and
filter rules and deletion limits differ. See [`syq rsync`](commands/rsync.md)
for all accepted options.
