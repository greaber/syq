# syq for Go

Package `syq` is the official preview Go adapter for the
[syq parallel file copier](https://github.com/greaber/syq). It invokes an
installed `syq` executable directly with an argument slice; it never constructs
a shell command and it does not download or install a binary.

The preview API intentionally offers raw execution and version discovery only.
A typed copy and event API will follow syq's versioned NDJSON automation
interface.

```go
package main

import (
    "context"
    "fmt"
    "log"

    syq "github.com/greaber/syq/sdk/go"
)

func main() {
    result, err := syq.Run(
        context.Background(),
        "cp", "project", "--to", "server", "--into", "/backup", "--dry-run",
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Print(string(result.Stdout))
}
```

`Run` returns a `*ProcessError` for a nonzero process status. The error retains
the complete result, including stdout and stderr as byte slices. A caller that
needs the status can use `errors.As` and inspect `ProcessError.Result`.
Signal termination is represented by an exit code of `-1` and a non-nil
`Signal`. If cancellation or a deadline terminated the process, `ContextError`
is also set and `errors.Is` matches it through `ProcessError`.

The `syq` executable must already be on `PATH`. Use `Client{Executable:
"/path/to/syq"}` to select an explicit binary.

This module currently targets Go 1.26 or newer on Linux and macOS.
