package syq_test

import (
	"context"

	syq "github.com/greaber/syq/sdk/go"
)

func ExampleRun() {
	result, err := syq.Run(
		context.Background(),
		"cp", "project", "--to", "server", "--into", "/backup", "--dry-run",
	)
	if err != nil {
		// Handle the process error and inspect its retained result as needed.
		return
	}
	_ = result.Stdout
}
