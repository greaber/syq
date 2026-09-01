//go:build unix

package syq

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSignalTerminationIsRetained(t *testing.T) {
	client := Client{Executable: fakeExecutable(t)}
	result, err := client.Run(context.Background(), "term")
	var processError *ProcessError
	if !errors.As(err, &processError) {
		t.Fatalf("got error %v", err)
	}
	if result.ExitCode != -1 || result.Signal != syscall.SIGTERM {
		t.Fatalf("got exit code %d and signal %v", result.ExitCode, result.Signal)
	}
	if result.ContextError != nil {
		t.Fatalf("got context error %v", result.ContextError)
	}
	if !strings.Contains(err.Error(), "received signal terminated") {
		t.Fatalf("got error %q", err)
	}
}

func TestContextTerminationIsRetained(t *testing.T) {
	client := Client{Executable: fakeExecutable(t)}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := client.Run(ctx, "wait")
	var processError *ProcessError
	if !errors.As(err, &processError) {
		t.Fatalf("got error %v", err)
	}
	if result.ExitCode != -1 || result.Signal != syscall.SIGKILL {
		t.Fatalf("got exit code %d and signal %v", result.ExitCode, result.Signal)
	}
	if !errors.Is(result.ContextError, context.DeadlineExceeded) {
		t.Fatalf("got context error %v", result.ContextError)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("process error did not retain the context deadline: %v", err)
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("process error did not retain the os/exec error: %v", err)
	}
}
