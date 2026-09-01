// Package syq provides safe subprocess access to the syq executable.
package syq

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf8"
)

// Client selects the syq executable used for an invocation.
// An empty Executable uses syq from PATH.
type Client struct {
	Executable string
}

// Result is the complete result of one syq process.
type Result struct {
	Argv     []string
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// ProcessError reports a syq process that completed unsuccessfully.
type ProcessError struct {
	Result Result
	Err    error
}

func (e *ProcessError) Error() string {
	return fmt.Sprintf("syq exited with status %d", e.Result.ExitCode)
}

// Unwrap exposes the error returned by os/exec.
func (e *ProcessError) Unwrap() error {
	return e.Err
}

// Run invokes syq from PATH without a shell and captures its complete output.
func Run(ctx context.Context, args ...string) (Result, error) {
	return Client{}.Run(ctx, args...)
}

// Run invokes the selected syq executable without a shell and captures its
// complete byte output.
func (c Client) Run(ctx context.Context, args ...string) (Result, error) {
	executable := c.Executable
	if executable == "" {
		executable = "syq"
	}
	argv := make([]string, 1, len(args)+1)
	argv[0] = executable
	argv = append(argv, args...)

	command := exec.CommandContext(ctx, executable, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := Result{
		Argv:     argv,
		ExitCode: -1,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
	}
	if command.ProcessState != nil {
		result.ExitCode = command.ProcessState.ExitCode()
	}
	if err == nil {
		return result, nil
	}
	if _, ok := err.(*exec.ExitError); ok {
		return result, &ProcessError{Result: result, Err: err}
	}
	return result, fmt.Errorf("start syq: %w", err)
}

// Version returns the version reported by syq --version from PATH.
func Version(ctx context.Context) (string, error) {
	return Client{}.Version(ctx)
}

// Version returns the version reported by the selected syq executable.
func (c Client) Version(ctx context.Context) (string, error) {
	result, err := c.Run(ctx, "--version")
	if err != nil {
		return "", err
	}
	if !utf8.Valid(result.Stdout) {
		return "", fmt.Errorf("syq --version did not return UTF-8")
	}
	output := strings.TrimSpace(string(result.Stdout))
	const prefix = "syq "
	if !strings.HasPrefix(output, prefix) || len(output) == len(prefix) {
		return "", fmt.Errorf("unexpected syq --version output: %q", output)
	}
	return strings.TrimPrefix(output, prefix), nil
}
