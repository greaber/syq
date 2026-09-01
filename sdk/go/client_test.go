package syq

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const fakeSyq = `#!/bin/sh
case "$1" in
  --version)
    printf 'syq 9.8.7\n'
    ;;
  emit)
    printf '%s' "$2"
    printf 'diagnostic' >&2
    ;;
  fail)
    printf 'partial'
    printf 'failed' >&2
    exit 23
    ;;
  term)
    kill -TERM "$$"
    ;;
  wait)
    exec sleep 30
    ;;
  *)
    exit 2
    ;;
esac
`

func fakeExecutable(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("syq does not currently publish a Windows executable")
	}
	path := filepath.Join(t.TempDir(), "syq")
	if err := os.WriteFile(path, []byte(fakeSyq), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersion(t *testing.T) {
	client := Client{Executable: fakeExecutable(t)}
	version, err := client.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "9.8.7" {
		t.Fatalf("got version %q", version)
	}
}

func TestRunPreservesOneArgumentWithShellMetacharacters(t *testing.T) {
	client := Client{Executable: fakeExecutable(t)}
	argument := "a path; $(not-a-command)"
	result, err := client.Run(context.Background(), "emit", argument)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != argument {
		t.Fatalf("got stdout %q", result.Stdout)
	}
	if string(result.Stderr) != "diagnostic" {
		t.Fatalf("got stderr %q", result.Stderr)
	}
}

func TestNonzeroResultIsRetained(t *testing.T) {
	client := Client{Executable: fakeExecutable(t)}
	result, err := client.Run(context.Background(), "fail")
	var processError *ProcessError
	if !errors.As(err, &processError) {
		t.Fatalf("got error %v", err)
	}
	if result.ExitCode != 23 || processError.Result.ExitCode != 23 {
		t.Fatalf("got exit status %d", result.ExitCode)
	}
	if string(result.Stdout) != "partial" {
		t.Fatalf("got stdout %q", result.Stdout)
	}
	if string(result.Stderr) != "failed" {
		t.Fatalf("got stderr %q", result.Stderr)
	}
}
