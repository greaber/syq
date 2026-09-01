//go:build unix

package syq

import (
	"os"
	"syscall"
)

func terminationSignal(state *os.ProcessState) os.Signal {
	waitStatus, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !waitStatus.Signaled() {
		return nil
	}
	return waitStatus.Signal()
}
