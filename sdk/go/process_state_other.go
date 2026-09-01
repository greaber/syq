//go:build !unix

package syq

import "os"

func terminationSignal(_ *os.ProcessState) os.Signal {
	return nil
}
