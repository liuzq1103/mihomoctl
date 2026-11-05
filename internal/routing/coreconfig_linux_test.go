//go:build linux

package routing

import (
	"path/filepath"
	"syscall"
	"testing"
)

// TestReadCoreConfigRefusesFIFOWithoutHanging pins the FIFO hardening: a
// named pipe squatting on the configuration path is refused as a non-regular
// file. The open itself must not block waiting for a writer.
func TestReadCoreConfigRefusesFIFOWithoutHanging(t *testing.T) {
	scope := txScope(t)
	fifo := filepath.Join(scope.ConfigRoot, "mihomo", "config.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	_, _, err := readCoreConfig(fifo, false)
	if err == nil {
		t.Fatal("FIFO accepted as a configuration")
	}
	mustCode(t, err, "controller-path-must-be-private-owned-regular")
}
