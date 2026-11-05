//go:build linux

package platform

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPrivateFIFORefusedWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pipe")
	if e := syscall.Mkfifo(p, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := ReadPrivate(p); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO read blocked before file-kind refusal")
	}
}
