//go:build linux

package runtimecore

import (
	"os"
	"testing"
)

// emulatedKernel reports whether this suite runs under CPU emulation. The
// emulated process group exposes no stable kernel start time, so the /proc
// ownership proof cannot be exercised there. The native amd64 job supplies
// that coverage; the arm64 gate states the gap instead of hiding it.
func emulatedKernel() bool {
	return os.Getenv("MIHOMOCTL_GO_TEST_EMULATED") == "1"
}

// skipEmulatedKernel marks the tests whose subject is the kernel ownership
// proof itself. They are skipped under emulation, where the kernel identity
// the proof binds to does not exist.
func skipEmulatedKernel(t *testing.T) {
	t.Helper()
	if emulatedKernel() {
		t.Skip("the emulated kernel exposes no stable process identity; the native amd64 job covers the ownership proof")
	}
}
