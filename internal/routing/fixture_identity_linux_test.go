//go:build linux

package routing

import (
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// fixtureControllerListener creates the fixture controller's loopback socket
// from a raw descriptor. The fixture then owns that descriptor and can hand a
// duplicate to a helper process without disturbing the test server's poller
// registration (Listener.File would evict the listener from the poller and
// leave the server blocked in accept).
func fixtureControllerListener(t *testing.T) (net.Listener, *os.File) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Listen(fd, 16); err != nil {
		t.Fatal(err)
	}
	if err = syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "fixture-controller-listener")
	l, err := net.FileListener(file)
	if err != nil {
		t.Fatal(err)
	}
	return l, file
}

// fixtureRuntimeBinary stages the runtimecore-format state naming a helper
// child process as the managed core. The child inherits the fixture
// controller's listening socket, so the /proc ownership proof the client runs
// on Linux succeeds exactly as it would against a managed core: a separate
// live process with its own kernel identity holds the listener descriptor.
// A helper child also keeps its identity decoupled from the test binary's
// own process, so the proof verifies a real foreign process rather than the
// verifier itself.
func fixtureRuntimeBinary(t *testing.T, a platform.App, configPath string, f *fixtureServer) string {
	t.Helper()
	core, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("helper process unavailable: %v", err)
	}
	cmd := exec.Command(core, "3600")
	if f.listenerFile != nil {
		// The duplicated descriptor is passed to the child only. The child
		// never reads it, so the fixture server keeps serving itself.
		cmd.ExtraFiles = []*os.File{f.listenerFile}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// The child's /proc identity (exe, argv) becomes visible only once its
	// exec has committed. The product's start path polls for the stable
	// identity (runtimecore process start); the fixture must do the same, or
	// it can record an empty argv in the window of a cold first exec and the
	// ownership proof then correctly fails as stale.
	deadline := time.Now().Add(5 * time.Second)
	self, err := inspectGoIdentity(cmd.Process.Pid)
	for err == nil && (self.Exe != core || len(self.Args) != 2 || self.Args[0] != core || self.Args[1] != "3600") {
		if time.Now().After(deadline) {
			t.Skipf("helper identity did not settle: %+v", self)
		}
		time.Sleep(10 * time.Millisecond)
		self, err = inspectGoIdentity(cmd.Process.Pid)
	}
	if err != nil {
		t.Skipf("kernel identity unavailable: %v", err)
	}
	state := map[string]any{
		"version":   1,
		"namespace": "mihomoctl-go",
		"scope":     a.Scope.Name,
		"config":    configPath,
		"home":      a.Scope.CoreHome(),
		"identity": map[string]any{
			"pid":        self.PID,
			"uid":        self.UID,
			"start_time": self.Start,
			"boot_id":    self.Boot,
			"exe":        self.Exe,
			"argv":       self.Args,
		},
	}
	if err := platform.WriteJSON(a.Scope.RuntimeState(), state); err != nil {
		t.Fatal(err)
	}
	return self.Exe
}
