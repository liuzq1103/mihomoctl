//go:build linux

package routing

import (
	"os"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// fixtureRuntimeBinary stages the runtimecore-format state document naming
// this very test process as the managed core. The process genuinely owns the
// fixture controller's listening socket, so the /proc ownership proof the
// client runs on Linux succeeds exactly as it would against a managed core.
func fixtureRuntimeBinary(t *testing.T, a platform.App, configPath string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, err := inspectGoIdentity(os.Getpid())
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
	return exe
}
