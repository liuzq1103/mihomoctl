//go:build !linux

package routing

import (
	"net"
	"os"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// fixtureControllerListener returns a nil listener off Linux: httptest then
// binds its own, and no ownership proof runs there by design.
func fixtureControllerListener(t *testing.T) (net.Listener, *os.File) {
	t.Helper()
	return nil, nil
}

// fixtureRuntimeBinary is a no-op off Linux: the runtime ownership proof is
// skipped there by design, so no state document is needed.
func fixtureRuntimeBinary(t *testing.T, a platform.App, configPath string, f *fixtureServer) string {
	t.Helper()
	return "/nonexistent/mihomo"
}
