//go:build !linux

package routing

import (
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// fixtureRuntimeBinary is a no-op off Linux: the runtime ownership proof is
// skipped there by design, so no state document is needed.
func fixtureRuntimeBinary(t *testing.T, a platform.App, configPath string) string {
	t.Helper()
	return "/nonexistent/mihomo"
}
