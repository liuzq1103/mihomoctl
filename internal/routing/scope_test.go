package routing

import (
	"os"
	"testing"
)

// The product refuses a root process that mutates the user scope, so the
// user-scope fixtures cannot run as root. The CI root pass covers the system
// scope; the non-root pass covers these fixtures.
func skipUserScopeAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root may not mutate the user scope; the non-root CI pass covers this fixture")
	}
}
