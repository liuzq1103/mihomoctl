package routing

import (
	"context"
	"os"
	"path/filepath"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// The routing transaction journal participates in the shared scope-lock
// recovery protocol: every authorized mutation under platform.WithLock
// replays abandoned routing journals first — before the mutation and before
// any other module's journals of a later order — and read-only commands
// surface pending recovery through platform.CheckPending instead of
// publishing uncommitted state as truth.
func init() {
	platform.RegisterRecovery("routing-transactions", 10, recoverRoutingTransactions, pendingRoutingTransactions)
}

// recoverRoutingTransactions replays abandoned transaction journals under
// the shared lock before any module mutation. recoverTransactions never
// takes the lock itself: WithLock already holds it and flock is not
// reentrant across file descriptors.
func recoverRoutingTransactions(ctx context.Context, scope platform.Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return recoverTransactions(scope, scope.System)
}

// pendingRoutingTransactions is the read-only predicate behind
// platform.CheckPending: it reports whether the scope owns a recovery
// directory — pending or completed-but-uncleaned — without recovering,
// creating, or modifying anything.
func pendingRoutingTransactions(scope platform.Scope) (bool, error) {
	entries, err := os.ReadDir(filepath.Join(scope.StateRoot, "backups"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, controllerFileError(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return true, nil
		}
	}
	return false, nil
}
