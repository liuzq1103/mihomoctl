package delivery

import (
	"context"
	"path/filepath"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func init() {
	platform.RegisterRecovery("delivery", 30, recoverDeliveryScope, pendingDeliveryScope)
}

// The shared coordinator already holds the scope lock. These callbacks never
// acquire WithLock or call a public command.
func recoverDeliveryScope(ctx context.Context, scope platform.Scope) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	a := platform.App{Scope: scope}
	bootstrapping, e := optionalExists(bootstrapJournalPath(a))
	if e != nil {
		return e
	}
	removing, e := optionalExists(uninstallJournal(a))
	if e != nil {
		return e
	}
	updating, e := optionalExists(filepath.Join(installRoot(a), "pending.json"))
	if e != nil {
		return e
	}
	if (removing && updating) || (bootstrapping && (removing || updating)) {
		return fail("delivery-conflicting-journals")
	}
	if bootstrapping {
		return recoverBootstrap(a)
	}
	if removing {
		return recoverUninstall(a)
	}
	if updating {
		return recoverInstall(a)
	}
	return nil
}

func pendingDeliveryScope(scope platform.Scope) (bool, error) {
	a := platform.App{Scope: scope}
	for _, p := range []string{bootstrapJournalPath(a), uninstallJournal(a), filepath.Join(installRoot(a), "pending.json")} {
		exists, e := optionalExists(p)
		if e != nil {
			return false, e
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}
