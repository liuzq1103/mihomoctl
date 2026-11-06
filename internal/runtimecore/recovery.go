package runtimecore

import (
	"context"
	"os"
	"path/filepath"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func init() { platform.RegisterRecovery("runtimecore", 20, recoverScope, runtimePending) }

// The coordinator already owns the real scope lock. These callbacks must not
// acquire WithLock, call Run, or invoke any public helper which locks again.
func recoverScope(ctx context.Context, scope platform.Scope) error {
	a := platform.App{Scope: scope}
	if e := preventLockInheritance(a); e != nil {
		return e
	}
	if e := recoverCompound(ctx, a); e != nil {
		return e
	}
	return recoverTransaction(a)
}
func runtimePending(scope platform.Scope) (bool, error) {
	for _, leaf := range []string{"compound.json", "transaction.json"} {
		p := filepath.Join(scope.StateRoot, leaf)
		if e := platform.CheckPath(p); e != nil {
			return false, e
		}
		if _, e := os.Lstat(p); e == nil {
			return true, nil
		} else if !os.IsNotExist(e) {
			return false, e
		}
	}
	return false, nil
}
