package platform

import (
	"context"
	"sort"
	"sync"
)

type recoveryHook struct {
	Name    string
	Order   int
	Recover func(context.Context, Scope) error
	Pending func(Scope) (bool, error)
}

var recoveryRegistry = struct {
	sync.RWMutex
	hooks []recoveryHook
}{}

// RegisterRecovery connects independently owned journals to the shared scope
// lock. Hooks run before every mutation, including mutations in other modules.
// Registration happens only during package initialization.
func RegisterRecovery(name string, order int, recover func(context.Context, Scope) error, pending func(Scope) (bool, error)) {
	recoveryRegistry.Lock()
	defer recoveryRegistry.Unlock()
	for _, h := range recoveryRegistry.hooks {
		if h.Name == name {
			panic("duplicate recovery hook")
		}
	}
	recoveryRegistry.hooks = append(recoveryRegistry.hooks, recoveryHook{name, order, recover, pending})
	sort.SliceStable(recoveryRegistry.hooks, func(i, j int) bool { return recoveryRegistry.hooks[i].Order < recoveryRegistry.hooks[j].Order })
}
func hooks() []recoveryHook {
	recoveryRegistry.RLock()
	defer recoveryRegistry.RUnlock()
	return append([]recoveryHook{}, recoveryRegistry.hooks...)
}
func recoverAll(ctx context.Context, s Scope) error {
	for _, h := range hooks() {
		if h.Recover != nil {
			if e := h.Recover(ctx, s); e != nil {
				return e
			}
		}
	}
	return nil
}

// CheckPending is read-only: a reader never publishes uncommitted state as
// runtime truth. The next explicitly authorized mutation performs recovery.
func CheckPending(s Scope) error {
	for _, h := range hooks() {
		if h.Pending != nil {
			p, e := h.Pending(s)
			if e != nil {
				return e
			}
			if p {
				return Usage("transaction-recovery-required")
			}
		}
	}
	return nil
}
