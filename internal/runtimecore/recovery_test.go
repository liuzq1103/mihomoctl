package runtimecore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestRuntimeRecoveryHookPendingIsReadOnlyAndPersistent(t *testing.T) {
	a := testApp(t)
	if pending, e := runtimePending(a.Scope); e != nil || pending {
		t.Fatal(pending, e)
	}
	for _, leaf := range []string{"transaction.json", "compound.json"} {
		path := filepath.Join(a.Scope.StateRoot, leaf)
		raw := []byte("incomplete private journal")
		if e := platform.AtomicWrite(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		pending, e := runtimePending(a.Scope)
		if e != nil || !pending {
			t.Fatal("hook missed persistent journal", pending, e)
		}
		requireCode(t, platform.CheckPending(a.Scope), "transaction-recovery-required")
		unchanged, e := platform.ReadPrivate(path)
		if e != nil || !bytesEqual(unchanged, raw) {
			t.Fatal("pending hook changed a journal", e)
		}
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
	}
}
