//go:build linux

package routing

import (
	"context"
	"fmt"
	"os"
	"testing"
)

// TestDebugControllerOwnership prints every input of the controller ownership
// proof from inside the real fixture flow. Debug-only instrument for the
// ci-debug branch; never part of a release candidate.
func TestDebugControllerOwnership(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	fmt.Printf("DBG fixture port=%d\n", f.port())
	mgr, e := os.ReadFile(a.Scope.ManagerPath())
	fmt.Printf("DBG manager=%q err=%v\n", string(mgr), e)
	st, e := os.ReadFile(a.Scope.RuntimeState())
	fmt.Printf("DBG state=%q err=%v\n", string(st), e)
	owner := newRuntimeOwner(a, managerDoc(a))
	fmt.Printf("DBG owner binary=%q config=%q statePath=%q backend=%q\n", owner.binary, owner.config, owner.statePath, owner.backend)
	id, err := owner.runningIdentity(context.Background())
	fmt.Printf("DBG runningIdentity err=%v idNil=%v\n", err, id == nil)
	if id != nil {
		fmt.Printf("DBG id=%+v\n", *id)
		now, e := inspectGoIdentity(id.PID)
		fmt.Printf("DBG now err=%v now=%+v\n", e, now)
		fmt.Printf("DBG identityAlive=%v\n", owner.identityAlive(id))
		fmt.Printf("DBG ownsLoopback=%v\n", ownsLoopback(id.PID, "127.0.0.1", f.port()))
	}
	env := runRequest(t, a, []string{"controller", "status"})
	fmt.Printf("DBG envelope overall=%s errors=%v\n", env.Overall, env.Errors)
	if env.Overall != "PASS" {
		t.Fatalf("see DBG diagnostics above")
	}
}
