//go:build linux

package runtimecore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// The immediate rollback of a failed file transaction never undoes a foreign
// object. The recovery verifies every destination before it undoes anything;
// the in-process rollback that runs when a later publication fails owes the
// same protection, because a foreign replacement can arrive between the
// publication and the failure. The foreign file is created while the object
// it replaces is still standing, so it is a new object, not a recycled
// identity.
func TestImmediateRollbackRefusesForeignReplacement(t *testing.T) {
	a := initializedApp(t)
	target := a.Scope.ManagerPath()
	before := []byte("original content")
	if e := platform.AtomicWrite(target, before, 0600); e != nil {
		t.Fatal(e)
	}
	prev, e := platform.ObjectIdentity(target)
	if e != nil {
		t.Fatal(e)
	}
	published := []byte("published content")
	if e = platform.AtomicWrite(target, published, 0600); e != nil {
		t.Fatal(e)
	}
	object, e := platform.ObjectIdentity(target)
	if e != nil {
		t.Fatal(e)
	}
	j := journal{Version: 1, Files: []fileSnapshot{{Path: target, Before: before, After: published, Existed: true, PrevObject: prev, PublishedObject: object}}}
	// Positive control: the published object is still the one the journal
	// names, so the rollback restores the recorded original bytes.
	if e = restoreFiles(a, j); e != nil {
		t.Fatal(e)
	}
	if raw, re := platform.ReadPrivate(target); re != nil || !bytesEqual(raw, before) {
		t.Fatal("the rollback did not restore the original bytes", re)
	}

	// A foreign replacement takes the path while the published object is
	// gone; the rollback refuses instead of undoing it. The journal names
	// only the published object: it was alive while the replacement was
	// created, so the replacement's identity cannot match it, and no freed
	// identity can be spuriously re-acquired.
	if e = platform.AtomicWrite(target, published, 0600); e != nil {
		t.Fatal(e)
	}
	object2, e := platform.ObjectIdentity(target)
	if e != nil {
		t.Fatal(e)
	}
	replacement := target + ".foreign"
	if e = platform.AtomicWrite(replacement, published, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(replacement, target); e != nil {
		t.Fatal(e)
	}
	standing, e := platform.ObjectIdentity(target)
	if e != nil {
		t.Fatal(e)
	}
	if standing == object2 {
		t.Fatal("the replacement did not create a new object")
	}
	j = journal{Version: 1, Files: []fileSnapshot{{Path: target, Before: before, After: published, Existed: true, PublishedObject: object2}}}
	e = restoreFiles(a, j)
	requireCode(t, e, "transaction-conflict")
	if raw, re := platform.ReadPrivate(target); re != nil || !bytesEqual(raw, published) {
		t.Fatal("the immediate rollback overwrote a foreign replacement", re)
	}
}

// A path the transaction created is not deleted when a foreign object took
// it: the rollback refuses instead of removing an object it does not own.
func TestImmediateRollbackRefusesForeignObjectOnCreatedPath(t *testing.T) {
	a := initializedApp(t)
	target := filepath.Join(a.Scope.StateRoot, "created", "file")
	created := []byte("created content")
	if e := os.MkdirAll(filepath.Dir(target), 0700); e != nil {
		t.Fatal(e)
	}
	if e := platform.AtomicWrite(target, created, 0600); e != nil {
		t.Fatal(e)
	}
	object, e := platform.ObjectIdentity(target)
	if e != nil {
		t.Fatal(e)
	}
	// A foreign object replaces the file the transaction created.
	foreign := target + ".foreign"
	if e = platform.AtomicWrite(foreign, []byte("foreign content"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(foreign, target); e != nil {
		t.Fatal(e)
	}
	j := journal{Version: 1, Files: []fileSnapshot{{Path: target, After: created, PublishedObject: object}}}
	e = restoreFiles(a, j)
	requireCode(t, e, "transaction-conflict")
	if raw, re := platform.ReadPrivate(target); re != nil || !bytesEqual(raw, []byte("foreign content")) {
		t.Fatal("the immediate rollback deleted a foreign object on the created path", re)
	}
}
