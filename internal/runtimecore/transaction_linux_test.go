//go:build linux

package runtimecore

import (
	"os"
	"path/filepath"
	"syscall"
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

// An in-place edit of the transaction's own published file keeps its object
// identity, so the identity proof cannot see it. The immediate rollback
// checks the content of every destination before it undoes anything — the
// same rule the crash recovery runs — and refuses instead of overwriting the
// edit with the recorded Before bytes. The refusal also comes before any
// other destination is undone, so the configuration never ends up mixed.
func TestImmediateRollbackRefusesAnInPlaceEdit(t *testing.T) {
	a := initializedApp(t)
	target := a.Scope.ManagerPath()
	other := filepath.Join(a.Scope.StateRoot, "other.json")
	before := []byte("original content")
	otherBefore := []byte("other original")
	if e := platform.AtomicWrite(target, before, 0600); e != nil {
		t.Fatal(e)
	}
	if e := platform.AtomicWrite(other, otherBefore, 0600); e != nil {
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
	otherPublished := []byte("other published")
	if e = platform.AtomicWrite(other, otherPublished, 0600); e != nil {
		t.Fatal(e)
	}
	object, e := platform.ObjectIdentity(target)
	if e != nil {
		t.Fatal(e)
	}
	// Another writer edits the FIRST-journaled file in place: the same
	// object, different bytes. The reverse-order undo would restore the
	// second file before it ever compared the edited one.
	editInPlaceRuntime(t, target, []byte("edited in place"))
	if edited, e := platform.ObjectIdentity(target); e != nil || edited != object {
		t.Fatal("the edit did not keep the published object's identity", e)
	}

	j := journal{Version: 1, Files: []fileSnapshot{
		{Path: target, Before: before, After: published, Existed: true, PrevObject: prev, PublishedObject: object},
		{Path: other, Before: otherBefore, After: otherPublished, Existed: true},
	}}
	e = restoreFiles(a, j)
	requireCode(t, e, "transaction-conflict")
	if raw, re := platform.ReadPrivate(target); re != nil || !bytesEqual(raw, []byte("edited in place")) {
		t.Fatal("the immediate rollback overwrote an in-place edit", re)
	}
	if raw, re := platform.ReadPrivate(other); re != nil || !bytesEqual(raw, otherPublished) {
		t.Fatal("the rollback restored a file before another one refused", re)
	}
}

// The same refusal protects a path the transaction created: the edited file
// must not be deleted as if it were still the transaction's untouched
// publication.
func TestImmediateRollbackRefusesAnInPlaceEditOnACreatedPath(t *testing.T) {
	a := initializedApp(t)
	target := filepath.Join(a.Scope.StateRoot, "created.json")
	created := []byte("created content")
	if e := platform.AtomicWrite(target, created, 0600); e != nil {
		t.Fatal(e)
	}
	object, e := platform.ObjectIdentity(target)
	if e != nil {
		t.Fatal(e)
	}
	editInPlaceRuntime(t, target, []byte("edited after creation"))
	if edited, e := platform.ObjectIdentity(target); e != nil || edited != object {
		t.Fatal("the edit did not keep the created object's identity", e)
	}

	j := journal{Version: 1, Files: []fileSnapshot{{Path: target, After: created, PublishedObject: object}}}
	e = restoreFiles(a, j)
	requireCode(t, e, "transaction-conflict")
	if raw, re := platform.ReadPrivate(target); re != nil || !bytesEqual(raw, []byte("edited after creation")) {
		t.Fatal("the immediate rollback deleted an in-place edit on the created path", re)
	}
}

// editInPlaceRuntime rewrites a file's bytes through the same inode, the way
// an editor or another writer that opened the path for writing would.
func editInPlaceRuntime(t *testing.T, path string, content []byte) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(content); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
}

// The snapshot loop binds the object it replaces with the same fail-closed
// rule as every other observation: a transient failure refuses the whole
// publication before the journal is written. Swallowing it would name the
// publication while leaving the object it replaces unnamed, and a crash in
// that window would wedge the recovery on the intact original forever.
func TestSnapshotIdentityFailureRefusesThePublication(t *testing.T) {
	a := initializedApp(t)
	target := a.Scope.ManagerPath()
	before := []byte("original content")
	if e := platform.AtomicWrite(target, before, 0600); e != nil {
		t.Fatal(e)
	}
	original := captureObjectIdentity
	t.Cleanup(func() { captureObjectIdentity = original })
	captureObjectIdentity = func(string) (string, error) {
		return "", &os.PathError{Op: "lstat", Path: target, Err: syscall.EIO}
	}
	_, e := applyFilesBinding(a, map[string][]byte{target: []byte("published")})
	if e == nil {
		t.Fatal("the publication was accepted with an unobservable identity")
	}
	captureObjectIdentity = original
	if _, re := os.Lstat(journalPath(a)); !os.IsNotExist(re) {
		t.Fatal("a journal was written for a refused publication", re)
	}
	if raw, re := platform.ReadPrivate(target); re != nil || !bytesEqual(raw, before) {
		t.Fatal("the untouched original was modified", re)
	}
}

// The compound snapshot refuses identically: no half-identified record.
func TestCompoundSnapshotIdentityFailureRefuses(t *testing.T) {
	a := initializedApp(t)
	target := a.Scope.ManagerPath()
	if e := platform.AtomicWrite(target, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	original := captureObjectIdentity
	t.Cleanup(func() { captureObjectIdentity = original })
	captureObjectIdentity = func(string) (string, error) {
		return "", &os.PathError{Op: "lstat", Path: target, Err: syscall.EIO}
	}
	_, e := snapshotCompoundFile(a, target, []byte("published"))
	if e == nil {
		t.Fatal("the compound snapshot accepted an unobservable identity")
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
