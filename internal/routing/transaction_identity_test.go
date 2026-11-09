//go:build unix || windows

package routing

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTransactionRecoveryRefusesForeignObjectWithIdenticalBytes pins the
// ownership invariant of the recovery: a pending transaction only undoes the
// objects it published. Identical bytes are not proof of ownership — a
// foreign replacement carrying the same content is a different object and
// must survive the recovery untouched.
func TestTransactionRecoveryRefusesForeignObjectWithIdenticalBytes(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "before crash", 0600)

	tx, err := beginFileTransaction(scope, "test-object", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("after publication"), 0600); err != nil {
		t.Fatal(err)
	}
	published, err := txObjectIdentity(target)
	if err != nil || published == "" {
		t.Fatalf("published object identity: %q %v", published, err)
	}
	// A foreign process replaces the published file with a new object that
	// carries exactly the same bytes.
	foreign := target + ".foreign"
	writeTxFile(t, foreign, "after publication", 0600)
	if err := os.Rename(foreign, target); err != nil {
		t.Fatal(err)
	}
	replacement, err := txObjectIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == published {
		t.Fatal("the replacement did not create a new object")
	}

	err = recoverTransactions(scope, false)
	mustCode(t, err, "transaction-current-drifted")
	if readTxFile(t, target) != "after publication" {
		t.Fatal("recovery overwrote a foreign replacement")
	}
	if entries := backupsEntries(t, scope); len(entries) != 1 {
		t.Fatalf("drifted journal was not retained: %v", entries)
	}
}

// TestTransactionRecoveryAcceptsIdenticalContentPublication pins the
// ambiguous case: a publication whose bytes equal the previous ones cannot be
// told apart by content, so both recorded objects stay candidates and the
// recovery still rolls the transaction back instead of refusing it.
func TestTransactionRecoveryAcceptsIdenticalContentPublication(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "same", 0600)

	tx, err := beginFileTransaction(scope, "test-same", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("same"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverTransactions(scope, false); err != nil {
		t.Fatalf("recovery refused an unambiguous transaction: %v", err)
	}
	if readTxFile(t, target) != "same" {
		t.Fatalf("content = %q", readTxFile(t, target))
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("recovery left journals behind: %v", entries)
	}
}

// TestTransactionJournalRecordsObjectIdentities pins the write-ahead record:// the journal names the object that was published before the rename, so the
// recovery can tell it apart from a replacement afterwards.
func TestTransactionJournalRecordsObjectIdentities(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "old", 0600)

	tx, err := beginFileTransaction(scope, "test-identity", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if len(tx.journal) != 1 {
		t.Fatalf("journal records = %d", len(tx.journal))
	}
	record := tx.journal[0]
	if record.PublishedObject == "" {
		t.Fatal("the published object identity was not journaled")
	}
	if record.PrevObject == "" {
		t.Fatal("the previous object identity was not journaled")
	}
	if record.PublishedObject == record.PrevObject {
		t.Fatal("the published and the previous object are the same")
	}
	current, err := txObjectIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	if current != record.PublishedObject {
		t.Fatalf("published object %q does not match the object at the path %q", record.PublishedObject, current)
	}
}

// TestTransactionRecoveryAcceptsItsOwnInterruptedRollback pins the recovery
// of a rollback that was interrupted after it restored a file. The restore
// writes a NEW object, so the journal has to name it: without that name the
// next recovery finds bytes it recognizes at an object it does not, and the
// transaction would be permanently blocked instead of being finished.
func TestTransactionRecoveryAcceptsItsOwnInterruptedRollback(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	tx, err := beginFileTransaction(scope, "test-interrupted", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash: the rollback restored the original bytes, but the
	// transaction was interrupted before it could finish, so the journal is
	// still pending and the restored object stands at the path.
	if err := tx.undoRecord(&tx.journal[0]); err != nil {
		t.Fatal(err)
	}
	if tx.journal[0].RestoredObject == "" {
		t.Fatal("the restored object identity was not journaled")
	}
	restored, err := txObjectIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	if restored != tx.journal[0].RestoredObject {
		t.Fatalf("restored object %q does not match the object at the path %q", tx.journal[0].RestoredObject, restored)
	}
	if readTxFile(t, target) != "original" {
		t.Fatalf("content = %q", readTxFile(t, target))
	}

	if err := recoverTransactions(scope, false); err != nil {
		t.Fatalf("recovery refused its own interrupted rollback: %v", err)
	}
	if readTxFile(t, target) != "original" {
		t.Fatalf("content = %q", readTxFile(t, target))
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("recovery left journals behind: %v", entries)
	}
}

// TestTransactionRecoveryRefusesForeignObjectAfterInterruptedRollback pins
// the other half of the same invariant: an interrupted rollback does not
// open the door to a foreign replacement. A file that carries the restored
// bytes but is a different object is still refused.
func TestTransactionRecoveryRefusesForeignObjectAfterInterruptedRollback(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	tx, err := beginFileTransaction(scope, "test-interrupted-foreign", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.undoRecord(&tx.journal[0]); err != nil {
		t.Fatal(err)
	}
	// A foreign process replaces the restored file with a new object that
	// carries exactly the same bytes.
	foreign := target + ".foreign"
	writeTxFile(t, foreign, "original", 0600)
	if err := os.Rename(foreign, target); err != nil {
		t.Fatal(err)
	}
	replacement, err := txObjectIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == tx.journal[0].RestoredObject {
		t.Fatal("the replacement did not create a new object")
	}

	err = recoverTransactions(scope, false)
	mustCode(t, err, "transaction-current-drifted")
	if readTxFile(t, target) != "original" {
		t.Fatal("recovery overwrote a foreign replacement")
	}
	if entries := backupsEntries(t, scope); len(entries) != 1 {
		t.Fatalf("drifted journal was not retained: %v", entries)
	}
}
