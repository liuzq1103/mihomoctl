//go:build unix || windows

package routing

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// replaceWithForeignObject replaces the file at path with a new object that
// carries the given bytes but none of the identities named in forbidden.
// Every object that ever stands at the path is pinned by a hard link first: a
// rename over the path frees the standing object's inode, and the next
// allocation can hand it — or any journal identity freed earlier — straight
// back, which would let the loop oscillate between the journal's own
// identities forever. Pinning keeps every candidate alive, so the allocator
// must eventually produce an identity the journal does not name. These tests
// pin refusals, not the allocator's luck.
func replaceWithForeignObject(t *testing.T, path, content string, forbidden ...string) string {
	t.Helper()
	for attempt := 0; ; attempt++ {
		pinned := fmt.Sprintf("%s.pinned%d", path, attempt)
		if err := os.Link(path, pinned); err != nil {
			t.Fatal(err)
		}
		foreign := fmt.Sprintf("%s.foreign%d", path, attempt)
		writeTxFile(t, foreign, content, 0600)
		if err := os.Rename(foreign, path); err != nil {
			t.Fatal(err)
		}
		object, err := txObjectIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		fresh := true
		for _, named := range forbidden {
			if object == named {
				fresh = false
				break
			}
		}
		if fresh {
			return object
		}
		if attempt > 8 {
			t.Fatalf("could not replace %s with an object the journal does not name (last: %s)", path, object)
		}
	}
}

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
	replaceWithForeignObject(t, target, "after publication", tx.journal[0].PrevObject, tx.journal[0].PublishedObject)

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

// TestTransactionJournalRecordsObjectIdentities pins the write-ahead record:
// the journal names the object that was published before the rename, so the
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

// TestTransactionRecoveryKeepsTheRestoredObjectItAlreadyPublished pins the
// repeated-interruption case. A recovery that finds its own restored object at
// the path has to finish the transaction instead of restoring a second time: a
// second restore would publish a new object and overwrite the only record of
// the first one, so the next recovery would find bytes it recognizes at an
// object it does not know and refuse the transaction forever.
func TestTransactionRecoveryKeepsTheRestoredObjectItAlreadyPublished(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	tx, err := beginFileTransaction(scope, "test-repeat-interrupted", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.undoRecord(&tx.journal[0]); err != nil {
		t.Fatal(err)
	}
	restored, err := txObjectIdentity(target)
	if err != nil {
		t.Fatal(err)
	}

	if err := recoverTransactions(scope, false); err != nil {
		t.Fatalf("recovery refused its own interrupted rollback: %v", err)
	}
	after, err := txObjectIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	if after != restored {
		t.Fatalf("the recovery published the object %q instead of keeping the restored one %q", after, restored)
	}
	if readTxFile(t, target) != "original" {
		t.Fatalf("content = %q", readTxFile(t, target))
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("recovery left journals behind: %v", entries)
	}
}

// TestTransactionRecoveryRefusesAReplacedBackup pins the integrity of the
// journal's own dependencies. The backup file is where a rollback reads the
// bytes it publishes, so the journal records the content it wrote there. A
// backup that was replaced after the crash must not decide what is written
// over the user's configuration.
func TestTransactionRecoveryRefusesAReplacedBackup(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	tx, err := beginFileTransaction(scope, "test-replaced-backup", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	if tx.journal[0].BackupSHA256 == "" {
		t.Fatal("the backup content was not journaled")
	}
	backup := tx.journal[0].Backup
	if backup == "" {
		t.Fatal("the journal names no backup")
	}
	// A foreign process replaces the backup file with different bytes.
	writeTxFile(t, backup, "replaced", 0600)

	err = recoverTransactions(scope, false)
	mustCode(t, err, "rollback-failed")
	if readTxFile(t, target) != "published" {
		t.Fatalf("the recovery published a replaced backup: %q", readTxFile(t, target))
	}
	if entries := backupsEntries(t, scope); len(entries) != 1 {
		t.Fatalf("the refused journal was not retained: %v", entries)
	}
}

// TestLiveRollbackRefusesForeignReplacement pins the ownership invariant on
// the live rollback path: a transaction whose later operation fails rolls
// back in this process, and the crash recovery's destination verification
// does not run first. A foreign replacement that arrived between the
// publication and the failure is not overwritten with the backup, and a
// foreign object on a path the transaction created is not deleted.
func TestLiveRollbackRefusesForeignReplacement(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)
	created := filepath.Join(scope.ConfigRoot, "mihomo", "created.yaml")

	tx, err := beginFileTransaction(scope, "test-live-foreign", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(created, []byte("new file"), 0600); err != nil {
		t.Fatal(err)
	}
	// Foreign processes replace the published object and take the created
	// path while the transaction is still live. The replacement at the
	// published path is built to name none of the journal identities: the
	// published object is still standing, but the previous one was freed by
	// the publication and could otherwise be handed back. The foreign file
	// on the created path is created while the object it replaces is still
	// standing, and that object is the only identity its record names.
	replaceWithForeignObject(t, target, "published", tx.journal[0].PrevObject, tx.journal[0].PublishedObject)
	taken := created + ".foreign"
	writeTxFile(t, taken, "foreign content", 0600)
	if err := os.Rename(taken, created); err != nil {
		t.Fatal(err)
	}

	err = tx.rollback(true)
	mustCode(t, err, "rollback-failed")
	if readTxFile(t, target) != "published" {
		t.Fatal("the live rollback overwrote a foreign replacement")
	}
	if readTxFile(t, created) != "foreign content" {
		t.Fatal("the live rollback deleted a foreign object on the created path")
	}
	if entries := backupsEntries(t, scope); len(entries) != 1 {
		t.Fatalf("the failed rollback did not retain the journal: %v", entries)
	}
}

// TestLiveRollbackUndoesRepeatedPublicationsOfOnePath pins the multi-record
// shape of one path: a transaction that publishes the same path twice undoes
// BOTH publications on its live rollback. The second undo publishes a new
// object the first record never named — the journal names it, through the
// later record — so the ownership check must accept every object the journal
// names at the path through any of its records; refusing the transaction's
// own intermediate object would leave a journal that fails identically on
// every retry and wedge the scope.
func TestLiveRollbackUndoesRepeatedPublicationsOfOnePath(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	tx, err := beginFileTransaction(scope, "test-republish", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	if len(tx.journal) != 2 {
		t.Fatalf("journal records = %d", len(tx.journal))
	}
	if err := tx.rollback(true); err != nil {
		t.Fatalf("rollback refused its own repeated publication: %v", err)
	}
	if readTxFile(t, target) != "original" {
		t.Fatalf("content = %q", readTxFile(t, target))
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("rollback left journals behind: %v", entries)
	}
}

// TestRecoveryUndoesRepeatedPublicationsOfOnePath pins the crash shape of the
// same transaction: a crash after the second publication leaves the second
// published object standing, and the recovery rolls both publications back to
// the original bytes instead of wedging on an object the first record does
// not name.
func TestRecoveryUndoesRepeatedPublicationsOfOnePath(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	tx, err := beginFileTransaction(scope, "test-republish-crash", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash: the transaction never committed, so its pending
	// journal is all that stands.
	if err := recoverTransactions(scope, false); err != nil {
		t.Fatalf("recovery refused a repeated publication: %v", err)
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
	// carries exactly the same bytes and none of the identities the journal
	// names.
	record := &tx.journal[0]
	replacement := replaceWithForeignObject(t, target, "original", record.PrevObject, record.PublishedObject, record.RestoredObject)

	err = recoverTransactions(scope, false)
	mustCode(t, err, "transaction-current-drifted")
	if readTxFile(t, target) != "original" {
		t.Fatal("recovery overwrote a foreign replacement")
	}
	standing, err := txObjectIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	if standing != replacement {
		t.Fatal("recovery replaced the foreign object")
	}
	if entries := backupsEntries(t, scope); len(entries) != 1 {
		t.Fatalf("drifted journal was not retained: %v", entries)
	}
}
