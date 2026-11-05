package routing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// txScope builds a private scope whose managed roots live under a temporary
// directory, with a helper to read files back.
func txScope(t *testing.T) platform.Scope {
	t.Helper()
	root := privateTempDir(t)
	scope := platform.Scope{
		Name:        "user",
		ConfigRoot:  filepath.Join(root, "config"),
		DataRoot:    filepath.Join(root, "data"),
		StateRoot:   filepath.Join(root, "state"),
		CacheRoot:   filepath.Join(root, "cache"),
		RuntimeRoot: filepath.Join(root, "state", "runtime"),
	}
	if err := platform.PrivateDir(filepath.Join(scope.ConfigRoot, "mihomo")); err != nil {
		t.Fatal(err)
	}
	if err := platform.PrivateDir(scope.DataRoot); err != nil {
		t.Fatal(err)
	}
	return scope
}

func writeTxFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := platform.AtomicWrite(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func readTxFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func backupsEntries(t *testing.T, scope platform.Scope) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(scope.StateRoot, "backups"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestTransactionCommitPublishes(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "old", 0600)

	tx, err := beginFileTransaction(scope, "test-commit", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(scope.StateRoot, "created", "note.txt")
	if err := tx.writeBytes(created, []byte("side"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.commit(); err != nil {
		t.Fatal(err)
	}
	if readTxFile(t, target) != "new" || readTxFile(t, created) != "side" {
		t.Fatal("committed content missing")
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("committed transaction left recovery data: %v", entries)
	}
	if _, err := os.Stat(tx.staging); !os.IsNotExist(err) {
		t.Fatal("staging survived commit")
	}
}

func TestTransactionRollbackAfterPublication(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	tx, err := beginFileTransaction(scope, "test-rollback", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(scope.DataRoot, "fresh", "tree", "file")
	if err := tx.writeBytes(created, []byte("new file"), 0600); err != nil {
		t.Fatal(err)
	}
	// Fault injected after both publications.
	if err := tx.rollback(true); err != nil {
		t.Fatal(err)
	}
	if readTxFile(t, target) != "original" {
		t.Fatalf("target = %q, rollback did not restore", readTxFile(t, target))
	}
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Fatal("created file survived rollback")
	}
	if _, err := os.Stat(filepath.Dir(created)); !os.IsNotExist(err) {
		t.Fatal("created directory survived rollback")
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("rolled-back transaction left recovery data: %v", entries)
	}
}

func TestTransactionDeleteRollback(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "keep me", 0600)

	tx, err := beginFileTransaction(scope, "test-delete", false)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := tx.delete(target, "")
	if err != nil || !removed {
		t.Fatalf("delete = %v %v", removed, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("delete did not remove the file")
	}
	if err := tx.rollback(true); err != nil {
		t.Fatal(err)
	}
	if readTxFile(t, target) != "keep me" {
		t.Fatal("rollback did not restore the deleted file")
	}
}

func TestTransactionDeleteMarkerRefusal(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "foreign.txt")
	writeTxFile(t, target, "unrelated", 0600)

	tx, err := beginFileTransaction(scope, "test-marker", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.delete(target, "managed-by-mihomoctl:"); err == nil {
		t.Fatal("foreign file deleted without the managed marker")
	} else {
		mustCode(t, err, "refuse-delete")
	}
	if readTxFile(t, target) != "unrelated" {
		t.Fatal("refused delete touched the file")
	}
}

func TestTransactionRefusesUnsafeDestinations(t *testing.T) {
	scope := txScope(t)
	tx, err := beginFileTransaction(scope, "test-destinations", false)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(privateTempDir(t), "elsewhere.txt")
	if err := tx.writeBytes(outside, []byte("x"), 0600); err == nil {
		t.Fatal("destination outside managed roots accepted")
	} else {
		mustCode(t, err, "destination-outside-managed-roots")
	}

	directory := filepath.Join(scope.DataRoot, "adirectory")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(directory, []byte("x"), 0600); err == nil {
		t.Fatal("directory destination accepted")
	} else {
		mustCode(t, err, "refuse-non-file-destination")
	}

	link := filepath.Join(scope.DataRoot, "link.txt")
	writeTxFile(t, filepath.Join(scope.DataRoot, "real.txt"), "real", 0600)
	if err := os.Symlink(filepath.Join(scope.DataRoot, "real.txt"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := tx.writeBytes(link, []byte("x"), 0600); err == nil {
		t.Fatal("symlink destination accepted")
	} else {
		mustCode(t, err, "refuse-symlink-destination")
	}
}

// TestTransactionCrashRecovery simulates a process crash between publication
// and commit: the pending write-ahead journal must roll the file back on the
// next operation.
func TestTransactionCrashRecovery(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "before crash", 0600)

	tx, err := beginFileTransaction(scope, "test-crash", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("after publication"), 0600); err != nil {
		t.Fatal(err)
	}
	// Crash: neither commit nor rollback runs. The journal stays pending.

	if err := recoverTransactions(scope, false); err != nil {
		t.Fatal(err)
	}
	if readTxFile(t, target) != "before crash" {
		t.Fatalf("crash recovery left %q", readTxFile(t, target))
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("recovery left journals behind: %v", entries)
	}
}

// TestTransactionRecoveryRefusesManualDrift pins the safety valve: a pending
// journal is only replayed when the published bytes are still exactly what
// the transaction wrote (or its backup); a manual edit afterwards wins.
func TestTransactionRecoveryRefusesManualDrift(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "before crash", 0600)

	tx, err := beginFileTransaction(scope, "test-drift", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("after publication"), 0600); err != nil {
		t.Fatal(err)
	}
	// An operator edits the file after the crash, before recovery.
	writeTxFile(t, target, "manual edit", 0600)

	err = recoverTransactions(scope, false)
	mustCode(t, err, "transaction-current-drifted")
	// The manual edit is preserved and the journal is retained for inspection.
	if readTxFile(t, target) != "manual edit" {
		t.Fatal("recovery overwrote a manual edit")
	}
	if entries := backupsEntries(t, scope); len(entries) != 1 {
		t.Fatalf("drifted journal was not retained: %v", entries)
	}
}

func TestTransactionRecoversCommittedJournalsByCleanup(t *testing.T) {
	scope := txScope(t)
	tx, err := beginFileTransaction(scope, "test-committed", false)
	if err != nil {
		t.Fatal(err)
	}
	// Crash after the committed state was persisted but before cleanup.
	if err := tx.persist("committed"); err != nil {
		t.Fatal(err)
	}
	if err := recoverTransactions(scope, false); err != nil {
		t.Fatal(err)
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("committed journal retained: %v", entries)
	}
}

func TestTransactionJournalIsWriteAhead(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "old", 0600)

	tx, err := beginFileTransaction(scope, "test-wal", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	// The durable journal already describes the publication.
	raw, err := platform.ReadPrivate(filepath.Join(tx.backupRoot, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		ID      string     `json:"id"`
		State   string     `json:"state"`
		Journal []txRecord `json:"journal"`
	}
	if json.Unmarshal(raw, &document) != nil || document.ID != tx.id || document.State != "pending" {
		t.Fatalf("journal = %s", raw)
	}
	if len(document.Journal) != 1 || document.Journal[0].Op != "publish" ||
		document.Journal[0].PublishedSHA256 != hashSHA256([]byte("new")) ||
		document.Journal[0].Backup == "" {
		t.Fatalf("journal records = %+v", document.Journal)
	}
	// The backup holds the prior content.
	if readTxFile(t, document.Journal[0].Backup) != "old" {
		t.Fatal("backup does not hold prior content")
	}
}

// TestTransactionRecoversEmptyJournal pins the crash-between-begin-and-first-
// publish window: a journal with zero records is valid and cleans up instead
// of blocking every future transaction.
func TestTransactionRecoversEmptyJournal(t *testing.T) {
	scope := txScope(t)
	// Crash immediately after begin: the journal is pending with no records.
	if _, err := beginFileTransaction(scope, "test-empty", false); err != nil {
		t.Fatal(err)
	}
	if err := recoverTransactions(scope, false); err != nil {
		t.Fatalf("empty pending journal blocked recovery: %v", err)
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("empty journal retained: %v", entries)
	}
}
