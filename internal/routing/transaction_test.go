package routing

import (
	"encoding/json"
	"errors"
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

// TestTransactionWriteFailurePreservesOriginal pins the txAtomicReplace
// error-propagation fix: a chmod or write failure after the temporary exists
// must abort BEFORE the rename — never publish a truncated file and report
// success. The write path is forced to fail partway through the payload.
func TestTransactionWriteFailurePreservesOriginal(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	saved := txTempWrite
	t.Cleanup(func() { txTempWrite = saved })

	tx, err := beginFileTransaction(scope, "test-writefail", false)
	if err != nil {
		t.Fatal(err)
	}
	// The seam is active for the publication only; the rollback below must
	// run through the real write path.
	txTempWrite = func(temporary *os.File, mode os.FileMode, data []byte) error {
		if len(data) > 2 {
			if _, err := temporary.Write(data[:len(data)/2]); err != nil {
				return err
			}
		}
		return errors.New("forced write failure")
	}
	publishErr := tx.writeBytes(target, []byte("replacement content"), 0600)
	txTempWrite = saved
	if publishErr == nil {
		t.Fatal("forced write failure reported as success")
	}
	if readTxFile(t, target) != "original" {
		t.Fatal("destination modified despite write failure")
	}
	// The abandoned temporary is gone; only the configuration remains.
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.yaml" {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("temporary litter after write failure: %v", names)
	}
	// The transaction rolls back cleanly (nothing was published).
	if err := tx.rollback(true); err != nil {
		t.Fatalf("rollback after write failure: %v", err)
	}
	if readTxFile(t, target) != "original" {
		t.Fatal("original content lost")
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("journals retained after clean rollback: %v", entries)
	}
}

// TestRollbackRefusesDirectoryAtCreatedFilePath pins the foreign-contents
// hardening: when a directory replaces a file this transaction created after
// the crash, the drift preflight cannot speak to it (it only guards regular
// files), so rollback must REFUSE and retain the journal rather than
// recursively deleting the directory's contents.
func TestRollbackRefusesDirectoryAtCreatedFilePath(t *testing.T) {
	scope := txScope(t)
	// A path inside directories the transaction itself has to create, so
	// the record carries CreatedDirs as well.
	target := filepath.Join(scope.ConfigRoot, "mihomo", "extra", "config.yaml")
	tx, err := beginFileTransaction(scope, "test-dirreplaced", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("candidate"), 0600); err != nil {
		t.Fatal(err)
	}
	// Crash, then a foreign directory replaces the created file.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(target, "foreign.txt")
	writeTxFile(t, canary, "precious", 0600)

	mustCode(t, recoverTransactions(scope, false), "rollback-failed")
	if data, err := os.ReadFile(canary); err != nil || string(data) != "precious" {
		t.Fatalf("foreign contents destroyed: %v %q", err, data)
	}
	if entries := backupsEntries(t, scope); len(entries) == 0 {
		t.Fatal("refused rollback dropped the journal")
	}
}

// TestRollbackRefusesDirectoryAtSymlinkPath is the symlink-restore variant,
// reached where such records can actually occur: journal-driven recovery
// (the engine's own delete refuses symlink destinations, so a symlink record
// only arrives as journal input). A directory that replaced the journaled
// symlink's path after the crash is foreign, and restoring the symlink must
// refuse instead of deleting it recursively.
func TestRollbackRefusesDirectoryAtSymlinkPath(t *testing.T) {
	scope := txScope(t)
	link := filepath.Join(scope.ConfigRoot, "mihomo", "link.yaml")
	if err := os.Symlink(filepath.Join(filepath.Dir(scope.StateRoot), "victim"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Crash leaves a pending journal whose delete record restored a symlink;
	// afterwards a foreign directory replaces the link's path.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(link, 0700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(link, "foreign.txt")
	writeTxFile(t, canary, "precious", 0600)
	root := filepath.Join(scope.StateRoot, "backups", "test-linkdir-abcdef012345")
	if err := platform.PrivateDir(root); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"id": "test-linkdir-abcdef012345", "name": "test-linkdir", "state": "pending",
		"staging": "",
		"journal": []map[string]any{{
			"op": "delete", "path": link, "type": "symlink",
			"mode": "605", "symlink_target": filepath.Join(filepath.Dir(scope.StateRoot), "victim"),
		}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.AtomicWrite(filepath.Join(root, "journal.json"), append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	mustCode(t, recoverTransactions(scope, false), "rollback-failed")
	if data, err := os.ReadFile(canary); err != nil || string(data) != "precious" {
		t.Fatalf("foreign contents destroyed: %v %q", err, data)
	}
	if entries := backupsEntries(t, scope); len(entries) == 0 {
		t.Fatal("refused rollback dropped the journal")
	}
}

// TestRecoveryPreflightsEveryDestinationBeforeUndo pins the multi-record
// ordering: the type preflight walks ALL journaled destinations BEFORE any
// record is undone. A foreign directory at the LAST record's path must stop
// the rollback before the FIRST record is reversed — otherwise recovery would
// trade a consistent crashed state for a half-undone one while still
// reporting a refusal.
func TestRecoveryPreflightsEveryDestinationBeforeUndo(t *testing.T) {
	scope := txScope(t)
	primary := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, primary, "original", 0600)
	tx, err := beginFileTransaction(scope, "test-driftgate", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(primary, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	secondary := filepath.Join(scope.DataRoot, "extra", "new-file")
	if err := tx.writeBytes(secondary, []byte("created"), 0600); err != nil {
		t.Fatal(err)
	}
	// Crash, then a foreign directory replaces the second record's path.
	if err := os.Remove(secondary); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(secondary, 0700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(secondary, "foreign.txt")
	writeTxFile(t, canary, "precious", 0600)

	mustCode(t, recoverTransactions(scope, false), "rollback-failed")
	// No record may have been undone before the refusal: the earlier
	// publication is still the live bytes (its backup restore never ran).
	if data := readTxFile(t, primary); data != "published" {
		t.Fatalf("earlier record was undone before the refusal: primary = %q", data)
	}
	if data, err := os.ReadFile(canary); err != nil || string(data) != "precious" {
		t.Fatalf("foreign contents destroyed: %v %q", err, data)
	}
	if entries := backupsEntries(t, scope); len(entries) == 0 {
		t.Fatal("refused rollback dropped the journal")
	}
}

// forgeJournal writes a journal document by hand under the backups root,
// simulating an attacker- or corruption-controlled recovery input.
func forgeJournal(t *testing.T, scope platform.Scope, directory, id, name, state, staging string) {
	t.Helper()
	root := filepath.Join(scope.StateRoot, "backups", directory)
	if err := platform.PrivateDir(root); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"id": id, "name": name, "state": state,
		"staging": staging, "journal": []map[string]any{},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.AtomicWrite(filepath.Join(root, "journal.json"), append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestRecoveryRefusesForgedJournalPaths pins the forged-journal threat: the
// journal's staging field and identifiers are untrusted input, and recovery
// must never delete anything outside the exact location beginFileTransaction
// can create — regardless of what the document claims.
func TestRecoveryRefusesForgedJournalPaths(t *testing.T) {
	canary := func(t *testing.T, scope platform.Scope) string {
		t.Helper()
		dir := filepath.Join(filepath.Dir(scope.StateRoot), "canary-"+filepath.Base(scope.StateRoot))
		if err := platform.PrivateDir(dir); err != nil {
			t.Fatal(err)
		}
		writeTxFile(t, filepath.Join(dir, "keep.txt"), "precious", 0600)
		return dir
	}
	cases := []struct {
		label     string
		directory string
		id        string
		canary    bool
		staging   func(t *testing.T, scope platform.Scope) string
	}{
		{
			label:     "arbitrary staging outside the state root",
			directory: "forged-abcdef012345",
			id:        "forged-abcdef012345",
			canary:    true,
			staging:   func(t *testing.T, scope platform.Scope) string { return canary(t, scope) },
		},
		{
			label:     "staging inside the state root but outside the staging root",
			directory: "forged-bcdef0123456",
			id:        "forged-bcdef0123456",
			staging: func(t *testing.T, scope platform.Scope) string {
				return filepath.Join(scope.DataRoot, "forged-bcdef0123456-x")
			},
		},
		{
			label:     "staging in the staging root with a foreign prefix",
			directory: "forged-cdef01234567",
			id:        "forged-cdef01234567",
			staging: func(t *testing.T, scope platform.Scope) string {
				return filepath.Join(scope.StateRoot, "staging", "other-label-1")
			},
		},
		{
			label:     "identifier shape violation",
			directory: "forged-CDEF01234567",
			id:        "forged-CDEF01234567",
			staging:   func(t *testing.T, scope platform.Scope) string { return "" },
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.label, func(t *testing.T) {
			scope := txScope(t)
			outside := testCase.staging(t, scope)
			forgeJournal(t, scope, testCase.directory, testCase.id, "forged", "committed", outside)
			err := recoverTransactions(scope, false)
			mustCode(t, err, "transaction-journal-invalid")
			if testCase.canary {
				if _, statErr := os.Lstat(filepath.Join(outside, "keep.txt")); statErr != nil {
					t.Fatalf("canary touched by refused journal: %v", statErr)
				}
			}
			// The refused journal is retained for inspection, never cleaned.
			if _, statErr := os.Lstat(filepath.Join(scope.StateRoot, "backups", testCase.directory, "journal.json")); statErr != nil {
				t.Fatalf("refused journal removed: %v", statErr)
			}
		})
	}
	// A symlink planted at the expected staging location must also be
	// refused, with the link target untouched.
	t.Run("symlinked staging directory", func(t *testing.T) {
		scope := txScope(t)
		victim := canary(t, scope)
		stagingRoot := filepath.Join(scope.StateRoot, "staging")
		if err := platform.PrivateDir(stagingRoot); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(stagingRoot, "forged-def012345678-1")
		if err := os.Symlink(victim, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		forgeJournal(t, scope, "forged-def012345678", "forged-def012345678", "forged", "committed", link)
		err := recoverTransactions(scope, false)
		mustCode(t, err, "transaction-journal-invalid")
		if _, statErr := os.Lstat(filepath.Join(victim, "keep.txt")); statErr != nil {
			t.Fatalf("symlink target touched: %v", statErr)
		}
	})
}

// TestCheckPendingPredicate covers the read-only predicate behind
// platform.CheckPending: completed transactions leave nothing pending, a
// crashed pending journal surfaces as transaction-recovery-required, and the
// predicate neither recovers nor mutates anything by itself.
func TestCheckPendingPredicate(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)

	// A completed transaction leaves nothing pending behind.
	tx, err := beginFileTransaction(scope, "test-hook", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("committed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.commit(); err != nil {
		t.Fatal(err)
	}
	if pending, err := pendingRoutingTransactions(scope); err != nil || pending {
		t.Fatalf("pending after commit = %v err = %v", pending, err)
	}
	if err := platform.CheckPending(scope); err != nil {
		t.Fatalf("CheckPending after commit: %v", err)
	}

	// Crash with a pending journal: the published file is uncommitted state.
	tx, err = beginFileTransaction(scope, "test-hook", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if pending, err := pendingRoutingTransactions(scope); err != nil || !pending {
		t.Fatalf("pending after crash = %v err = %v", pending, err)
	}
	if err := platform.CheckPending(scope); err == nil || platform.SafeError(err) != "transaction-recovery-required" {
		t.Fatalf("CheckPending after crash = %v", err)
	}
	// The predicate is read-only: the journal and the uncommitted state are
	// still exactly as the crash left them.
	if readTxFile(t, target) != "pending" {
		t.Fatal("pending predicate mutated the uncommitted state")
	}

	// Explicit recovery clears the pending state for the next reader: the
	// last committed content ("committed") comes back.
	if err := recoverTransactions(scope, false); err != nil {
		t.Fatal(err)
	}
	if readTxFile(t, target) != "committed" {
		t.Fatal("recovery did not restore the pre-transaction content")
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("recovery retained journals: %v", entries)
	}
	if err := platform.CheckPending(scope); err != nil {
		t.Fatalf("CheckPending after recovery: %v", err)
	}
}
