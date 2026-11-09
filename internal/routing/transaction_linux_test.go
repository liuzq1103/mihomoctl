//go:build linux

package routing

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// txBackups lists the retained transaction journals of a scope.
func txBackups(t *testing.T, a platform.App) []string {
	t.Helper()
	return backupsEntries(t, a.Scope)
}

// TestLinuxWithLockHookRecoversJournals proves the shared recovery wiring:
// with the routing hook registered at init, a plain platform.WithLock —
// no routing code in the critical section — replays an abandoned journal
// before the mutation runs.
func TestLinuxWithLockHookRecoversJournals(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "original", 0600)
	tx, err := beginFileTransaction(scope, "test-hook", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	// Crash: no commit, no rollback, no explicit recoverTransactions.

	if err := platform.WithLock(context.Background(), scope, func() error { return nil }); err != nil {
		t.Fatalf("WithLock hook recovery failed: %v", err)
	}
	if readTxFile(t, target) != "original" {
		t.Fatal("hook recovery did not restore the pre-transaction content")
	}
	if entries := backupsEntries(t, scope); len(entries) != 0 {
		t.Fatalf("hook recovery retained journals: %v", entries)
	}
	if pending, err := pendingRoutingTransactions(scope); err != nil || pending {
		t.Fatalf("pending after hook recovery = %v err = %v", pending, err)
	}
	if err := platform.CheckPending(scope); err != nil {
		t.Fatalf("CheckPending after hook recovery: %v", err)
	}
}

// TestLinuxApplyPolicyAfterWriteFailureRollsBackAllFiles is the fault
// injection the durable-recovery requirement asks for: the configuration and
// an afterWrite provider file are already published when the hook fails.
// Both files must return to their prior bytes with no receipt and no leftover
// recovery data, and the hook's error must surface unchanged.
func TestLinuxApplyPolicyAfterWriteFailureRollsBackAllFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	_, manager, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		t.Fatal(err)
	}
	sideFile := filepath.Join(a.Scope.DataRoot, "provider-cache.yaml")

	_, err = applyPolicy(context.Background(), a, manager, configPath, a.Scope.CoreHome(),
		[]byte(linuxFreshConfig), []byte(linuxRoutedConfig),
		func(tx *fileTransaction) error {
			// The provider file publishes fine...
			if err := tx.writeBytes(sideFile, []byte("provider data"), 0600); err != nil {
				return err
			}
			// ...and then the hook fails after publication.
			return control("provider-write-failed", exitFail)
		})
	mustCode(t, err, "provider-write-failed")

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != linuxFreshConfig {
		t.Fatalf("config = %q, original not restored", raw)
	}
	if _, err := os.Lstat(sideFile); !os.IsNotExist(err) {
		t.Fatal("published provider file survived rollback")
	}
	if _, err := os.Lstat(receiptPath(configPath)); !os.IsNotExist(err) {
		t.Fatal("receipt survived rollback")
	}
	if entries := txBackups(t, a); len(entries) != 0 {
		t.Fatalf("rollback left recovery data: %v", entries)
	}
}

// TestLinuxApplyPolicyReceiptFailureRollsBack pins the semantics change the
// root flagged: a receipt failure is a hard rollback, never a warning.
func TestLinuxApplyPolicyReceiptFailureRollsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	_, manager, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		t.Fatal(err)
	}
	// A directory squatting on the receipt path makes the receipt publication
	// refuse without touching the configuration.
	if err := os.Mkdir(receiptPath(configPath), 0700); err != nil {
		t.Fatal(err)
	}

	_, err = applyPolicy(context.Background(), a, manager, configPath, a.Scope.CoreHome(),
		[]byte(linuxFreshConfig), []byte(linuxRoutedConfig), nil)
	mustCode(t, err, "refuse-non-file-destination")

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != linuxFreshConfig {
		t.Fatalf("config = %q, original not restored", raw)
	}
	if entries := txBackups(t, a); len(entries) != 0 {
		t.Fatalf("rollback left recovery data: %v", entries)
	}
}

// TestLinuxTransactionRestoresModeOnRollback proves metadata (permission
// bits), not just content, survives a rollback: an 0400 original must not
// come back as the published 0600.
func TestLinuxTransactionRestoresModeOnRollback(t *testing.T) {
	scope := txScope(t)
	target := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, target, "restricted", 0400)

	tx, err := beginFileTransaction(scope, "test-mode", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(target, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("published mode = %v err = %v", info.Mode().Perm(), err)
	}
	if err := tx.rollback(true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("restored mode = %o, want 400", info.Mode().Perm())
	}
	if raw, _ := os.ReadFile(target); string(raw) != "restricted" {
		t.Fatalf("restored content = %q", raw)
	}
}

// TestLinuxApplyPolicyRecoversAbandonedJournalBeforeRunning proves the
// crash-recovery ordering inside runFileTransaction: a journal abandoned by a
// process crash between publication and commit is rolled back first, and the
// new operation still lands on top of the restored bytes.
func TestLinuxApplyPolicyRecoversAbandonedJournalBeforeRunning(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")

	// A previous process crashed after publishing but before committing.
	crashed, err := beginFileTransaction(a.Scope, "policy-apply", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := crashed.writeBytes(configPath, []byte("external-controller: 127.0.0.1:19090\nsecret: "+fixtureToken+"\nrules:\n  - MATCH,DIRECT\n# crashed mid-transaction\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, manager, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := applyPolicy(context.Background(), a, manager, configPath, a.Scope.CoreHome(),
		[]byte(linuxFreshConfig), []byte(linuxRoutedConfig), nil)
	if err != nil {
		t.Fatalf("applyPolicy after crash recovery = %v", err)
	}
	if result["state"] != "restart-required" {
		t.Fatalf("result = %v", result)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != linuxRoutedConfig {
		t.Fatalf("config = %q, crashed bytes leaked into the apply", raw)
	}
	if _, err := os.Stat(receiptPath(configPath)); err != nil {
		t.Fatal("receipt missing after successful apply")
	}
	if entries := txBackups(t, a); len(entries) != 0 {
		t.Fatalf("recovery left journals: %v", entries)
	}
}

// TestLinuxRollbackRefusesForeignFIFO pins the type-drift refusal for every
// non-regular replacement: after a crash, FIFOs sit where two journaled
// destinations (one backed-up, one created by the transaction) used to hold
// regular files. The refusal must come from Lstat alone — recovery may never
// OPEN a FIFO, so with no writer on the other end the whole check still
// completes — and both foreign objects stay exactly where they are, with the
// journal retained for an operator.
func TestLinuxRollbackRefusesForeignFIFO(t *testing.T) {
	scope := txScope(t)
	primary := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	writeTxFile(t, primary, "original", 0600)
	tx, err := beginFileTransaction(scope, "test-fifodrift", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.writeBytes(primary, []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	secondary := filepath.Join(scope.DataRoot, "extra", "new.yaml")
	if err := tx.writeBytes(secondary, []byte("created"), 0600); err != nil {
		t.Fatal(err)
	}
	// Crash, then private FIFOs replace both destinations.
	for _, path := range []string{primary, secondary} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
	}

	done := make(chan error, 1)
	go func() { done <- recoverTransactions(scope, false) }()
	var recovery error
	select {
	case recovery = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("recovery blocked on a foreign FIFO: the type preflight must Lstat, never open")
	}
	mustCode(t, recovery, "rollback-failed")
	for _, path := range []string{primary, secondary} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("foreign FIFO %s removed: %v", path, err)
		}
		if info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("destination %s no longer a FIFO: %v", path, info.Mode())
		}
	}
	if entries := backupsEntries(t, scope); len(entries) == 0 {
		t.Fatal("refused rollback dropped the journal")
	}
}

// TestLinuxRollbackFailureRetainsJournal is the worst-case fault injection:
// the hook fails after publication AND the rollback cannot restore (its
// backup vanished). The error must be the distinct rollback-failed code with
// the journal retained for inspection — never a silent partial state.
func TestLinuxRollbackFailureRetainsJournal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	_, manager, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = applyPolicy(context.Background(), a, manager, configPath, a.Scope.CoreHome(),
		[]byte(linuxFreshConfig), []byte(linuxRoutedConfig),
		func(tx *fileTransaction) error {
			// Sabotage recovery, then fail: the journal's backup disappears.
			for _, record := range tx.journal {
				if record.Backup != "" {
					if err := os.Remove(record.Backup); err != nil {
						return err
					}
				}
			}
			return control("provider-write-failed", exitFail)
		})
	mustCode(t, err, "rollback-failed")
	if entries := txBackups(t, a); len(entries) != 1 {
		t.Fatalf("rollback-failed journal not retained: %v", entries)
	}
}
