//go:build linux

package delivery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// An installation whose program root was lost leaves its launcher behind.
// The status has to report that orphaned installation instead of an absent
// one, and a later installation has to be able to repair the scope instead
// of refusing a command that is already there.
func TestOrphanedInstallationIsReportedAndRepaired(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	// The copy of the receipt outside the program root names the launcher.
	if e = writeInstallationRecord(a, rec); e != nil {
		t.Fatal(e)
	}
	// The program root is lost.
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	status, e := installationStatus(a)
	if e != nil {
		t.Fatal(e)
	}
	if status["status"] != "orphaned" || status["installed"] != false {
		t.Fatalf("status = %v", status)
	}
	if status["bin_path"] != rec.BinPath {
		t.Fatalf("status = %v", status)
	}
	if _, e = os.Lstat(rec.BinPath); e != nil {
		t.Fatal("the launcher of the lost installation was removed", e)
	}
	// The launcher is removed by identity, so the scope is repaired.
	removed, e := repairOrphanedInstallation(a)
	if e != nil {
		t.Fatal(e)
	}
	if removed != rec.BinPath {
		t.Fatalf("removed = %q", removed)
	}
	if _, e = os.Lstat(rec.BinPath); !os.IsNotExist(e) {
		t.Fatal("the launcher was not removed", e)
	}
	if _, e = os.Lstat(installationRecordPath(a)); !os.IsNotExist(e) {
		t.Fatal("the record was not dropped", e)
	}
	status, e = installationStatus(a)
	if e != nil {
		t.Fatal(e)
	}
	if status["status"] != "not-installed" {
		t.Fatalf("status = %v", status)
	}
}

// A foreign object that took the place of the launcher of a lost
// installation is never removed as if it were ours, and it does not keep the
// scope from being repaired.
func TestOrphanedInstallationNeverRemovesAForeignLauncher(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeInstallationRecord(a, rec); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	// A replacement file carrying identical bytes is a different object.
	if e = platform.AtomicWrite(rec.BinPath, launcher(installRoot(a)), 0700); e != nil {
		t.Fatal(e)
	}
	removed, e := repairOrphanedInstallation(a)
	if e != nil {
		t.Fatal(e)
	}
	if removed != "" {
		t.Fatalf("a foreign object was removed: %q", removed)
	}
	if _, e = os.Lstat(rec.BinPath); e != nil {
		t.Fatal("the foreign object was removed", e)
	}
}

// A later installation repairs an orphaned launcher instead of refusing the
// command that is already there.
func TestInstallationRepairsAnOrphanedLauncher(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeInstallationRecord(a, rec); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	source := fixture(t, "0.2.0", "bootstrap-binary")
	bin := filepath.Dir(rec.BinPath)
	data, e := bootstrap(context.Background(), a, source, bin, false, bootstrapHooks{})
	if e != nil {
		t.Fatal(e)
	}
	if data["repaired_orphan_launcher"] != rec.BinPath {
		t.Fatalf("data = %v", data)
	}
	if _, e = readReceipt(a); e != nil {
		t.Fatal("the installation was not published", e)
	}
	// The new launcher is the one the receipt binds.
	installed, e := installationStatus(a)
	if e != nil {
		t.Fatal(e)
	}
	if installed["installed"] != true {
		t.Fatalf("status = %v", installed)
	}
}

// An orphaned launcher recorded at one directory does not make a foreign
// command at a DIFFERENT requested directory ours. The orphan repair only
// covers the recorded destination: accepting the foreign one would remove the
// recorded launcher, publish the program root and only then fail to link the
// launcher over the foreign file, wedging the scope behind a journal no
// recovery can finish. The foreign destination is refused before anything is
// repaired.
func TestInstallRefusesAForeignDestinationWhileAnOrphanLivesElsewhere(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeInstallationRecord(a, rec); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	other := filepath.Join(filepath.Dir(a.Scope.DataRoot), "other-bin")
	if e = os.MkdirAll(other, 0700); e != nil {
		t.Fatal(e)
	}
	if e = platform.AtomicWrite(filepath.Join(other, "mihomoctl"), []byte("#!/bin/sh\n# a foreign command\n"), 0700); e != nil {
		t.Fatal(e)
	}
	source := fixture(t, "0.2.0", "bootstrap-binary")
	_, e = bootstrap(context.Background(), a, source, other, false, bootstrapHooks{})
	var pe *platform.Error
	if !errors.As(e, &pe) || pe.Code != "installation-command-exists" {
		t.Fatalf("error = %v", e)
	}
	// The recorded launcher survives: nothing was repaired for a refusal.
	if _, e = os.Lstat(rec.BinPath); e != nil {
		t.Fatal("the refusal removed the recorded launcher", e)
	}
	if _, e = os.Lstat(installationRecordPath(a)); e != nil {
		t.Fatal("the refusal dropped the record", e)
	}
	if _, e = os.Lstat(installRoot(a)); !os.IsNotExist(e) {
		t.Fatal("the refusal published a program root", e)
	}
	if _, e = os.Lstat(bootstrapJournalPath(a)); !os.IsNotExist(e) {
		t.Fatal("the refusal left a bootstrap journal", e)
	}
}

// An installation MAY move to a different directory while its orphaned
// launcher is repaired: the orphan repair is not tied to the requested
// destination, only its acceptance of an occupied destination is.
func TestInstallRepairsAnOrphanWhileMovingToAFreeDirectory(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeInstallationRecord(a, rec); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	other := filepath.Join(filepath.Dir(a.Scope.DataRoot), "other-bin")
	source := fixture(t, "0.2.0", "bootstrap-binary")
	data, e := bootstrap(context.Background(), a, source, other, false, bootstrapHooks{})
	if e != nil {
		t.Fatal(e)
	}
	if data["repaired_orphan_launcher"] != rec.BinPath {
		t.Fatalf("data = %v", data)
	}
	if _, e = os.Lstat(rec.BinPath); !os.IsNotExist(e) {
		t.Fatal("the orphaned launcher was not removed", e)
	}
	if _, e = os.Lstat(filepath.Join(other, "mihomoctl")); e != nil {
		t.Fatal("the new launcher was not published", e)
	}
}

// A dry run never repairs anything: it describes the state it finds.
func TestDryRunDoesNotRepairAnOrphanedLauncher(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeInstallationRecord(a, rec); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	source := fixture(t, "0.2.0", "bootstrap-binary")
	if _, e = bootstrap(context.Background(), a, source, filepath.Dir(rec.BinPath), true, bootstrapHooks{}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(rec.BinPath); e != nil {
		t.Fatal("a dry run removed the launcher", e)
	}
	if _, e = os.Lstat(installationRecordPath(a)); e != nil {
		t.Fatal("a dry run dropped the record", e)
	}
}

// A record from before the receipt bound the launcher object keeps the
// guarantee it was written with: content identity. A launcher that still
// hashes to the recorded digest is ours — even when it is a new object with
// the same bytes — and a repair may remove it.
func TestLegacyOrphanedRecordRemovesAContentMatchingLauncher(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	legacy := rec
	legacy.LauncherDevice, legacy.LauncherInode = 0, 0
	if e = writeInstallationRecord(a, legacy); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	// A new object with the launcher's exact bytes is the recorded launcher
	// to a record that never bound an object.
	if e = platform.AtomicWrite(rec.BinPath, launcher(installRoot(a)), 0700); e != nil {
		t.Fatal(e)
	}
	if _, orphaned, e := installationOrphan(a); e != nil || !orphaned {
		t.Fatalf("the legacy record did not claim its launcher: %v", e)
	}
	removed, e := repairOrphanedInstallation(a)
	if e != nil {
		t.Fatal(e)
	}
	if removed != rec.BinPath {
		t.Fatalf("removed = %q", removed)
	}
	if _, e = os.Lstat(rec.BinPath); !os.IsNotExist(e) {
		t.Fatal("the launcher was not removed", e)
	}
}

// A record from before object binding is not unconditional deletion
// authority either: a launcher whose content no longer hashes to the recorded
// digest is foreign, is never removed, and is not reported as an orphan of
// this installation.
func TestLegacyOrphanedRecordNeverRemovesAForeignLauncher(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	legacy := rec
	legacy.LauncherDevice, legacy.LauncherInode = 0, 0
	if e = writeInstallationRecord(a, legacy); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	// A foreign command that carries different bytes.
	if e = platform.AtomicWrite(rec.BinPath, []byte("#!/bin/sh\n# a foreign command\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, orphaned, e := installationOrphan(a); e != nil || orphaned {
		t.Fatalf("a foreign command was claimed as ours: %v", e)
	}
	removed, e := repairOrphanedInstallation(a)
	if e != nil {
		t.Fatal(e)
	}
	if removed != "" {
		t.Fatalf("a foreign command was removed: %q", removed)
	}
	if _, e = os.Lstat(rec.BinPath); e != nil {
		t.Fatal("the foreign command was removed", e)
	}
	if _, e = os.Lstat(installationRecordPath(a)); !os.IsNotExist(e) {
		t.Fatal("the record was not dropped", e)
	}
}

// The uninstall of an installation whose program root was lost removes the
// launcher that is left behind, by identity.
func TestUninstallRemovesAnOrphanedLauncher(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeInstallationRecord(a, rec); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(installRoot(a)); e != nil {
		t.Fatal(e)
	}
	data, e := uninstallLocked(a, false, uninstallHooks{})
	if e != nil {
		t.Fatal(e)
	}
	if data["changed"] != true {
		t.Fatalf("data = %v", data)
	}
	if _, e = os.Lstat(rec.BinPath); !os.IsNotExist(e) {
		t.Fatal("the launcher was not removed", e)
	}
}
