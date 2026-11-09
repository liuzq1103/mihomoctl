//go:build linux

package delivery

import (
	"context"
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
