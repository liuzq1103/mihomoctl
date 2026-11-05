package delivery

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestUninstallRecoveryAndSafety(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires native Linux filesystem semantics")
	}
	for _, phase := range []string{"journal-only", "launcher-removed"} {
		t.Run(phase, func(t *testing.T) {
			a, _ := installed(t)
			rec, e := readReceipt(a)
			if e != nil {
				t.Fatal(e)
			}
			receipt, e := platform.ReadPrivate(filepath.Join(installRoot(a), "receipt.json"))
			if e != nil {
				t.Fatal(e)
			}
			journal := uninstallPending{2, installRoot(a), uninstallStage(a), rec.BinPath, rec.LauncherSHA256, platform.Hash(receipt)}
			if phase == "launcher-removed" && os.Remove(rec.BinPath) != nil {
				t.Fatal("launcher fixture")
			}
			if e = platform.WriteJSON(uninstallJournal(a), journal); e != nil {
				t.Fatal(e)
			}
			if e = recoverUninstall(a); e != nil {
				t.Fatal(e)
			}
			for _, p := range []string{installRoot(a), rec.BinPath, uninstallJournal(a), uninstallStage(a)} {
				if _, e := os.Stat(p); !os.IsNotExist(e) {
					t.Fatal("uninstall recovery left path", p, e)
				}
			}
		})
	}
	a, _ := installed(t)
	root := installRoot(a)
	if e := os.Symlink(filepath.Join(root, "bin", "mihomoctl"), filepath.Join(root, "generations", "symlink")); e != nil {
		t.Fatal(e)
	}
	if e := validateOwnedTree(root); e == nil {
		t.Fatal("installation symlink accepted for deletion")
	}
}
