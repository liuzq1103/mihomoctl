//go:build linux

package delivery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

var errRemovalCrash = errors.New("injected uninstall interruption")

func interruptUninstall(t *testing.T, a platform.App, phase string) removalJournal {
	t.Helper()
	fired := false
	hooks := uninstallHooks{checkpoint: func(p string) error {
		if p == phase && !fired {
			fired = true
			return errRemovalCrash
		}
		return nil
	}}
	_, e := uninstallLocked(a, false, hooks)
	if !errors.Is(e, errRemovalCrash) || !fired {
		t.Fatalf("phase %s: %v", phase, e)
	}
	j, e := loadRemoval(a)
	if e != nil {
		t.Fatal(e)
	}
	return j
}

func TestUninstallCrashRecoveryAllBoundaries(t *testing.T) {
	for _, phase := range []string{"journal-published", "root-quarantined", "launcher-removed", "entry-removed", "root-removed"} {
		t.Run(phase, func(t *testing.T) {
			a, _ := installed(t)
			core := filepath.Join(a.Scope.DataRoot, "cores", "active", "mihomo")
			if e := platform.AtomicWrite(core, []byte("independent-core"), 0700); e != nil {
				t.Fatal(e)
			}
			if e := platform.WriteYAML(a.Scope.ManagerPath(), map[string]any{"core": map[string]any{"binary": core}}); e != nil {
				t.Fatal(e)
			}
			manager, _ := os.ReadFile(a.Scope.ManagerPath())
			j := interruptUninstall(t, a, phase)
			status, e := installationStatus(a)
			if e != nil || status["status"] != "uninstalling" {
				t.Fatal(status, e)
			}
			doc, e := Run(context.Background(), a, platform.Request{Command: []string{"installation", "recover"}})
			if e != nil || doc.Data == nil || doc.Data["installed"] != false || doc.Data["status"] != "not-installed" {
				t.Fatal(doc, e)
			}
			for _, p := range []string{installRoot(a), j.Quarantine, j.Receipt.BinPath, uninstallJournal(a)} {
				if _, e := os.Lstat(p); !os.IsNotExist(e) {
					t.Fatal("retained program path", p, e)
				}
			}
			if b, e := os.ReadFile(core); e != nil || string(b) != "independent-core" {
				t.Fatal("core changed", e)
			}
			if b, e := os.ReadFile(a.Scope.ManagerPath()); e != nil || string(b) != string(manager) {
				t.Fatal("manager changed", e)
			}
			result, e := Uninstall(context.Background(), a, false)
			if e != nil || result["changed"] != false {
				t.Fatal("repeat uninstall", result, e)
			}
		})
	}
}

func TestBootstrapRecoversCompletedRemovalBeforeReinstall(t *testing.T) {
	a, _ := installed(t)
	j := interruptUninstall(t, a, "root-removed")
	source := fixture(t, "0.3.0", "replacement")
	bin := filepath.Dir(j.Receipt.BinPath)
	if _, e := Bootstrap(context.Background(), a, source, bin, true); e == nil {
		t.Fatal("preview ignored outstanding deletion")
	}
	if _, e := Bootstrap(context.Background(), a, source, bin, false); e != nil {
		t.Fatal(e)
	}
	current, e := readCurrent(installRoot(a))
	if e != nil {
		t.Fatal(e)
	}
	if e = recoverUninstall(a); e != nil {
		t.Fatal(e)
	}
	again, e := readCurrent(installRoot(a))
	if e != nil || again != current {
		t.Fatal("old journal removed new install", e)
	}
	if _, e = os.Lstat(uninstallJournal(a)); !os.IsNotExist(e) {
		t.Fatal("journal retained", e)
	}
}

func TestOldJournalRefusesNewInstallation(t *testing.T) {
	for _, phase := range []string{"journal-published", "root-removed"} {
		t.Run(phase, func(t *testing.T) {
			a, _ := installed(t)
			j := interruptUninstall(t, a, phase)
			savedJournal := filepath.Join(privateTemp(t), "journal.json")
			if e := os.Rename(uninstallJournal(a), savedJournal); e != nil {
				t.Fatal(e)
			}
			if phase == "journal-published" {
				if e := os.Rename(installRoot(a), filepath.Join(privateTemp(t), "old-install")); e != nil {
					t.Fatal(e)
				}
				if e := os.Remove(j.Receipt.BinPath); e != nil {
					t.Fatal(e)
				}
			}
			// Simulate an older installer unaware of the deletion journal. Use
			// identical program bytes to ensure SHA alone is not the identity.
			source := fixture(t, "0.2.0", "old-binary")
			if _, e := Bootstrap(context.Background(), a, source, filepath.Dir(j.Receipt.BinPath), false); e != nil {
				t.Fatal(e)
			}
			id, e := readCurrent(installRoot(a))
			if e != nil {
				t.Fatal(e)
			}
			if e = os.Rename(savedJournal, uninstallJournal(a)); e != nil {
				t.Fatal(e)
			}
			if e = recoverUninstall(a); e == nil {
				t.Fatal("stale journal accepted replacement")
			}
			if _, e = Uninstall(context.Background(), a, false); e == nil {
				t.Fatal("public uninstall read replacement receipt first")
			}
			after, e := readCurrent(installRoot(a))
			if e != nil || after != id {
				t.Fatal("replacement removed", e)
			}
			if _, e = os.Stat(j.Receipt.BinPath); e != nil {
				t.Fatal("replacement launcher removed", e)
			}
			if _, e = Bootstrap(context.Background(), a, source, filepath.Dir(j.Receipt.BinPath), false); e == nil {
				t.Fatal("bootstrap ignored stale conflicting journal")
			}
		})
	}
}

func TestRemovalRefusesForeignFilesAndChangedBytes(t *testing.T) {
	for _, kind := range []string{"new-file", "changed-file", "symlink", "receipt", "current"} {
		t.Run(kind, func(t *testing.T) {
			a, id := installed(t)
			j := interruptUninstall(t, a, "root-quarantined")
			p := filepath.Join(j.Quarantine, "generations", id, "bin", "mihomoctl")
			switch kind {
			case "new-file":
				p = filepath.Join(j.Quarantine, "foreign")
				if e := os.WriteFile(p, []byte("foreign"), 0600); e != nil {
					t.Fatal(e)
				}
			case "changed-file":
				if e := os.WriteFile(p, []byte("changed"), 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				p = filepath.Join(j.Quarantine, "foreign-link")
				if e := os.Symlink(a.Scope.ConfigRoot, p); e != nil {
					t.Fatal(e)
				}
			case "receipt":
				p = filepath.Join(j.Quarantine, "receipt.json")
				if e := os.WriteFile(p, []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			case "current":
				p = filepath.Join(j.Quarantine, "current")
				if e := os.WriteFile(p, []byte(strings.Repeat("a", 64)+"\n"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e := recoverUninstall(a); e == nil {
				t.Fatal("foreign modification deleted")
			}
			if _, e := os.Lstat(p); e != nil {
				t.Fatal("foreign/modified entry removed", e)
			}
			if _, e := os.Stat(j.Receipt.BinPath); e != nil {
				t.Fatal("launcher removed before drift preflight", e)
			}
			if _, e := os.Stat(uninstallJournal(a)); e != nil {
				t.Fatal("journal discarded", e)
			}
		})
	}
}

// A replacement file that carries identical bytes is still a different object.
// Recovery must refuse it instead of deleting it as a program-owned file.
func TestRemovalRefusesSameByteForeignReplacement(t *testing.T) {
	replace := func(t *testing.T, path string, mode os.FileMode) {
		t.Helper()
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		// Write elsewhere and rename over the path: the bytes are identical but
		// the inode is new, which is exactly the replacement case.
		staged := filepath.Join(privateTemp(t), "replacement")
		if e = os.WriteFile(staged, b, mode); e != nil {
			t.Fatal(e)
		}
		if e = os.Rename(staged, path); e != nil {
			t.Fatal(e)
		}
	}
	t.Run("program-file", func(t *testing.T) {
		a, id := installed(t)
		j := interruptUninstall(t, a, "journal-published")
		p := filepath.Join(installRoot(a), "generations", id, "bin", "mihomoctl")
		replace(t, p, 0700)
		if e := recoverUninstall(a); e == nil {
			t.Fatal("same-byte replacement accepted")
		}
		if _, e := os.Lstat(p); e != nil {
			t.Fatal("foreign replacement deleted", e)
		}
		if _, e := os.Lstat(j.Receipt.BinPath); e != nil {
			t.Fatal("launcher removed after refusal", e)
		}
		if _, e := os.Lstat(uninstallJournal(a)); e != nil {
			t.Fatal("journal discarded", e)
		}
	})
	t.Run("launcher", func(t *testing.T) {
		a, _ := installed(t)
		j := interruptUninstall(t, a, "journal-published")
		replace(t, j.Receipt.BinPath, 0700)
		if e := recoverUninstall(a); e == nil {
			t.Fatal("same-byte launcher replacement accepted")
		}
		if _, e := os.Lstat(j.Receipt.BinPath); e != nil {
			t.Fatal("foreign launcher deleted", e)
		}
		if _, e := os.Lstat(installRoot(a)); e != nil {
			t.Fatal("program root removed after refusal", e)
		}
	})
}

func TestRemovalRefusesConfiguredCoreWithinProgram(t *testing.T) {
	for _, adopted := range []bool{false, true} {
		t.Run(map[bool]string{false: "configured", true: "adopted"}[adopted], func(t *testing.T) {
			a, id := installed(t)
			p := filepath.Join(installRoot(a), "generations", id, "bin", "mihomoctl")
			if e := platform.WriteYAML(a.Scope.ManagerPath(), map[string]any{"core": map[string]any{"binary": p, "adopted": adopted}}); e != nil {
				t.Fatal(e)
			}
			for _, dry := range []bool{true, false} {
				options := map[string][]string{}
				if dry {
					options["dry-run"] = []string{"true"}
				}
				doc, e := Run(context.Background(), a, platform.Request{Command: []string{"installation", "uninstall"}, Options: options})
				if e == nil {
					t.Fatal("core deletion reported success", doc)
				}
			}
			if st, e := os.Stat(p); e != nil || st.Mode().Perm()&0100 == 0 {
				t.Fatal("core removed or made nonexecutable", e)
			}
			if _, e := readReceipt(a); e != nil {
				t.Fatal("launcher/receipt changed", e)
			}
			if _, e := os.Lstat(uninstallJournal(a)); !os.IsNotExist(e) {
				t.Fatal("refusal wrote removal journal", e)
			}
		})
	}
}

func TestCorruptInstallationStatusFails(t *testing.T) {
	for _, kind := range []string{"receipt", "launcher", "current", "binary", "missing-receipt", "symlink-root", "foreign-file"} {
		t.Run(kind, func(t *testing.T) {
			a, id := installed(t)
			rec, e := readReceipt(a)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "foreign-file":
				e = os.WriteFile(filepath.Join(installRoot(a), "foreign"), []byte("foreign"), 0600)
			case "receipt":
				e = os.WriteFile(filepath.Join(installRoot(a), "receipt.json"), []byte("{}"), 0600)
			case "launcher":
				e = os.WriteFile(rec.BinPath, []byte("foreign"), 0700)
			case "current":
				e = os.WriteFile(filepath.Join(installRoot(a), "current"), []byte("bad"), 0600)
			case "binary":
				e = os.WriteFile(filepath.Join(installRoot(a), "generations", id, "bin", "mihomoctl"), []byte("changed"), 0700)
			case "missing-receipt":
				e = os.Remove(filepath.Join(installRoot(a), "receipt.json"))
			case "symlink-root":
				backup := filepath.Join(privateTemp(t), "root")
				e = os.Rename(installRoot(a), backup)
				if e == nil {
					e = os.Symlink(backup, installRoot(a))
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			doc, e := Run(context.Background(), a, platform.Request{Command: []string{"installation", "status"}})
			if e == nil || doc.Overall == "PASS" {
				t.Fatal("corruption represented as not-installed", doc, e)
			}
		})
	}
}

func TestSharedRecoveryCoordinatesDeliveryUninstall(t *testing.T) {
	a, _ := installed(t)
	j := interruptUninstall(t, a, "launcher-removed")
	if e := platform.CheckPending(a.Scope); e == nil {
		t.Fatal("reader missed delivery uninstall journal")
	}
	called := false
	if e := platform.WithLock(context.Background(), a.Scope, func() error {
		called = true
		if _, e := os.Lstat(j.Quarantine); !os.IsNotExist(e) {
			return errors.New("mutation ran before delivery cleanup")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if !called {
		t.Fatal("coordinator never reached mutation")
	}
	if e := platform.CheckPending(a.Scope); e != nil {
		t.Fatal(e)
	}
}

func TestSharedRecoveryCoordinatesDeliveryUpdate(t *testing.T) {
	a, old := installed(t)
	source := fixture(t, "0.3.0", "new")
	m, e := LoadManifest(source)
	if e != nil {
		t.Fatal(e)
	}
	id, e := stageGeneration(installRoot(a), source, m)
	if e != nil {
		t.Fatal(e)
	}
	if e = platform.WriteJSON(filepath.Join(installRoot(a), "pending.json"), pending{1, old, id}); e != nil {
		t.Fatal(e)
	}
	if e = platform.CheckPending(a.Scope); e == nil {
		t.Fatal("reader missed delivery update journal")
	}
	if e = platform.WithLock(context.Background(), a.Scope, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = platform.CheckPending(a.Scope); e != nil {
		t.Fatal(e)
	}
}

func TestRemovalPreservesRecordedRunningCoreWhenManagerDiffers(t *testing.T) {
	a, id := installed(t)
	core := filepath.Join(installRoot(a), "generations", id, "bin", "mihomoctl")
	if e := platform.WriteYAML(a.Scope.ManagerPath(), map[string]any{"core": map[string]any{"binary": filepath.Join(a.Scope.DataRoot, "cores", "new-core")}}); e != nil {
		t.Fatal(e)
	}
	if e := platform.WriteJSON(a.Scope.RuntimeState(), map[string]any{"namespace": Project, "scope": a.Scope.Name, "identity": map[string]any{"pid": 1234, "exe": core}}); e != nil {
		t.Fatal(e)
	}
	if _, e := Uninstall(context.Background(), a, false); e == nil {
		t.Fatal("recorded running core was ignored")
	}
	if st, e := os.Stat(core); e != nil || st.Mode().Perm()&0100 == 0 {
		t.Fatal("running core not preserved", e)
	}
	if _, e := readReceipt(a); e != nil {
		t.Fatal(e)
	}
}
