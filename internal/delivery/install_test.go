package delivery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func testApp(t *testing.T) platform.App {
	t.Helper()
	base := privateTemp(t)
	return platform.App{Scope: platform.Scope{Name: "test", System: runtime.GOOS == "linux" && os.Geteuid() == 0, DataRoot: filepath.Join(base, "data"), StateRoot: filepath.Join(base, "state"), ConfigRoot: filepath.Join(base, "config"), RuntimeRoot: filepath.Join(base, "runtime")}}
}

// Create a real receipt-owned filesystem fixture; transaction unit tests also run
// on Windows, but native lock/permission/bootstrap tests are Linux-only below.
func installed(t *testing.T) (platform.App, string) {
	t.Helper()
	a := testApp(t)
	root := installRoot(a)
	source := fixture(t, "0.2.0", "old-binary")
	m, e := LoadManifest(source)
	if e != nil {
		t.Fatal(e)
	}
	id, e := stageGeneration(root, source, m)
	if e != nil {
		t.Fatal(e)
	}
	bin := filepath.Join(filepath.Dir(a.Scope.DataRoot), "bin", "mihomoctl")
	if e = platform.AtomicWrite(bin, launcher(root), 0700); e != nil {
		t.Fatal(e)
	}
	if e = platform.WriteJSON(filepath.Join(root, "receipt.json"), Receipt{1, Project, bin, platform.Hash(launcher(root))}); e != nil {
		t.Fatal(e)
	}
	if e = platform.AtomicWrite(filepath.Join(root, "current"), []byte(id+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	return a, id
}
func TestUpdateRejectsUnmanagedAndDrift(t *testing.T) {
	a := testApp(t)
	if _, e := installTree(a, "", false, false, true, installHooks{}); e == nil {
		t.Fatal("unmanaged update accepted")
	}
	a, _ = installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(rec.BinPath, []byte("foreign"), 0700)
	if _, e = installTree(a, "", false, false, true, installHooks{}); e == nil {
		t.Fatal("launcher drift accepted")
	}
}
func TestUpdateVersionPolicyAndDryRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("manifest target is Linux; native identity policy tested in Linux CI")
	}
	a, old := installed(t)
	same := fixture(t, "0.2.0", "same")
	if _, e := installTree(a, same, false, false, true, installHooks{}); e == nil {
		t.Fatal("implicit reinstall accepted")
	}
	down := fixture(t, "0.1.0", "down")
	if _, e := installTree(a, down, false, false, true, installHooks{}); e == nil {
		t.Fatal("implicit downgrade accepted")
	}
	if _, e := installTree(a, down, false, true, true, installHooks{}); e != nil {
		t.Fatal(e)
	}
	newSource := fixture(t, "0.3.0", "new")
	if _, e := installTree(a, newSource, false, false, true, installHooks{}); e != nil {
		t.Fatal(e)
	}
	got, e := readCurrent(installRoot(a))
	if e != nil || got != old {
		t.Fatal("dry-run changed generation", got, e)
	}
	if _, e = os.Lstat(filepath.Join(installRoot(a), "pending.json")); !os.IsNotExist(e) {
		t.Fatal("dry-run wrote journal")
	}
}
func TestUpdateRollbackAtBothBoundaries(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux manifest")
	}
	for _, phase := range []string{"journal", "switch"} {
		t.Run(phase, func(t *testing.T) {
			a, old := installed(t)
			active := filepath.Join(a.Scope.DataRoot, "cores", "active")
			platform.AtomicWrite(active, []byte("running-core"), 0700)
			source := fixture(t, "0.3.0", "new-binary")
			hooks := installHooks{}
			injected := errors.New("injected I/O failure")
			if phase == "journal" {
				hooks.afterJournal = func() error { return injected }
			} else {
				hooks.afterSwitch = func() error { return injected }
			}
			if _, e := installTree(a, source, false, false, false, hooks); !errors.Is(e, injected) {
				t.Fatal(e)
			}
			cur, e := readCurrent(installRoot(a))
			if e != nil || cur != old {
				t.Fatal("rollback did not restore", cur, e)
			}
			if _, _, e = generation(installRoot(a), old); e != nil {
				t.Fatal(e)
			}
			b, e := os.ReadFile(active)
			if e != nil || string(b) != "running-core" {
				t.Fatal("active core changed")
			}
			if _, e = installTree(a, source, false, false, false, installHooks{}); e != nil {
				t.Fatal("retry failed", e)
			}
		})
	}
}
func TestCrashRecovery(t *testing.T) {
	for _, phase := range []string{"before-switch", "after-switch", "corrupt-new", "conflict", "corrupt-journal"} {
		t.Run(phase, func(t *testing.T) {
			a, old := installed(t)
			root := installRoot(a)
			source := fixture(t, "0.3.0", "new")
			m, e := LoadManifest(source)
			if e != nil {
				t.Fatal(e)
			}
			id, e := stageGeneration(root, source, m)
			if e != nil {
				t.Fatal(e)
			}
			platform.WriteJSON(filepath.Join(root, "pending.json"), pending{1, old, id})
			want := old
			if phase == "after-switch" || phase == "corrupt-new" {
				platform.AtomicWrite(filepath.Join(root, "current"), []byte(id+"\n"), 0600)
				want = id
			}
			if phase == "corrupt-new" {
				os.WriteFile(filepath.Join(root, "generations", id, "bin", "mihomoctl"), []byte("corrupt"), 0700)
				want = old
			}
			if phase == "conflict" {
				platform.AtomicWrite(filepath.Join(root, "current"), []byte(platform.Hash([]byte("foreign"))+"\n"), 0600)
			}
			if phase == "corrupt-journal" {
				platform.AtomicWrite(filepath.Join(root, "pending.json"), []byte(`{"format":1,"old":"../../outside"}`), 0600)
			}
			e = recoverInstall(a)
			if phase == "conflict" || phase == "corrupt-journal" {
				if e == nil {
					t.Fatal("conflict accepted")
				}
				if _, e = os.Stat(filepath.Join(root, "pending.json")); e != nil {
					t.Fatal("failure discarded journal")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			cur, e := readCurrent(root)
			if e != nil || cur != want {
				t.Fatal(cur, want, e)
			}
			if e = recoverInstall(a); e != nil {
				t.Fatal("recovery not idempotent", e)
			}
		})
	}
}
func TestLinuxBootstrapAndUninstall(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux filesystem, permissions and flock")
	}
	a := testApp(t)
	source := fixture(t, "0.2.0", "binary")
	bin := filepath.Join(filepath.Dir(a.Scope.DataRoot), "bin")
	if _, e := Bootstrap(context.Background(), a, source, bin, false); e != nil {
		t.Fatal(e)
	}
	if _, e := readReceipt(a); e != nil {
		t.Fatal(e)
	}
	if _, e := Bootstrap(context.Background(), a, source, bin, false); e == nil {
		t.Fatal("second bootstrap overwrote command")
	}
	if _, e := Uninstall(context.Background(), a, true); e != nil {
		t.Fatal(e)
	}
	if _, e := readReceipt(a); e != nil {
		t.Fatal("dry uninstall changed receipt", e)
	}
	if _, e := Uninstall(context.Background(), a, false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(installRoot(a), "receipt.json")); e != nil {
		t.Fatal("uninstall removed data", e)
	}
}
