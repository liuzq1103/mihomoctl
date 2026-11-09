//go:build linux

package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

var bootstrapPhases = []string{"staged", "journal-published", "root-published", "launcher-published", "launcher-stage-unlinked", "staging-cleaned", "journal-removed"}

// Exit without running defers in a separate process. This exercises lock
// release and recovery from persisted state rather than an in-memory rollback.
func TestBootstrapCrashWorker(t *testing.T) {
	if os.Getenv("MIHOMOCTL_BOOTSTRAP_WORKER") != "1" {
		return
	}
	var a platform.App
	if e := json.Unmarshal([]byte(os.Getenv("MIHOMOCTL_BOOTSTRAP_APP")), &a); e != nil {
		t.Fatal(e)
	}
	phase := os.Getenv("MIHOMOCTL_BOOTSTRAP_PHASE")
	_, e := bootstrap(context.Background(), a, os.Getenv("MIHOMOCTL_BOOTSTRAP_SOURCE"), os.Getenv("MIHOMOCTL_BOOTSTRAP_BIN"), false, bootstrapHooks{checkpoint: func(p string) error {
		if p == phase {
			os.Exit(73)
		}
		return nil
	}})
	t.Fatalf("worker did not reach %s: %v", phase, e)
}

func crashBootstrap(t *testing.T, phase string) (platform.App, string, string) {
	t.Helper()
	a := testApp(t)
	source := fixture(t, "0.2.0", "bootstrap-binary")
	bin := filepath.Join(filepath.Dir(a.Scope.DataRoot), "bin")
	b, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestBootstrapCrashWorker$")
	cmd.Env = append(os.Environ(), "MIHOMOCTL_BOOTSTRAP_WORKER=1", "MIHOMOCTL_BOOTSTRAP_APP="+string(b),
		"MIHOMOCTL_BOOTSTRAP_PHASE="+phase, "MIHOMOCTL_BOOTSTRAP_SOURCE="+source, "MIHOMOCTL_BOOTSTRAP_BIN="+bin)
	output, e := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("phase %s: %s %v", phase, output, e)
	}
	return a, source, bin
}

func publicInstallation(t *testing.T, a platform.App, action, source, bin string) platform.Envelope {
	t.Helper()
	r := platform.Request{Command: []string{"installation", action}, Options: map[string][]string{}}
	if action == "install" {
		r.Options["source"], r.Options["bin-dir"] = []string{source}, []string{bin}
	}
	doc, e := Run(context.Background(), a, r)
	if e != nil || doc.Data == nil {
		t.Fatalf("public %s: %+v %v", action, doc, e)
	}
	return doc
}

func TestBootstrapCrashPublicEntryRecovery(t *testing.T) {
	for _, phase := range bootstrapPhases {
		for _, entry := range []string{"recover", "install", "uninstall"} {
			t.Run(phase+"/"+entry, func(t *testing.T) {
				a, source, bin := crashBootstrap(t, phase)
				if phase != "staged" && phase != "journal-removed" {
					if e := platform.CheckPending(a.Scope); e == nil {
						t.Fatal("pending bootstrap reader accepted")
					}
					if _, e := installationStatus(a); e == nil {
						t.Fatal("pending status accepted")
					}
					if _, e := Bootstrap(context.Background(), a, source, bin, true); e == nil {
						t.Fatal("dry-run recovered pending publication")
					}
				}
				doc := publicInstallation(t, a, entry, source, bin)
				installed := entry != "uninstall" && (entry == "install" || phase != "staged")
				if entry != "install" && doc.Data["installed"] != installed {
					t.Fatal(doc.Data)
				}
				if installed {
					if _, e := readReceipt(a); e != nil {
						t.Fatal(e)
					}
					status, e := installationStatus(a)
					if e != nil || status["installed"] != true {
						t.Fatal(status, e)
					}
				}
				// All entry choices must leave an idempotent uninstall and a
				// working fresh install, without an old journal deleting it.
				publicInstallation(t, a, "uninstall", source, bin)
				publicInstallation(t, a, "uninstall", source, bin)
				publicInstallation(t, a, "install", source, bin)
				publicInstallation(t, a, "recover", source, bin)
				if _, e := readReceipt(a); e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}

func TestBootstrapRecoveryRefusesForeignIdentity(t *testing.T) {
	for _, scenario := range []string{"foreign-before-link", "same-bytes-launcher", "changed-launcher", "same-bytes-receipt", "foreign-tree-file", "foreign-empty-root", "replaced-root", "symlink-launcher", "forged-journal"} {
		t.Run(scenario, func(t *testing.T) {
			phase := "launcher-published"
			if scenario == "foreign-before-link" || scenario == "foreign-empty-root" {
				phase = "journal-published"
			}
			a, source, bin := crashBootstrap(t, phase)
			j, e := loadBootstrap(a)
			if e != nil {
				t.Fatal(e)
			}
			var protected string
			switch scenario {
			case "foreign-before-link":
				protected = j.Receipt.BinPath
				e = os.WriteFile(protected, launcher(j.Root), 0700)
			case "same-bytes-launcher", "changed-launcher":
				protected = j.Receipt.BinPath
				// Retain the original inode to rule out allocator inode reuse.
				e = os.Rename(protected, protected+".original")
				if e == nil {
					b := launcher(j.Root)
					if scenario == "changed-launcher" {
						b = []byte("foreign launcher")
					}
					e = os.WriteFile(protected, b, 0700)
				}
			case "same-bytes-receipt":
				protected = filepath.Join(j.Root, "receipt.json")
				b, re := os.ReadFile(protected)
				if re != nil {
					t.Fatal(re)
				}
				e = os.Rename(protected, filepath.Join(a.Scope.DataRoot, "original-receipt"))
				if e == nil {
					e = os.WriteFile(protected, b, 0600)
				}
			case "replaced-root":
				protected = j.Root
				e = os.Rename(j.Root, j.Root+".original")
				if e == nil {
					e = os.Mkdir(j.Root, 0700)
				}
				if e == nil {
					// Root identity alone must reject a replacement, before
					// considering even an empty replacement's contents.
					e = os.Chmod(j.Root, 0700)
				}
			case "symlink-launcher":
				protected = j.Receipt.BinPath
				e = os.Rename(protected, protected+".original")
				if e == nil {
					e = os.Symlink(protected+".original", protected)
				}
			case "foreign-tree-file":
				protected = filepath.Join(j.Root, "foreign")
				e = os.WriteFile(protected, []byte("not owned"), 0600)
			case "foreign-empty-root":
				protected = j.Root
				e = os.Mkdir(protected, 0700)
			case "forged-journal":
				protected = bootstrapJournalPath(a)
				j.Entries["../../foreign"] = j.Launcher
				e = platform.WriteJSON(protected, j)
			}
			if e != nil {
				t.Fatal(e)
			}
			if scenario == "symlink-launcher" {
				for _, action := range []string{"recover", "install", "uninstall"} {
					r := platform.Request{Command: []string{"installation", action}, Options: map[string][]string{"source": {source}, "bin-dir": {bin}}}
					if _, e = Run(context.Background(), a, r); e == nil {
						t.Fatalf("%s accepted symlink", action)
					}
					if target, e := os.Readlink(protected); e != nil || target != protected+".original" {
						t.Fatal("foreign symlink touched", target, e)
					}
				}
				return
			}
			before, e := bootstrapIdentity(protected)
			if e != nil {
				t.Fatal(e)
			}
			for _, action := range []string{"recover", "install", "uninstall"} {
				r := platform.Request{Command: []string{"installation", action}, Options: map[string][]string{"source": {source}, "bin-dir": {bin}}}
				if _, e = Run(context.Background(), a, r); e == nil {
					t.Fatalf("%s accepted %s", action, scenario)
				}
				after, e := bootstrapIdentity(protected)
				if e != nil || before != after {
					t.Fatalf("foreign path touched: %v", e)
				}
				if exists, e := optionalExists(bootstrapJournalPath(a)); e != nil || !exists {
					t.Fatal("journal lost", e)
				}
			}
		})
	}
}

func TestBootstrapPublicationNeverReplacesExistingDestination(t *testing.T) {
	base := privateTemp(t)
	stage, root := filepath.Join(base, "stage"), filepath.Join(base, "root")
	if e := os.Mkdir(stage, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	before, e := bootstrapIdentity(root)
	if e != nil {
		t.Fatal(e)
	}
	if e = publishBootstrapRoot(stage, root); e == nil {
		t.Fatal("empty foreign root replaced")
	}
	after, e := bootstrapIdentity(root)
	if e != nil || before != after {
		t.Fatal("foreign root changed", e)
	}
}

// A publication whose objects are gone cannot be rolled forward. Recovery must
// undo the remnants it owns instead of refusing every later command.
func TestBootstrapAbandonsPublicationWhoseObjectsAreGone(t *testing.T) {
	t.Run("staged-tree-removed", func(t *testing.T) {
		a, source, bin := crashBootstrap(t, "journal-published")
		j, e := loadBootstrap(a)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.RemoveAll(j.Stage); e != nil {
			t.Fatal(e)
		}
		if e = recoverBootstrap(a); e != nil {
			t.Fatal(e)
		}
		if exists, e := optionalExists(bootstrapJournalPath(a)); e != nil || exists {
			t.Fatal("journal retained", e)
		}
		if exists, e := optionalExists(j.LauncherDir); e != nil || exists {
			t.Fatal("staged launcher retained", e)
		}
		publicInstallation(t, a, "install", source, bin)
		if _, e := readReceipt(a); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("published-root-removed", func(t *testing.T) {
		a, source, bin := crashBootstrap(t, "launcher-published")
		j, e := loadBootstrap(a)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.RemoveAll(j.Root); e != nil {
			t.Fatal(e)
		}
		if e = recoverBootstrap(a); e != nil {
			t.Fatal(e)
		}
		// The launcher is ours and points at a root that no longer exists.
		if exists, e := optionalExists(j.Receipt.BinPath); e != nil || exists {
			t.Fatal("own launcher retained", e)
		}
		if exists, e := optionalExists(bootstrapJournalPath(a)); e != nil || exists {
			t.Fatal("journal retained", e)
		}
		publicInstallation(t, a, "install", source, bin)
		if _, e := readReceipt(a); e != nil {
			t.Fatal(e)
		}
	})
}

// A launcher that was staged for publication but removed before it could be
// linked leaves a publication that can never complete: the receipt binds the
// exact launcher object, and that object was released with the staging
// directory. Recovery must roll the publication back instead of retaining a
// half-installed program that no command can roll back or clear.
func TestBootstrapRollsBackWhenTheStagedLauncherIsGone(t *testing.T) {
	for _, phase := range []string{"journal-published", "root-published"} {
		t.Run(phase, func(t *testing.T) {
			a, source, bin := crashBootstrap(t, phase)
			j, e := loadBootstrap(a)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.RemoveAll(j.LauncherDir); e != nil {
				t.Fatal(e)
			}
			if e = recoverBootstrap(a); e == nil {
				t.Fatal("recovery accepted a publication with no launcher")
			}
			// The scope has to be usable again: nothing of the abandoned
			// publication may survive, not even the published root.
			if exists, e := optionalExists(bootstrapJournalPath(a)); e != nil || exists {
				t.Fatal("journal retained", e)
			}
			if exists, e := optionalExists(j.Root); e != nil || exists {
				t.Fatal("published root retained", e)
			}
			if exists, e := optionalExists(j.Stage); e != nil || exists {
				t.Fatal("staged tree retained", e)
			}
			// A fresh installation has to succeed on the recovered scope.
			publicInstallation(t, a, "install", source, bin)
			if _, e := readReceipt(a); e != nil {
				t.Fatal(e)
			}
			publicInstallation(t, a, "uninstall", source, bin)
			publicInstallation(t, a, "install", source, bin)
			if _, e := readReceipt(a); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// An interrupted abandonment leaves the published root renamed out of the
// way, and its removal may already have deleted part of the tree. The next
// recovery has to finish that removal: a partly removed tree standing at the
// published path would fail the inventory check and block every later command
// for good.
func TestBootstrapResumesAnInterruptedAbandonment(t *testing.T) {
	a, source, bin := crashBootstrap(t, "root-published")
	j, e := loadBootstrap(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(j.LauncherDir); e != nil {
		t.Fatal(e)
	}
	// The interruption: the root was renamed out of the way and the removal
	// of the tombstone had already deleted part of the tree.
	tombstone := bootstrapTombstone(a, j)
	if e = os.Rename(j.Root, tombstone); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(tombstone, "current")); e != nil {
		t.Fatal(e)
	}
	if e = recoverBootstrap(a); e != nil {
		t.Fatalf("the recovery did not finish the interrupted abandonment: %v", e)
	}
	if exists, e := optionalExists(tombstone); e != nil || exists {
		t.Fatal("the tombstone was retained", e)
	}
	if exists, e := optionalExists(bootstrapJournalPath(a)); e != nil || exists {
		t.Fatal("journal retained", e)
	}
	publicInstallation(t, a, "install", source, bin)
	if _, e := readReceipt(a); e != nil {
		t.Fatal(e)
	}
}

// An abandonment that was interrupted while removing the staged tree has to
// resume: the stage is renamed out of the way before anything is deleted, so
// the interruption leaves a partly removed tree in the private tombstone,
// never a partly deleted staged tree at the stage path where the next
// recovery would verify the full inventory against it and refuse forever.
func TestBootstrapResumesAnInterruptedStageAbandonment(t *testing.T) {
	a, source, bin := crashBootstrap(t, "journal-published")
	j, e := loadBootstrap(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(j.LauncherDir); e != nil {
		t.Fatal(e)
	}
	// The interruption: the stage was renamed out of the way and the removal
	// of the tombstone had already deleted part of the tree.
	tombstone := bootstrapTombstone(a, j)
	if e = os.Rename(j.Stage, tombstone); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(tombstone, "current")); e != nil {
		t.Fatal(e)
	}
	if e = recoverBootstrap(a); e != nil {
		t.Fatalf("the recovery did not finish the interrupted abandonment: %v", e)
	}
	if exists, e := optionalExists(tombstone); e != nil || exists {
		t.Fatal("the tombstone was retained", e)
	}
	if exists, e := optionalExists(j.Stage); e != nil || exists {
		t.Fatal("a staged tree was left at the stage path", e)
	}
	if exists, e := optionalExists(bootstrapJournalPath(a)); e != nil || exists {
		t.Fatal("journal retained", e)
	}
	publicInstallation(t, a, "install", source, bin)
	if _, e := readReceipt(a); e != nil {
		t.Fatal(e)
	}
}

// An already-installed check reports success only while the receipt it just
// verified stays readable: a receipt that becomes unreadable between the
// preflight and the record copy is a foreign change that is reported, not a
// success the external record was silently skipped for.
func TestAlreadyInstalledReportsAnUnreadableReceipt(t *testing.T) {
	a, _ := installed(t)
	source := fixture(t, "0.2.0", "old-binary")
	bin := filepath.Join(filepath.Dir(a.Scope.DataRoot), "bin")
	hooks := bootstrapHooks{checkpoint: func(phase string) error {
		if phase == "already-installed" {
			return os.Remove(filepath.Join(installRoot(a), "receipt.json"))
		}
		return nil
	}}
	_, e := bootstrap(context.Background(), a, source, bin, false, hooks)
	if e == nil {
		t.Fatal("success reported although the receipt could not be read")
	}
	if exists, e := optionalExists(installationRecordPath(a)); e != nil || exists {
		t.Fatal("a record was written from an unreadable receipt", e)
	}
}

// An installation published by the previous protocol — its receipt carries
// no installation id and no launcher object — is still recognized as already
// installed, and it receives the external record that outlives its program
// root, so a later loss of that root stays detectable and repairable.
func TestLegacyInstallationIsAlreadyInstalled(t *testing.T) {
	a, _ := installed(t)
	rec, e := readReceipt(a)
	if e != nil {
		t.Fatal(e)
	}
	// The receipt exactly as the previous protocol wrote it.
	legacy := Receipt{Format: 1, Project: Project, BinPath: rec.BinPath, LauncherSHA256: rec.LauncherSHA256}
	if e = platform.WriteJSON(filepath.Join(installRoot(a), "receipt.json"), legacy); e != nil {
		t.Fatal(e)
	}
	source := fixture(t, "0.2.0", "old-binary")
	data, e := bootstrap(context.Background(), a, source, filepath.Dir(rec.BinPath), false, bootstrapHooks{})
	if e != nil {
		t.Fatal(e)
	}
	if data["already_installed"] != true {
		t.Fatalf("data = %v", data)
	}
	if _, exists, e := loadInstallationRecord(a); e != nil || !exists {
		t.Fatal("the external record was not written from the legacy receipt", e)
	}
}

// An interrupted abandonment is resumed by removing exactly the objects the
// journal inventoried. An object the journal never recorded is foreign: it
// survives the removal, and the private abandoned directory keeps it instead
// of being deleted with it.
func TestBootstrapAbandonmentPreservesForeignObjects(t *testing.T) {
	a, source, bin := crashBootstrap(t, "root-published")
	j, e := loadBootstrap(a)
	if e != nil {
		t.Fatal(e)
	}
	// The interruption: the root was renamed out of the way, and an object
	// that the journal never recorded appeared in the renamed tree.
	tombstone := bootstrapTombstone(a, j)
	if e = os.Rename(j.Root, tombstone); e != nil {
		t.Fatal(e)
	}
	foreign := filepath.Join(tombstone, "foreign")
	if e = os.WriteFile(foreign, []byte("not owned"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = recoverBootstrap(a); e != nil {
		t.Fatalf("the recovery did not finish the interrupted abandonment: %v", e)
	}
	// The foreign object survived: it was never journaled, so it was never a
	// deletion target.
	data, e := os.ReadFile(foreign)
	if e != nil || string(data) != "not owned" {
		t.Fatalf("the foreign object was removed: %q %v", data, e)
	}
	// The journaled objects of the abandoned tree are gone.
	for _, name := range []string{"current", "receipt.json", "generations"} {
		if exists, e := optionalExists(filepath.Join(tombstone, name)); e != nil || exists {
			t.Fatalf("a journaled object survived the removal: %s %v", name, e)
		}
	}
	if exists, e := optionalExists(bootstrapJournalPath(a)); e != nil || exists {
		t.Fatal("journal retained", e)
	}
	// The scope stays usable: the abandoned tree holds a foreign object, but
	// the publication it described is gone and the journal is discarded.
	publicInstallation(t, a, "install", source, bin)
	if _, e := readReceipt(a); e != nil {
		t.Fatal(e)
	}
}

// A publication that can never succeed on this kernel or filesystem must be
// rolled back; a foreign destination is a conflict, not an unsupported system.
func TestPublishRollbackDetectsUnsupportedSystem(t *testing.T) {
	for _, e := range []error{syscall.ENOSYS, syscall.EINVAL, syscall.EOPNOTSUPP} {
		code, ok := publishRollback(e)
		if !ok || code != "bootstrap-publish-unsupported" {
			t.Fatal(e, code, ok)
		}
	}
	if _, ok := publishRollback(syscall.EEXIST); ok {
		t.Fatal("a foreign destination was treated as an unsupported system")
	}
	if _, ok := publishRollback(errors.New("unrelated")); ok {
		t.Fatal("an unrelated failure was treated as an unsupported system")
	}
}

func TestBootstrapInterruptedRecoveryAndSharedMutation(t *testing.T) {
	a, source, bin := crashBootstrap(t, "journal-published")
	for _, phase := range []string{"root-published", "launcher-published", "launcher-stage-unlinked", "staging-cleaned"} {
		interrupted := errors.New("recovery interrupted")
		fired := false
		e := recoverBootstrapWithHooks(a, bootstrapHooks{checkpoint: func(p string) error {
			if p == phase {
				fired = true
				return interrupted
			}
			return nil
		}})
		if !errors.Is(e, interrupted) || !fired {
			t.Fatalf("%s: %v", phase, e)
		}
		if e = platform.CheckPending(a.Scope); e == nil {
			t.Fatal("interrupted recovery lost journal")
		}
	}
	// A mutation in another module enters this shared lock and must finish
	// delivery recovery before its own callback can touch state.
	if e := platform.WithLock(context.Background(), a.Scope, func() error {
		if e := platform.CheckPending(a.Scope); e != nil {
			return e
		}
		_, e := readReceipt(a)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	publicInstallation(t, a, "install", source, bin)
	publicInstallation(t, a, "uninstall", source, bin)
	publicInstallation(t, a, "install", source, bin)
}
