//go:build linux

package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
