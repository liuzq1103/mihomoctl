//go:build linux

package runtimecore

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

type crashSpec struct {
	App      platform.App
	Request  platform.Request
	Phase    string
	Recover  bool
	Activate bool
	Config   string
	Before   []byte
	After    []byte
}

func runCrashHelper(path string) {
	raw, e := platform.ReadPrivate(path)
	if e != nil {
		os.Exit(111)
	}
	var spec crashSpec
	if json.Unmarshal(raw, &spec) != nil {
		os.Exit(112)
	}
	compoundCheckpoint = func(phase string) {
		if phase == spec.Phase {
			if e := platform.WriteJSON(filepath.Join(spec.App.Scope.StateRoot, "crash-witness.json"), map[string]any{"phase": phase, "pid": os.Getpid()}); e != nil {
				os.Exit(116)
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			os.Exit(113)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if spec.Activate {
		_, e = CommitAndStart(ctx, spec.App, spec.Config, spec.Before, spec.After)
	} else if spec.Recover {
		e = platform.WithLock(ctx, spec.App.Scope, func() error { return recoverCompound(ctx, spec.App) })
	} else {
		_, e = Run(ctx, spec.App, spec.Request)
	}
	if e != nil {
		os.Stderr.WriteString(platform.SafeError(e))
		os.Exit(114)
	}
	os.Exit(115)
}
func crashAt(t *testing.T, spec crashSpec) {
	t.Helper()
	witness := filepath.Join(spec.App.Scope.StateRoot, "crash-witness.json")
	if _, e := os.Lstat(witness); e == nil {
		if e = durableRemove(witness); e != nil {
			t.Fatal(e)
		}
	} else if !os.IsNotExist(e) {
		t.Fatal(e)
	}
	path := filepath.Join(spec.App.Scope.ConfigRoot, "crash-test.json")
	if e := platform.WriteJSON(path, spec); e != nil {
		t.Fatal(e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=none")
	cmd.Env = append(os.Environ(), "RUNTIMECORE_CRASH_SPEC="+path)
	out, e := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("checkpoint %s timed out instead of executing its deliberate SIGKILL", spec.Phase)
	}
	exit, ok := e.(*exec.ExitError)
	if !ok {
		t.Fatalf("crash helper did not exit: %v %s", e, out)
	}
	state := exit.Sys().(syscall.WaitStatus)
	if !state.Signaled() || state.Signal() != syscall.SIGKILL {
		t.Fatalf("checkpoint %s not reached: %v %s", spec.Phase, state, out)
	}
	raw, e := platform.ReadPrivate(witness)
	if e != nil {
		t.Fatal("missing deliberate crash witness", e)
	}
	var observed struct {
		Phase string `json:"phase"`
		PID   int    `json:"pid"`
	}
	if json.Unmarshal(raw, &observed) != nil || observed.Phase != spec.Phase || observed.PID != cmd.Process.Pid {
		t.Fatal("SIGKILL did not come from the requested checkpoint")
	}
	if _, e = os.Stat(compoundPath(spec.App)); e != nil {
		t.Fatal("no durable recovery record", e)
	}
}
func recoverViaMutation(t *testing.T, a platform.App) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	doc, e := Run(ctx, a, platform.Request{Command: []string{"profile", "set-default"}, Args: []string{"default"}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatalf("recovery failed: %+v %v", doc, e)
	}
	for _, path := range []string{compoundPath(a), journalPath(a)} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("journal not durably cleared", path, e)
		}
	}
}
func replacementCore(t *testing.T, a platform.App) string {
	t.Helper()
	m, e := loadManager(a)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(m.Core.Binary)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(m.Core.Binary), "replacement-core")
	if e = platform.AtomicWrite(path, raw, 0700); e != nil {
		t.Fatal(e)
	}
	return path
}
func assertHealthy(t *testing.T, a platform.App) {
	t.Helper()
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"health"}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
}
func TestAdoptionSIGKILLRecoveryAllPhases(t *testing.T) {
	for _, phase := range []string{"prepared", "stopped", "files-published", "launch-recorded", "process-started-before-state", "activated", "committed"} {
		t.Run(phase, func(t *testing.T) {
			a := initializedApp(t)
			if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
				t.Fatal(e)
			}
			old, e := loadManager(a)
			if e != nil {
				t.Fatal(e)
			}
			candidate := replacementCore(t, a)
			crashAt(t, crashSpec{App: a, Request: platform.Request{Command: []string{"core", "adopt"}, Options: map[string][]string{"path": {candidate}}}, Phase: phase})
			_, e = Run(context.Background(), a, platform.Request{Command: []string{"status"}})
			requireCode(t, e, "transaction-recovery-required")
			if phase == "process-started-before-state" {
				if e = os.RemoveAll(a.Scope.RuntimeRoot); e != nil {
					t.Fatal(e)
				}
				a.Scope.RuntimeRoot = filepath.Join(a.Scope.StateRoot, "new-session-runtime")
			}
			recoverViaMutation(t, a)
			m, e := loadManager(a)
			if e != nil {
				t.Fatal(e)
			}
			want := old.Core.Binary
			if phase == "committed" {
				want = candidate
			}
			if m.Core.Binary != want {
				t.Fatalf("wanted %s, got %s", want, m.Core.Binary)
			}
			assertHealthy(t, a)
		})
	}
}
func TestResetSIGKILLRestoresFilesCredentialsAndRuntime(t *testing.T) {
	for _, phase := range []string{"prepared", "stopped", "files-published", "activated", "committed"} {
		t.Run(phase, func(t *testing.T) {
			a := initializedApp(t)
			x, e := resolve(a, "")
			if e != nil {
				t.Fatal(e)
			}
			x.Config["mode"] = "direct"
			if e = platform.WriteYAML(x.Manager.Core.Config, x.Config); e != nil {
				t.Fatal(e)
			}
			oldConfig, e := platform.ReadPrivate(x.Manager.Core.Config)
			if e != nil {
				t.Fatal(e)
			}
			oldCredentials, e := platform.ReadPrivate(x.Profile.Credentials)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
				t.Fatal(e)
			}
			preview, e := Run(context.Background(), a, platform.Request{Command: []string{"reset"}, Options: map[string][]string{"dry-run": {}}})
			if e != nil {
				t.Fatal(e)
			}
			r := platform.Request{Command: []string{"reset"}, Options: map[string][]string{"apply": {}, "plan-sha256": {preview.Data["plan_sha256"].(string)}}}
			crashAt(t, crashSpec{App: a, Request: r, Phase: phase})
			recoverViaMutation(t, a)
			if phase == "committed" {
				m, e := loadManager(a)
				if e != nil {
					t.Fatal(e)
				}
				id, e := runningIdentity(context.Background(), a, m)
				if e != nil || id != nil {
					t.Fatal("committed reset unexpectedly started", id, e)
				}
				return
			}
			config, e := platform.ReadPrivate(x.Manager.Core.Config)
			if e != nil || !bytesEqual(config, oldConfig) {
				t.Fatal("config not restored", e)
			}
			creds, e := platform.ReadPrivate(x.Profile.Credentials)
			if e != nil || !bytesEqual(creds, oldCredentials) {
				t.Fatal("credentials not restored", e)
			}
			assertHealthy(t, a)
		})
	}
}
func TestRecoveryCanItselfBeInterruptedRepeatedly(t *testing.T) {
	for _, phase := range []string{"restored-files", "restored-runtime"} {
		t.Run(phase, func(t *testing.T) {
			a := initializedApp(t)
			if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
				t.Fatal(e)
			}
			old, e := loadManager(a)
			if e != nil {
				t.Fatal(e)
			}
			candidate := replacementCore(t, a)
			crashAt(t, crashSpec{App: a, Request: platform.Request{Command: []string{"core", "adopt"}, Options: map[string][]string{"path": {candidate}}}, Phase: "activated"})
			crashAt(t, crashSpec{App: a, Recover: true, Phase: phase})
			recoverViaMutation(t, a)
			m, e := loadManager(a)
			if e != nil || m.Core.Binary != old.Core.Binary {
				t.Fatal(m, e)
			}
			assertHealthy(t, a)
		})
	}
}
// The compound journal binds the objects it published. A replacement file
// that carries identical bytes is a different object, so the recovery refuses
// it instead of undoing it as if it were the operation's own file.
func TestCompoundRecoveryRefusesSameByteForeignReplacement(t *testing.T) {
	a := initializedApp(t)
	if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
		t.Fatal(e)
	}
	candidate := replacementCore(t, a)
	crashAt(t, crashSpec{App: a, Request: platform.Request{Command: []string{"core", "adopt"}, Options: map[string][]string{"path": {candidate}}}, Phase: "files-published"})
	managed := a.Scope.ManagerPath()
	raw, e := platform.ReadPrivate(managed)
	if e != nil {
		t.Fatal(e)
	}
	foreign := managed + ".foreign"
	if e = platform.AtomicWrite(foreign, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(foreign, managed); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"start"}})
	requireCode(t, e, "compound-file-conflict")
	if _, e = os.Stat(compoundPath(a)); e != nil {
		t.Fatal("the recovery record was discarded", e)
	}
}

func TestRecoveryRefusesForeignChangesAndPreservesJournal(t *testing.T) {
	a := initializedApp(t)
	if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
		t.Fatal(e)
	}
	candidate := replacementCore(t, a)
	crashAt(t, crashSpec{App: a, Request: platform.Request{Command: []string{"core", "adopt"}, Options: map[string][]string{"path": {candidate}}}, Phase: "files-published"})
	raw, e := platform.ReadPrivate(a.Scope.ManagerPath())
	if e != nil {
		t.Fatal(e)
	}
	if e = platform.AtomicWrite(a.Scope.ManagerPath(), append(raw, []byte("# external change\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"start"}})
	requireCode(t, e, "compound-file-conflict")
	if _, e = os.Stat(compoundPath(a)); e != nil {
		t.Fatal(e)
	}
	if e = platform.AtomicWrite(a.Scope.ManagerPath(), raw, 0600); e != nil {
		t.Fatal(e)
	}
	recoverViaMutation(t, a)
	assertHealthy(t, a)
}
